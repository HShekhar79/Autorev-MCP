import os
import re
import signal
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import r2pipe

from utils.debug import debug_log


# =============================================================================
# Task 10: pdf (text-mode) fallback call parsing
# =============================================================================
#
# Used only when `pdfj @ <offset>` fails to produce a usable JSON structure
# for an otherwise-valid numeric offset (a known radare2 limitation with
# some addresses, e.g. very large ones). Matches a `call` MNEMONIC only:
#   - comments (anything after ';') are stripped first, so a comment that
#     merely mentions the word "call" is never mistaken for an instruction
#   - word-boundary lookaround ensures "recall"/"called"/"callback" etc.
#     never match — only the standalone word "call"
_PDF_CALL_INSTRUCTION_RE = re.compile(r"(?<![\w.])call(?![\w.])\s+([^\s;,]+)", re.IGNORECASE)


def _parse_call_targets_from_pdf_text(text: Optional[str]) -> List[str]:
    """
    Extract call targets from plain-text `pdf` disassembly output.

    Fallback-only parser (see get_calls_for_address / get_calls_from_all_
    functions). Given a line such as:
        | 0x140001722 e8d91c0000 call sym.system
    returns "sym.system" for that line. Only actual `call` instruction
    lines are matched; comments/strings containing the substring "call"
    are not.

    Defensive: `text` should be a str (r2's `.cmd()` return value), but a
    mocked/unconfigured r2 session in tests can hand back a non-string
    object. Treat anything that is not a real, non-empty string as "no
    text" rather than raising, mirroring how a genuinely empty pdf result
    is already handled.
    """
    targets: List[str] = []
    if not isinstance(text, str) or not text:
        return targets

    for line in text.splitlines():
        # r2 comments start with ';' — strip before matching.
        code_part = line.split(";", 1)[0]
        match = _PDF_CALL_INSTRUCTION_RE.search(code_part)
        if not match:
            continue
        target = match.group(1).strip()
        if target:
            targets.append(target)

    return targets


# =============================================================================
# Hard timeout configuration (env-overridable, ARISE naming convention)
# =============================================================================
#
# Defaults are conservative and compatible with the prior behaviour, where
# r2 itself was given "e anal.timeout=180" for "aaa": R2_ANALYSIS_HARD_TIMEOUT
# defaults above that so a legitimate 180s analysis is not cut short by our
# own outer wall-clock guard.

# pdfj op "type" values that represent a call-like instruction. radare2
# distinguishes a direct call ("call") from an unresolved/indirect one
# ("ucall"), a register-indirect one ("rcall"), and other indirect forms
# ("icall") — all of these are calls for evidence-extraction purposes.
_CALL_LIKE_OP_TYPES = frozenset({"call", "ucall", "rcall", "icall"})

R2_OPEN_HARD_TIMEOUT = int(os.environ.get("ARISE_R2_OPEN_HARD_TIMEOUT", "30"))
R2_ANALYSIS_HARD_TIMEOUT = int(os.environ.get("ARISE_R2_ANALYSIS_HARD_TIMEOUT", "200"))
R2_PER_CALL_HARD_TIMEOUT = int(os.environ.get("ARISE_R2_PER_CALL_HARD_TIMEOUT", "15"))
R2_CALLS_TOTAL_BUDGET_SECONDS = int(os.environ.get("ARISE_R2_CALLS_TOTAL_BUDGET_SECONDS", "300"))


class RadareExtractor:

    def __init__(self, binary_path):
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_path = binary_path
        self.r2 = None

    # -------------------------------------------------------------------
    # Central hard-timeout wrapper
    # -------------------------------------------------------------------
    def _run_with_hard_timeout(
        self,
        fn: Callable[[], Any],
        timeout_seconds: float,
        late_result_cleanup: Optional[Callable[[Any], None]] = None,
    ) -> Any:
        """
        Execute fn() under a hard wall-clock timeout.

        fn runs in a daemon worker thread so a permanently blocking radare2
        call can never hold the caller hostage (CPython threads cannot be
        force-killed safely, so we bound the *wait*, not the thread).

        On timeout:
          - any r2 process this session currently owns is killed and the
            session is invalidated (self.r2 = None) right here, centrally —
            not left to individual callers such as open()'s except clause.
            This is what makes the same protection apply uniformly to
            open(), aaa, and every per-function pdfj call.
          - TimeoutError is raised immediately to the caller.
          - if late_result_cleanup is given, a background reaper waits for
            the worker to eventually finish and hands its result to the
            callback, so a late-arriving resource (e.g. an r2pipe handle
            returned by a hung open()) is killed instead of leaked.

        Any exception raised by fn() itself (not a timeout) is re-raised to
        the caller unchanged once the worker completes within budget.
        """
        box: Dict[str, Any] = {}
        done = threading.Event()

        def _worker():
            try:
                box["value"] = fn()
            except BaseException as exc:  # noqa: BLE001 - propagate real errors verbatim
                box["error"] = exc
            finally:
                done.set()

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()

        if done.wait(timeout_seconds):
            if "error" in box:
                raise box["error"]
            return box.get("value")

        # ---- Hard timeout fired ----
        self._kill_r2_process()
        self.r2 = None

        if late_result_cleanup is not None:
            def _reap():
                done.wait()
                if "value" in box and box["value"] is not None:
                    try:
                        late_result_cleanup(box["value"])
                    except Exception:
                        pass

            threading.Thread(target=_reap, daemon=True).start()

        raise TimeoutError(
            f"radare2 operation exceeded hard timeout of {timeout_seconds}s"
        )

    # -------------------------------------------------------------------
    # Process cleanup
    # -------------------------------------------------------------------
    def _kill_r2_process(self) -> None:
        """
        Best-effort termination of the current session's underlying r2
        process, plus process-tree cleanup on Windows via taskkill.

        Defensive: never raises. Safe if self.r2, its .process attribute,
        or a pid is missing, or the process is already dead. Does not
        itself clear self.r2 — callers (namely _run_with_hard_timeout)
        own session invalidation.
        """
        if self.r2 is None:
            return

        proc = getattr(self.r2, "process", None)
        if proc is None:
            return

        try:
            proc.kill()
        except Exception:
            pass

        pid = getattr(proc, "pid", None)
        if not pid:
            return

        try:
            if os.name == "nt":
                # Process-tree kill: r2 may have spawned children.
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=5,
                )
            else:
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    # -------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------
    def open(self):
        """
        Open the binary and run baseline analysis, both under hard
        wall-clock timeouts. On timeout, the r2 process is killed, the
        session is invalidated, and TimeoutError propagates so the caller
        can record a structured failure instead of hanging in "processing".
        """

        def _late_open_cleanup(late_handle):
            # r2pipe.open() finally returned, but only after we already
            # gave up on it: kill its process rather than leaking it.
            proc = getattr(late_handle, "process", None)
            if proc is None:
                return
            try:
                proc.kill()
            except Exception:
                pass
            pid = getattr(proc, "pid", None)
            if pid:
                try:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(pid)],
                            capture_output=True,
                            timeout=5,
                        )
                    else:
                        os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

        try:
            self.r2 = self._run_with_hard_timeout(
                lambda: r2pipe.open(self.binary_path, flags=["-2"]),
                R2_OPEN_HARD_TIMEOUT,
                late_result_cleanup=_late_open_cleanup,
            )
        except TimeoutError:
            self.r2 = None
            raise
        except Exception as e:
            self.r2 = None
            raise RuntimeError(f"Radare2 open failed: {e}")

        def _run_baseline_analysis():
            self.r2.cmd("e anal.timeout=180")
            self.r2.cmd("aaa")

        try:
            self._run_with_hard_timeout(_run_baseline_analysis, R2_ANALYSIS_HARD_TIMEOUT)
        except TimeoutError:
            # self.r2 already invalidated centrally by _run_with_hard_timeout.
            raise
        except Exception as e:
            self.r2 = None
            raise RuntimeError(f"Radare2 analysis failed: {e}")

    def close(self):
        try:
            if self.r2:
                self.r2.quit()
        except Exception:
            pass
        finally:
            self.r2 = None

    # -------------------------------------------------------------------
    # Extraction
    # -------------------------------------------------------------------
    def get_functions(self):
        funcs = self.r2.cmdj("aflj")
        return funcs or []

    def get_imports(self):
        imports = self.r2.cmdj("iij")
        return [imp.get("name") for imp in imports or [] if imp.get("name")]

    def get_strings(self):
        strings = self.r2.cmdj("izj")
        return [s.get("string") for s in strings or [] if s.get("string")]

    def _resolve_call_target(self, op: Dict[str, Any]) -> Optional[str]:
        """
        Resolve a single call-like pdfj op's target string, restoring the
        richer resolution function_analysis_engine.py used before
        centralization, without reintroducing its security gap (only
        numeric addresses are ever used to build an r2 command here —
        never a name, and never raw disasm text is used as a command).

        Order (matches the prior per-engine behavior):
          1. op["jump"], if present and numeric, resolved via
             `fd @ <numeric_jump_address>` — more accurate than the raw
             disasm text for indirect/computed calls (e.g. "call rax",
             "call [rbp-0x8]"), where r2's own analysis may still know the
             true target even though the text doesn't show a symbol.
          2. Falls back to the disasm text's last token (e.g. "sym.system"
             from "call sym.system") when jump resolution didn't help.
          3. If still unresolved, scans op["refs"] for a numeric "addr"
             and resolves that via `fd @ <numeric_ref_address>`.
        Returns None if none of the above yields anything.
        """
        disasm_text = op.get("disasm", "") or ""
        parts = disasm_text.split()
        text_candidate = parts[-1] if len(parts) >= 2 else None

        # 1) jump target resolution — numeric only.
        try:
            numeric_jump = int(op.get("jump"))
        except (TypeError, ValueError):
            numeric_jump = None

        if numeric_jump is not None:
            try:
                sym = self.r2.cmd(f"fd @ {numeric_jump}")
                sym = sym.strip() if isinstance(sym, str) else None
                if sym and sym != str(numeric_jump):
                    return sym
            except Exception:
                pass

        # 2) disasm text fallback.
        if text_candidate:
            return text_candidate

        # 3) refs — numeric addr only.
        for ref in (op.get("refs") or []):
            if not isinstance(ref, dict):
                continue
            try:
                numeric_ref_addr = int(ref.get("addr"))
            except (TypeError, ValueError):
                continue
            try:
                sym = self.r2.cmd(f"fd @ {numeric_ref_addr}")
                sym = sym.strip() if isinstance(sym, str) else None
                if sym:
                    return sym
            except Exception:
                continue

        return None

    def get_calls_for_address(self, numeric_offset: int) -> List[str]:
        """
        Return RAW call-target strings for the function at numeric_offset,
        using the pdfj -> pdf fallback under a hard wall-clock timeout.

        This is the SINGLE centralized implementation of that fallback:
        get_calls_from_all_functions() below and
        function_analysis_engine.analyze_functions() both call this rather
        than each re-implementing pdfj/pdf command construction and
        parsing separately (which previously let a second, unfixed
        pdfj-only path exist in function_analysis_engine.py and silently
        lose evidence on the same offsets this fallback was built for).

        SECURITY: takes only an already-validated numeric_offset. Builds
        both r2 commands from that int alone — never from a function name.

        Raises TimeoutError if either the primary pdfj call or the pdf
        fallback call hits R2_PER_CALL_HARD_TIMEOUT; by that point
        _run_with_hard_timeout has already killed the r2 process and set
        self.r2 = None. Callers should treat this as "stop iterating
        further functions" (the session is dead), not as a
        this-function-only failure.
        """
        pdfj_cmd = f"pdfj @ {numeric_offset}"
        try:
            disasm = self._run_with_hard_timeout(
                lambda c=pdfj_cmd: self.r2.cmdj(c),
                R2_PER_CALL_HARD_TIMEOUT,
            )
        except TimeoutError:
            raise
        except Exception:
            disasm = None

        if disasm and disasm.get("ops"):
            # Valid, non-empty structured result.
            raw_calls: List[str] = []
            for op in disasm["ops"]:
                if op.get("type") not in _CALL_LIKE_OP_TYPES:
                    continue

                resolved = self._resolve_call_target(op)
                if resolved:
                    raw_calls.append(resolved)
            return raw_calls

        # pdfj returned {}, None, or an empty structure: fall back to
        # text-mode pdf on the SAME numeric offset, same hard timeout.
        pdf_cmd = f"pdf @ {numeric_offset}"
        try:
            pdf_text = self._run_with_hard_timeout(
                lambda c=pdf_cmd: self.r2.cmd(c),
                R2_PER_CALL_HARD_TIMEOUT,
            )
        except TimeoutError:
            raise
        except Exception:
            pdf_text = None

        return _parse_call_targets_from_pdf_text(pdf_text)

    @staticmethod
    def _resolve_function_address(func: Any) -> Optional[int]:
        """
        Resolve a single aflj entry's numeric address, supporting both the
        "offset" key (used by some existing fixtures/callers) and the real
        radare2 aflj schema's "addr" key — "offset" wins if a dict somehow
        carries both. Returns None (never the function's name) if neither
        key holds a valid number.
        """
        if not isinstance(func, dict):
            return None

        raw = func.get("offset")
        if raw is None:
            raw = func.get("addr")

        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    def get_calls_from_all_functions(self, max_functions: int = 200) -> List[str]:
        """
        Extract API call names from up to max_functions functions.

        SECURITY: each function is located by its NUMERIC ADDRESS from the
        untrusted aflj output ("offset" or, on real radare2, "addr"), never
        by its name — a malicious symbol name (e.g. "sym.evil;!bash") is
        therefore never interpolated into an r2 command string. Functions
        with a non-numeric/missing offset and addr are skipped. This holds
        for both the primary (pdfj) and fallback (pdf) paths, both built
        from the same numeric_offset only, inside get_calls_for_address().

        RELIABILITY: each pdfj/pdf call is bounded by
        R2_PER_CALL_HARD_TIMEOUT (enforced inside get_calls_for_address);
        the whole loop is additionally bounded by
        R2_CALLS_TOTAL_BUDGET_SECONDS. A hard timeout on any single function
        stops the loop immediately: _run_with_hard_timeout has already
        invalidated the session, so later functions are not attempted
        against a killed process. Partial results collected so far are
        returned rather than raised.

        TASK 10 FIX: `pdfj @ <offset>` can silently fail (return {}, None,
        or an empty structure) for some otherwise-valid offsets — a known
        radare2 limitation, observed with large addresses. get_calls_for_
        address() falls back to text-mode `pdf @ <same offset>` for that
        case; a structurally valid, non-empty pdfj result is used as-is.
        """
        functions = self.get_functions()
        all_calls: List[str] = []
        seen: set = set()

        start = time.monotonic()

        for func in functions[:max_functions]:
            if self.r2 is None:
                break

            if time.monotonic() - start >= R2_CALLS_TOTAL_BUDGET_SECONDS:
                break

            numeric_offset = self._resolve_function_address(func)
            if numeric_offset is None:
                # Invalid/missing offset/addr: skip safely, never fall
                # back to interpolating the function's (untrusted) name.
                continue

            try:
                raw_calls = self.get_calls_for_address(numeric_offset)
            except TimeoutError:
                # Session already invalidated centrally — stop rather than
                # attempt further functions against a dead process.
                break

            for raw_call in raw_calls:
                raw_call = raw_call.replace("sym.imp.", "")
                raw_call = raw_call.replace("sym.", "")
                raw_call = raw_call.replace("reloc.", "")
                raw_call = raw_call.replace("[", "").replace("]", "")
                raw_call = raw_call.strip()

                if raw_call and raw_call not in seen:
                    seen.add(raw_call)
                    all_calls.append(raw_call)

        return sorted(all_calls)


# ----------------------------------
# WRAPPER FUNCTIONS
# ----------------------------------

def extract_functions(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.get_functions()
    except Exception as e:
        debug_log("EXTRACT FUNCTIONS ERROR", str(e))
        return []
    finally:
        extractor.close()


def extract_imports(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.get_imports()
    except Exception as e:
        debug_log("EXTRACT IMPORTS ERROR", str(e))
        return []
    finally:
        extractor.close()


def extract_strings(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.get_strings()
    except Exception as e:
        debug_log("EXTRACT STRINGS ERROR", str(e))
        return []
    finally:
        extractor.close()


def extract_file_info(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.r2.cmdj("ij") or {}
    except Exception as e:
        debug_log("EXTRACT FILE INFO ERROR", str(e))
        return {}
    finally:
        extractor.close()


def extract_sections(binary_path):

    extractor = RadareExtractor(binary_path)

    try:
        extractor.open()
        return extractor.r2.cmdj("iSj") or []
    except Exception as e:
        debug_log("EXTRACT SECTIONS ERROR", str(e))
        return []
    finally:
        extractor.close()
