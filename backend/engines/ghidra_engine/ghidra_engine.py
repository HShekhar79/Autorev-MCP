from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import NamedTuple, Optional

from utils.debug import debug_log

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_DEFAULT_SCRIPTS_DIR = _HERE.parent.parent / "ghidra_scripts"
# <root>/backend/engines/ghidra_engine/ghidra_engine.py -> <root>
_PROJECT_ROOT = _HERE.parents[2]

GHIDRA_HOME: Optional[str] = os.environ.get("GHIDRA_HOME")
GHIDRA_SCRIPTS_DIR: str = os.environ.get(
    "GHIDRA_SCRIPTS_DIR", str(_DEFAULT_SCRIPTS_DIR)
)

GHIDRA_ANALYZE_HEADLESS: Optional[str] = None

_IS_WINDOWS = platform.system() == "Windows" or os.name == "nt"


# ---------------------------------------------------------------------------
# FIX 1 — SAFE RESOLUTION WITH EXPLICIT LOGGING
# ---------------------------------------------------------------------------
def _resolve_headless() -> Optional[str]:
    if not GHIDRA_HOME:
        debug_log("[GHIDRA] WARN", "GHIDRA_HOME not set — Ghidra disabled")
        return None

    support = Path(GHIDRA_HOME) / "support"
    exe = support / ("analyzeHeadless.bat" if _IS_WINDOWS else "analyzeHeadless")

    if not exe.exists():
        debug_log("[GHIDRA] WARN", f"analyzeHeadless not found at: {exe}")
        return None

    debug_log("[GHIDRA] CHECK", f"Resolved analyzeHeadless: {exe}")
    return str(exe)


GHIDRA_ANALYZE_HEADLESS = _resolve_headless()

# Official Ghidra PyGhidra launcher (required for Python post-scripts).
_PYGHIDRA_LAUNCHER_PARTS = ("Ghidra", "Features", "PyGhidra", "support", "pyghidra_launcher.py")


def _resolve_pyghidra_launcher() -> Optional[str]:
    if not GHIDRA_HOME:
        debug_log("[GHIDRA] WARN", "GHIDRA_HOME not set — PyGhidra launcher unavailable")
        return None
    launcher = Path(GHIDRA_HOME).joinpath(*_PYGHIDRA_LAUNCHER_PARTS)
    if not launcher.is_file():
        debug_log("[GHIDRA] WARN", f"PyGhidra launcher not found at: {launcher}")
        return None
    debug_log("[GHIDRA] CHECK", f"Resolved PyGhidra launcher: {launcher}")
    return str(launcher)


GHIDRA_PYGHIDRA_LAUNCHER: Optional[str] = _resolve_pyghidra_launcher()


# ---------------------------------------------------------------------------
# Dedicated Ghidra Python runtime.
# AutoRev itself runs on a Python the bundled JPype wheel does not support, so
# PyGhidra lives in a separate interpreter.  AutoRev's own sys.executable is
# NEVER used for provisioning or for the launcher.
# ---------------------------------------------------------------------------
def _resolve_ghidra_python() -> Optional[str]:
    """
    1. GHIDRA_PYTHON_EXECUTABLE (explicit; if set but invalid we fail, no fallback)
    2. <project root>/.ghidra-venv/Scripts/python.exe (Windows) or bin/python
    3. None -> caller fails clearly
    """
    explicit = (os.environ.get("GHIDRA_PYTHON_EXECUTABLE") or "").strip()
    if explicit:
        if Path(explicit).is_file():
            debug_log("[GHIDRA] CHECK", f"Ghidra Python (GHIDRA_PYTHON_EXECUTABLE): {explicit}")
            return explicit
        debug_log("[GHIDRA] WARN",
                  f"GHIDRA_PYTHON_EXECUTABLE is set but not a file: {explicit}")
        return None

    rel = ("Scripts", "python.exe") if _IS_WINDOWS else ("bin", "python")
    default = Path(_PROJECT_ROOT, ".ghidra-venv", *rel)
    if default.is_file():
        debug_log("[GHIDRA] CHECK", f"Ghidra Python (.ghidra-venv): {default}")
        return str(default)
    debug_log("[GHIDRA] WARN",
              f"Dedicated Ghidra Python not found at {default}; "
              "create .ghidra-venv or set GHIDRA_PYTHON_EXECUTABLE")
    return None


def _child_env() -> dict:
    """Environment for Ghidra-Python subprocesses: drop settings that belong to
    AutoRev's own interpreter and would corrupt the dedicated one."""
    env = dict(os.environ)
    for k in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "__PYVENV_LAUNCHER__"):
        env.pop(k, None)
    return env

# Text that proves a Python post-script never ran / failed, even with exit code 0.
_PYGHIDRA_MISSING_MARKERS = ("was not started with pyghidra", "python is not available")
# The official launcher asks questions via input(); with stdin=DEVNULL that
# surfaces as an EOFError instead of a hang.  Either form means "setup blocked".
_PYGHIDRA_PROMPT_MARKERS = (
    "do you wish to install pyghidra",
    "do you wish to upgrade",
    "eof when reading a line",
)
_SCRIPT_ERROR_MARKERS = ("report script error",)
# Our own extract_*.py scripts catch exceptions, print this and still write "[]".
_SCRIPT_SELF_ERROR_RE = re.compile(r"\[ghidra\]\[extract_\w+\]\s+error")
# Statuses after which running further scripts is pointless.
_FATAL_SETUP_STATUSES = ("pyghidra_unavailable", "pyghidra_prompt_blocked")

GHIDRA_TIMEOUT: int = int(os.environ.get("GHIDRA_TIMEOUT", "600"))
GHIDRA_PIP_TIMEOUT: int = int(os.environ.get("GHIDRA_PIP_TIMEOUT", "300"))
# Opt-in: let AutoRev pip-upgrade an OLDER PyGhidra in the active venv to the
# version bundled with Ghidra.  Default off (we never mutate silently).
GHIDRA_PYGHIDRA_AUTO_UPGRADE: bool = os.environ.get(
    "GHIDRA_PYGHIDRA_AUTO_UPGRADE", "").strip().lower() in ("1", "true", "yes", "on")
_PYGHIDRA_DIST_PARTS = ("Ghidra", "Features", "PyGhidra", "pypkg", "dist")
_PROVISION_LOCK = threading.Lock()
MAX_STRINGS: int = int(os.environ.get("GHIDRA_MAX_STRINGS", "5000"))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ghidra_available() -> bool:
    if not GHIDRA_PYGHIDRA_LAUNCHER:
        debug_log("[GHIDRA] SKIP", "PyGhidra launcher not resolved")
        return False

    p = Path(GHIDRA_PYGHIDRA_LAUNCHER)
    if not p.is_file():
        debug_log("[GHIDRA] SKIP", f"Launcher no longer exists: {p}")
        return False

    debug_log("[GHIDRA] CHECK", f"Launcher confirmed: {p}")
    return True


class _Setup(NamedTuple):
    ok: bool
    status: str    # ready | installed | upgraded | not_installed_no_wheel | outdated
                   # | pip_failed | pip_timeout | pip_error | verify_failed | python_error
    detail: str


def _vtuple(version: str) -> tuple:
    m = re.match(r"\d+(?:\.\d+)*", version or "")
    return tuple(int(x) for x in m.group(0).split(".")) if m else ()


def _wheel_version(wheel: Path) -> str:
    # pyghidra-3.0.2-py3-none-any.whl -> 3.0.2
    parts = wheel.name.split("-")
    return parts[1] if len(parts) > 1 else ""


def _bundled_wheel() -> Optional[Path]:
    if not GHIDRA_HOME:
        return None
    dist = Path(GHIDRA_HOME).joinpath(*_PYGHIDRA_DIST_PARTS)
    try:
        wheels = [w for w in dist.glob("pyghidra-*.whl") if _vtuple(_wheel_version(w))]
    except OSError:
        return None
    return max(wheels, key=lambda w: _vtuple(_wheel_version(w))) if wheels else None


_VERSION_PROBE = (
    "import importlib.metadata as m\n"
    "try:\n"
    "    print(m.version('pyghidra'))\n"
    "except m.PackageNotFoundError:\n"
    "    print('')\n"
)


def _installed_pyghidra_version(python_exe: str) -> Optional[str]:
    """Version of PyGhidra inside the DEDICATED Ghidra interpreter (None = absent).
    Raises RuntimeError if that interpreter cannot be queried at all."""
    try:
        proc = subprocess.run(
            [python_exe, "-c", _VERSION_PROBE],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            env=_child_env(),
        )
    except Exception as exc:
        raise RuntimeError(f"{type(exc).__name__}: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"probe exit {proc.returncode}: {(proc.stderr or '')[-300:]}")
    out = (proc.stdout or "").strip()
    return out or None


def _run_pip(python_exe: str, dist_dir: Path, version: str) -> subprocess.CompletedProcess:
    # <ghidra python> -m pip -> installs into the dedicated Ghidra venv, the same
    # interpreter _build_cmd uses for the launcher.  Offline, pinned to the bundled wheel.
    cmd = [
        python_exe, "-m", "pip", "install",
        "--no-index", "--find-links", str(dist_dir),
        "--disable-pip-version-check", "--no-input",
        f"pyghidra=={version}",
    ]
    debug_log("[GHIDRA] PIP CMD", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    return subprocess.run(
        cmd,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=GHIDRA_PIP_TIMEOUT,
        env=_child_env(),
    )


def _ensure_pyghidra(python_exe: str) -> _Setup:
    """
    Non-interactive PyGhidra provisioning (inside python_exe, the dedicated Ghidra
    interpreter - never AutoRev's own) so the official launcher never has to
    ask.  Missing -> offline install of Ghidra's bundled wheel.  Older than the
    bundled wheel -> upgrade only when GHIDRA_PYGHIDRA_AUTO_UPGRADE is set,
    otherwise report "outdated" (the launcher would prompt for it).
    Same or newer -> untouched.
    """
    wheel = _bundled_wheel()
    bundled = _wheel_version(wheel) if wheel else ""

    with _PROVISION_LOCK:
        try:
            installed = _installed_pyghidra_version(python_exe)
        except RuntimeError as exc:
            return _Setup(False, "python_error", f"cannot query {python_exe}: {exc}")

        if installed is None:
            if wheel is None:
                return _Setup(False, "not_installed_no_wheel",
                              "PyGhidra not installed and no bundled wheel found")
            action = "installed"
        elif bundled and _vtuple(installed) < _vtuple(bundled):
            if not GHIDRA_PYGHIDRA_AUTO_UPGRADE:
                return _Setup(False, "outdated",
                              f"pyghidra {installed} < bundled {bundled}; "
                              "set GHIDRA_PYGHIDRA_AUTO_UPGRADE=1 or upgrade manually")
            action = "upgraded"
        else:
            return _Setup(True, "ready", f"pyghidra {installed}")

        try:
            proc = _run_pip(python_exe, wheel.parent, bundled)
        except subprocess.TimeoutExpired:
            return _Setup(False, "pip_timeout", f"pip exceeded {GHIDRA_PIP_TIMEOUT}s")
        except Exception as exc:
            return _Setup(False, "pip_error", f"{type(exc).__name__}: {exc}")

        if proc.returncode != 0:
            tail = ((proc.stderr or "") + (proc.stdout or ""))[-600:]
            return _Setup(False, "pip_failed", f"pip exit {proc.returncode}: {tail}")

        try:
            after = _installed_pyghidra_version(python_exe)
        except RuntimeError as exc:
            return _Setup(False, "verify_failed", f"re-check failed: {exc}")
        if after is None or _vtuple(after) < _vtuple(bundled):
            return _Setup(False, "verify_failed",
                          f"pip succeeded but installed version is {after}")
        return _Setup(True, action, f"pyghidra {after}")


def _read_json_output(output_dir: Path, script_stem: str) -> Optional[list | dict]:
    """
    FIX: Validate JSON output thoroughly.
    Returns the parsed value (list or dict) — caller decides what empty means.
    Returns None only when the file is missing or unparseable.
    """
    candidate = output_dir / f"{script_stem}_output.json"

    if not candidate.exists():
        debug_log("[GHIDRA] WARN", f"Output file missing: {candidate}")
        return None

    raw = ""
    try:
        raw = candidate.read_text(encoding="utf-8").strip()
    except Exception as e:
        debug_log("[GHIDRA] WARN", f"Cannot read {candidate.name}: {e}")
        return None

    if not raw:
        # json.dump never produces a zero-byte file ("[]" is the valid empty
        # result), so a zero-byte file means a truncated/failed write.
        debug_log("[GHIDRA] WARN", f"Output file is zero bytes: {candidate.name}")
        return None

    try:
        data = json.loads(raw)
        count = len(data) if isinstance(data, (list, dict)) else "?"
        debug_log("[GHIDRA] READ", f"{candidate.name}: {count} entries")
        return data
    except json.JSONDecodeError as e:
        debug_log("[GHIDRA] WARN", f"JSON parse error in {candidate.name}: {e} — raw[:200]={raw[:200]}")
        return None


def _build_cmd(
    project_dir: Path,
    project_name: str,
    binary_path: str,
    script_name: str,
    script_args: list[str],
    is_last_script: bool,
    python_exe: Optional[str] = None,
) -> list[str]:
    # Official contract: pyghidra_launcher.py -H <install dir> <AnalyzeHeadless args...>
    # Run with the DEDICATED Ghidra interpreter (not AutoRev's sys.executable).
    python_exe = python_exe or _resolve_ghidra_python()
    if not python_exe:
        raise RuntimeError("Ghidra Python executable not resolved")
    cmd = [
        python_exe,
        GHIDRA_PYGHIDRA_LAUNCHER,
        "-H",
        GHIDRA_HOME,
        str(project_dir),
        project_name,
        "-import", binary_path,
        "-overwrite",
        "-scriptPath", GHIDRA_SCRIPTS_DIR,
        "-postScript", script_name,
        *script_args,
        "-log", str(project_dir / f"{script_name}.log"),
    ]

    # Only delete project on LAST script so imports persist across scripts
    if is_last_script:
        cmd.append("-deleteProject")

    return cmd


def _classify_script_run(returncode: int, stdout: str, stderr: str,
                         output_present: bool, log_text: str = "") -> str:
    """
    ok | pyghidra_unavailable | pyghidra_prompt_blocked | script_failed
    | process_failed | no_output
    (timeout / error / corrupt_output are assigned by the caller).

    Contract: exit 0 AND the expected output file present -> "ok", whatever the
    launcher/log text says (the PyGhidra launcher prints normal informational
    output, and a script can print an error line after it has already written
    its artifact).  Text is only used to *name* a failure that is already
    established by a non-zero exit or a missing artifact, or logged as a
    diagnostic.  File validity (parse) is checked by the caller.
    """
    text = f"{stdout or ''}\n{stderr or ''}\n{log_text or ''}".lower()
    has_error_text = (any(m in text for m in _SCRIPT_ERROR_MARKERS)
                      or bool(_SCRIPT_SELF_ERROR_RE.search(text)))

    if returncode == 0 and output_present:
        if has_error_text:
            debug_log("[GHIDRA] WARN",
                      "error text in launcher/log output, but exit 0 and output "
                      "file present - not treated as failure")
        return "ok"

    if any(m in text for m in _PYGHIDRA_MISSING_MARKERS):
        return "pyghidra_unavailable"
    if any(m in text for m in _PYGHIDRA_PROMPT_MARKERS):
        return "pyghidra_prompt_blocked"
    if has_error_text:
        return "script_failed"
    if returncode != 0:
        return "process_failed"
    return "no_output"


def _kill_process_tree(pid: int) -> None:
    """
    Best-effort termination of `pid` AND all of its descendants.

    subprocess.run(timeout=...) only kills the immediate child.  The Ghidra
    launcher chain (python -> analyzeHeadless -> cmd.exe -> java.exe) leaves the
    real worker orphaned and running after a timeout, so the whole tree is killed.

    Never raises: cleanup failure must not mask the caller's TimeoutExpired.
    """
    try:
        if _IS_WINDOWS:
            # /T = also terminate child processes, /F = force.
            result = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            debug_log("[GHIDRA] KILL TREE",
                      f"taskkill pid={pid} exit={getattr(result, 'returncode', '?')}")
        else:
            # _run_headless starts the child in its own session (pgid == pid) on
            # POSIX, so the whole group can be signalled.  Never killpg a group
            # that is not the child's own (it could be ours).
            try:
                if os.getpgid(pid) == pid and pid != os.getpgrp():
                    os.killpg(pid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # already gone
            debug_log("[GHIDRA] KILL TREE", f"signalled pid={pid}")
    except Exception as exc:
        debug_log("[GHIDRA] WARN",
                  f"process-tree kill failed for pid={pid}: {type(exc).__name__}: {exc}")


def _run_headless(cmd: list[str]) -> subprocess.CompletedProcess:
    """
    FIX: Log the full command before execution so subprocess activity is
    always visible in debug output.

    Popen + communicate() (instead of subprocess.run) so that on timeout the
    child PID is available and the whole process tree can be terminated.
    TimeoutExpired is re-raised unchanged for run_ghidra_analysis().
    """
    printable = " ".join(f'"{c}"' if " " in c else c for c in cmd)
    debug_log("[GHIDRA] CMD", printable)

    extra = {} if _IS_WINDOWS else {"start_new_session": True}

    proc = subprocess.Popen(
        cmd,
        shell=False,
        stdin=subprocess.DEVNULL,   # never block on an interactive prompt
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_child_env(),
        **extra,
    )

    try:
        stdout, stderr = proc.communicate(timeout=GHIDRA_TIMEOUT)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc.pid)
        # Best effort: reap the process and drain its pipes without hanging.
        try:
            out, err = proc.communicate(timeout=10)
            debug_log("[GHIDRA] TIMEOUT PARTIAL",
                      f"stdout_tail={(out or '')[-200:]!r} stderr_tail={(err or '')[-200:]!r}")
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        raise  # original TimeoutExpired, unchanged
    except BaseException:
        # Same safety net subprocess.run() provides (e.g. KeyboardInterrupt).
        _kill_process_tree(proc.pid)
        raise

    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


# ---------------------------------------------------------------------------
# Normalization — UNCHANGED (industry-safe contracts)
# ---------------------------------------------------------------------------

def _normalize_functions(raw) -> list:
    if not isinstance(raw, list):
        return []

    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        name = item.get("name") or item.get("function_name") or ""
        offset_raw = item.get("offset") or item.get("entry") or item.get("address") or 0

        try:
            offset = int(offset_raw, 16) if isinstance(offset_raw, str) else int(offset_raw)
        except Exception:
            offset = 0

        size = int(item.get("size") or item.get("length") or 0)

        if name:
            result.append({"name": name, "offset": offset, "size": size})

    return result


def _normalize_calls(raw) -> list:
    if not isinstance(raw, list):
        return []

    seen: set = set()
    result = []

    for item in raw:
        if isinstance(item, str):
            target = item
        elif isinstance(item, dict):
            target = item.get("callee") or item.get("target") or item.get("name") or ""
        else:
            continue

        target = target.strip()
        if target and target not in seen:
            seen.add(target)
            result.append(target)

    return result


def _normalize_strings(raw) -> list:
    if not isinstance(raw, list):
        return []

    result = []
    for item in raw:
        if isinstance(item, str):
            s = item
        elif isinstance(item, dict):
            s = item.get("value") or item.get("string") or ""
        else:
            continue

        s = s.strip()
        if s:
            result.append(s)
        if len(result) >= MAX_STRINGS:
            break

    return result


# ---------------------------------------------------------------------------
# MAIN ENGINE
# ---------------------------------------------------------------------------

def run_ghidra_analysis(file_path: str) -> Optional[dict]:
    """
    Run Ghidra headless analysis and return extracted data.

    Returns:
        dict  — always when Ghidra executed, even if output is empty.
                Callers should NOT treat empty lists as a failure.
        None  — only when Ghidra is unavailable or a fatal setup error occurred.

    FIX: Empty output (zero functions / strings / calls) is a valid result
    (e.g. very small binaries).  Only return None for genuine setup failures.
    """

    debug_log("[GHIDRA] ENTRY", file_path)

    # FIX 4 — Re-resolve headless path at runtime in case env changed
    global GHIDRA_ANALYZE_HEADLESS, GHIDRA_PYGHIDRA_LAUNCHER
    GHIDRA_ANALYZE_HEADLESS = _resolve_headless()
    GHIDRA_PYGHIDRA_LAUNCHER = _resolve_pyghidra_launcher()

    if not _ghidra_available():
        debug_log("[GHIDRA] FAIL", "Ghidra not available — skipping")
        return None

    if not os.path.isfile(file_path):
        debug_log("[GHIDRA] FAIL", f"Target file does not exist: {file_path}")
        return None

    ghidra_python = _resolve_ghidra_python()
    if not ghidra_python:
        debug_log("[GHIDRA] FAIL",
                  "Dedicated Ghidra Python unavailable (set GHIDRA_PYTHON_EXECUTABLE "
                  "or create <project>/.ghidra-venv) — skipping")
        return None

    setup = _ensure_pyghidra(ghidra_python)
    if not setup.ok:
        # Genuine setup failure: Ghidra could not run at all -> None, like
        # "GHIDRA_HOME not set", so callers do not report Ghidra as available.
        debug_log("[GHIDRA] FAIL", f"PyGhidra setup failed: {setup.status}: {setup.detail}")
        return None
    debug_log("[GHIDRA] SETUP", f"{setup.status}: {setup.detail}")

    debug_log("[GHIDRA] START", file_path)
    t0 = time.monotonic()

    tmp_dir = Path(tempfile.mkdtemp(prefix="ghidra_analysis_"))
    project_name = "GhidraAutoProject"
    debug_log("[GHIDRA] TMP DIR", str(tmp_dir))

    try:
        output_dir = tmp_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        # FIX 5 — All three scripts executed; each is tracked individually
        scripts = [
            ("extract_functions.py", ["--output-dir", str(output_dir)]),
            ("extract_calls.py",     ["--output-dir", str(output_dir)]),
            ("extract_strings.py",   ["--output-dir", str(output_dir)]),
        ]
        total_scripts = len(scripts)
        script_status: dict = {}

        for idx, (script_name, script_args) in enumerate(scripts):
            is_last = (idx == total_scripts - 1)
            debug_log("[GHIDRA] SCRIPT", f"{script_name} (last={is_last})")

            try:
                cmd = _build_cmd(
                    tmp_dir,
                    project_name,
                    file_path,
                    script_name,
                    script_args,
                    is_last,
                    ghidra_python,
                )
                proc = _run_headless(cmd)

                log_text = ""
                try:
                    log_text = (tmp_dir / f"{script_name}.log").read_text(
                        encoding="utf-8", errors="replace")
                except Exception:
                    pass

                out_file = output_dir / f"{Path(script_name).stem}_output.json"
                status = _classify_script_run(
                    proc.returncode, proc.stdout, proc.stderr,
                    out_file.is_file(), log_text,
                )
                script_status[script_name] = status

                if status == "ok":
                    debug_log("[GHIDRA] SCRIPT OK", script_name)
                    if (proc.stdout or "").strip():
                        debug_log("[GHIDRA] STDOUT", proc.stdout[-400:])
                else:
                    debug_log(
                        "[GHIDRA] WARN",
                        f"{script_name} status={status} exit={proc.returncode}\n"
                        f"STDERR: {(proc.stderr or '')[-800:]}\n"
                        f"STDOUT: {(proc.stdout or '')[-400:]}",
                    )
                    if status in _FATAL_SETUP_STATUSES:
                        debug_log("[GHIDRA] FAIL",
                                  f"{status} — skipping remaining scripts")
                        break

            except subprocess.TimeoutExpired:
                script_status[script_name] = "timeout"
                debug_log("[GHIDRA] WARN", f"{script_name} timed out after {GHIDRA_TIMEOUT}s")
            except Exception as exc:
                script_status[script_name] = "error"
                debug_log("[GHIDRA] WARN", f"{script_name} raised: {type(exc).__name__}: {exc}")

        # ── Parse outputs ──────────────────────────────────────────────────
        raw_functions = _read_json_output(output_dir, "extract_functions")
        raw_calls     = _read_json_output(output_dir, "extract_calls")
        raw_strings   = _read_json_output(output_dir, "extract_strings")

        for _name, _raw in (("extract_functions.py", raw_functions),
                            ("extract_calls.py", raw_calls),
                            ("extract_strings.py", raw_strings)):
            if script_status.get(_name) == "ok" and not isinstance(_raw, list):
                script_status[_name] = "corrupt_output"

        # FIX 7 — None means file missing/corrupt; [] means Ghidra ran but found nothing.
        #          Treat both [] and None as "no data for this category" — never abort.
        functions = _normalize_functions(raw_functions)
        calls     = _normalize_calls(raw_calls)
        strings   = _normalize_strings(raw_strings)

        elapsed = round(time.monotonic() - t0, 2)

        debug_log(
            "[GHIDRA] PARSE RESULTS",
            f"functions={len(functions)}, calls={len(calls)}, strings={len(strings)}",
        )

        # FIX 8 — CRITICAL: empty results are NOT a failure.
        #          We return a valid dict so the caller sets ghidra_available=True.
        #          Only return None when we never ran (handled above).
        if not functions and not calls and not strings:
            debug_log(
                "[GHIDRA] WARN",
                "Ghidra executed but produced zero output — "
                "returning empty result dict (ghidra_available will be True)",
            )

        result = {
            "functions": functions,
            "calls":     calls,
            "strings":   strings,
            "_meta": {
                "engine":         "ghidra",
                "ghidra_python":  ghidra_python,
                "elapsed":        elapsed,
                "function_count": len(functions),
                "call_count":     len(calls),
                "string_count":   len(strings),
                # Distinguish "ran but empty" from "not ran at all"
                "scripts_executed": [s for s, _ in scripts],
                "script_status":    script_status,
                "pyghidra_setup":   {"status": setup.status, "detail": setup.detail},
                "extraction_ok":    len(script_status) == total_scripts
                                    and all(v == "ok" for v in script_status.values()),
                "output_dir_files": [
                    f.name for f in output_dir.iterdir()
                ] if output_dir.exists() else [],
            },
        }

        _ok = result["_meta"]["extraction_ok"]
        debug_log("[GHIDRA] SUCCESS" if _ok else "[GHIDRA] DEGRADED",
                  f"{len(functions)} funcs, {len(strings)} strings in {elapsed}s status={script_status}")
        return result

    except Exception as exc:
        debug_log("[GHIDRA] FAIL", f"Unhandled exception: {type(exc).__name__}: {exc}")
        return None

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        debug_log("[GHIDRA] CLEANUP", str(tmp_dir))
