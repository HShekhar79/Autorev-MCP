from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from utils.debug import debug_log

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_DEFAULT_SCRIPTS_DIR = _HERE.parent.parent / "ghidra_scripts"

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

GHIDRA_TIMEOUT: int = int(os.environ.get("GHIDRA_TIMEOUT", "600"))
MAX_STRINGS: int = int(os.environ.get("GHIDRA_MAX_STRINGS", "5000"))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ghidra_available() -> bool:
    if not GHIDRA_ANALYZE_HEADLESS:
        debug_log("[GHIDRA] SKIP", "GHIDRA_ANALYZE_HEADLESS not resolved")
        return False

    p = Path(GHIDRA_ANALYZE_HEADLESS)
    if not p.exists():
        debug_log("[GHIDRA] SKIP", f"Resolved path no longer exists: {p}")
        return False

    debug_log("[GHIDRA] CHECK", f"Executable confirmed: {p}")
    return True


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
        debug_log("[GHIDRA] WARN", f"Output file is empty: {candidate.name}")
        # Return empty list — valid (zero results), not a failure
        return []

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
) -> list[str]:
    cmd_core = [
        GHIDRA_ANALYZE_HEADLESS,
        str(project_dir),
        project_name,
        "-import", binary_path,
        "-overwrite",
        "-scriptPath", GHIDRA_SCRIPTS_DIR,
        "-postScript", script_name,
        *script_args,
        "-log", str(project_dir / f"{script_name}.log"),
    ]

    # FIX 2 — Only delete project on LAST script so imports persist across scripts
    if is_last_script:
        cmd_core.append("-deleteProject")

    # FIX 3 — Windows-safe execution via cmd.exe /c
    if _IS_WINDOWS:
        return ["cmd.exe", "/c"] + cmd_core

    return cmd_core


def _run_headless(cmd: list[str]) -> subprocess.CompletedProcess:
    """
    FIX: Log the full command before execution so subprocess activity is
    always visible in debug output.
    """
    printable = " ".join(f'"{c}"' if " " in c else c for c in cmd)
    debug_log("[GHIDRA] CMD", printable)

    return subprocess.run(
        cmd,
        shell=False,
        capture_output=True,
        text=True,
        timeout=GHIDRA_TIMEOUT,
    )


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
    global GHIDRA_ANALYZE_HEADLESS
    GHIDRA_ANALYZE_HEADLESS = _resolve_headless()

    if not _ghidra_available():
        debug_log("[GHIDRA] FAIL", "Ghidra not available — skipping")
        return None

    if not os.path.isfile(file_path):
        debug_log("[GHIDRA] FAIL", f"Target file does not exist: {file_path}")
        return None

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
                )
                proc = _run_headless(cmd)

                # FIX 6 — Log stdout/stderr regardless of return code
                if proc.returncode != 0:
                    debug_log(
                        "[GHIDRA] WARN",
                        f"{script_name} exited {proc.returncode}\n"
                        f"STDERR: {proc.stderr[-800:]}\n"
                        f"STDOUT: {proc.stdout[-400:]}",
                    )
                else:
                    debug_log("[GHIDRA] SCRIPT OK", script_name)
                    if proc.stdout.strip():
                        debug_log("[GHIDRA] STDOUT", proc.stdout[-400:])

            except subprocess.TimeoutExpired:
                debug_log("[GHIDRA] WARN", f"{script_name} timed out after {GHIDRA_TIMEOUT}s")
            except Exception as exc:
                debug_log("[GHIDRA] WARN", f"{script_name} raised: {type(exc).__name__}: {exc}")

        # ── Parse outputs ──────────────────────────────────────────────────
        raw_functions = _read_json_output(output_dir, "extract_functions")
        raw_calls     = _read_json_output(output_dir, "extract_calls")
        raw_strings   = _read_json_output(output_dir, "extract_strings")

        # FIX 7 — None means file missing/corrupt; [] means Ghidra ran but found nothing.
        #          Treat both [] and None as "no data for this category" — never abort.
        functions = _normalize_functions(raw_functions if raw_functions is not None else [])
        calls     = _normalize_calls(raw_calls if raw_calls is not None else [])
        strings   = _normalize_strings(raw_strings if raw_strings is not None else [])

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
                "elapsed":        elapsed,
                "function_count": len(functions),
                "call_count":     len(calls),
                "string_count":   len(strings),
                # Distinguish "ran but empty" from "not ran at all"
                "scripts_executed": [s for s, _ in scripts],
                "output_dir_files": [
                    f.name for f in output_dir.iterdir()
                ] if output_dir.exists() else [],
            },
        }

        debug_log("[GHIDRA] SUCCESS", f"{len(functions)} funcs, {len(strings)} strings in {elapsed}s")
        return result

    except Exception as exc:
        debug_log("[GHIDRA] FAIL", f"Unhandled exception: {type(exc).__name__}: {exc}")
        return None

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        debug_log("[GHIDRA] CLEANUP", str(tmp_dir))
