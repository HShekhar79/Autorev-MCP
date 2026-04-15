from __future__ import annotations

import time
from typing import Optional

from utils.debug import debug_log

# ── Engine imports ─────────────────────────────────────────────────────────
from engines.extractor_engine.radare_extractor import (
    extract_functions as r2_extract_functions,
    extract_imports  as r2_extract_imports,
    extract_strings  as r2_extract_strings,
)

try:
    from engines.ghidra_engine.ghidra_engine import run_ghidra_analysis
    _GHIDRA_MODULE_AVAILABLE = True
    debug_log("[UNIFIED] ghidra module", "imported successfully")
except ImportError as _ghidra_import_err:
    _GHIDRA_MODULE_AVAILABLE = False
    run_ghidra_analysis = None  # type: ignore
    debug_log("[UNIFIED] ghidra module IMPORT FAIL", str(_ghidra_import_err))


# ---------------------------------------------------------------------------
# Merge helpers — UNCHANGED
# ---------------------------------------------------------------------------

def _merge_functions(r2_funcs: list, ghidra_funcs: list) -> list:
    merged: dict[str, dict] = {}

    for func in r2_funcs:
        name = (func.get("name") or "").strip()
        if name:
            merged[name] = func

    for func in ghidra_funcs:
        name = (func.get("name") or "").strip()
        if name and name not in merged:
            merged[name] = func

    result = list(merged.values())
    debug_log(
        "[UNIFIED] functions merged",
        f"r2={len(r2_funcs)}, ghidra={len(ghidra_funcs)}, result={len(result)}",
    )
    return result


def _merge_strings(r2_strings: list[str], ghidra_strings: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for s in r2_strings:
        if s and s not in seen:
            seen.add(s)
            result.append(s)

    for s in ghidra_strings:
        if s and s not in seen:
            seen.add(s)
            result.append(s)

    debug_log(
        "[UNIFIED] strings merged",
        f"r2={len(r2_strings)}, ghidra={len(ghidra_strings)}, result={len(result)}",
    )
    return result


def _merge_calls(ghidra_calls: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for c in ghidra_calls:
        if c and c not in seen:
            seen.add(c)
            result.append(c)
    return result


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def run_unified_extraction(file_path: str) -> dict:
    t0 = time.monotonic()

    # ── RADARE2 ────────────────────────────────────────────────────────────
    r2_functions: list = []
    r2_imports:   list = []
    r2_strings:   list[str] = []
    r2_available = False

    try:
        r2_functions = r2_extract_functions(file_path) or []
        r2_imports   = r2_extract_imports(file_path)   or []
        r2_strings   = r2_extract_strings(file_path)   or []
        r2_available = True
        debug_log(
            "[UNIFIED] radare2 OK",
            f"{len(r2_functions)} funcs, {len(r2_imports)} imports, {len(r2_strings)} strings",
        )
    except Exception as exc:
        debug_log("[UNIFIED] radare2 FAIL", f"{type(exc).__name__}: {exc}")

    # ── GHIDRA ─────────────────────────────────────────────────────────────
    ghidra_result:    Optional[dict] = None
    ghidra_available  = False

    if _GHIDRA_MODULE_AVAILABLE and run_ghidra_analysis is not None:
        debug_log("[UNIFIED] ghidra", "attempting analysis...")

        try:
            ghidra_result = run_ghidra_analysis(file_path)

            # FIX — ghidra_available must be True whenever run_ghidra_analysis
            # returns a dict, regardless of whether that dict has any entries.
            # None is the only sentinel for "Ghidra did not run / is not installed".
            if ghidra_result is not None:
                ghidra_available = True

                g_funcs  = ghidra_result.get("functions", [])
                g_strs   = ghidra_result.get("strings",   [])
                g_calls  = ghidra_result.get("calls",     [])

                if g_funcs or g_strs or g_calls:
                    debug_log("[UNIFIED] ghidra OK",    ghidra_result.get("_meta", {}))
                else:
                    # Ran fine but binary produced no extractable symbols
                    debug_log(
                        "[UNIFIED] ghidra PARTIAL",
                        "executed successfully — zero output (empty binary or stripped)",
                    )
            else:
                debug_log(
                    "[UNIFIED] ghidra returned None",
                    "Ghidra unavailable or setup failed — see [GHIDRA] logs above",
                )

        except Exception as exc:
            debug_log("[UNIFIED] ghidra EXCEPTION", f"{type(exc).__name__}: {exc}")
            # ghidra_result stays None → ghidra_available stays False
    else:
        debug_log("[UNIFIED] ghidra module not importable", "radare2-only mode active")

    # ── MERGE ──────────────────────────────────────────────────────────────
    ghidra_functions: list      = ghidra_result.get("functions", []) if ghidra_result else []
    ghidra_strings:   list[str] = ghidra_result.get("strings",   []) if ghidra_result else []
    ghidra_calls:     list[str] = ghidra_result.get("calls",     []) if ghidra_result else []

    merged_functions = _merge_functions(r2_functions, ghidra_functions)
    merged_strings   = _merge_strings(r2_strings, ghidra_strings)
    merged_calls     = _merge_calls(ghidra_calls)

    elapsed = round(time.monotonic() - t0, 2)

    result: dict = {
        "functions": merged_functions,
        "imports":   r2_imports,
        "strings":   merged_strings,
        "calls":     merged_calls,
        "_meta": {
            "radare2_available": r2_available,
            "ghidra_available":  ghidra_available,
            "extraction_engine": (
                "radare2+ghidra" if (r2_available and ghidra_available) else
                "ghidra"         if ghidra_available else
                "radare2"        if r2_available else
                "none"
            ),
            "function_count":    len(merged_functions),
            "import_count":      len(r2_imports),
            "string_count":      len(merged_strings),
            "call_count":        len(merged_calls),
            "elapsed_seconds":   elapsed,
        }
    }

    debug_log("[UNIFIED] extraction complete", result["_meta"])
    return result
