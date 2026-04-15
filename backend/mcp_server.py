from mcp.server.fastmcp import FastMCP
import traceback
import sys
import os

# ---------------------------------------------------------------------------
# FORCE CORRECT PYTHON PATH RESOLUTION
# ---------------------------------------------------------------------------

_THIS_FILE = os.path.abspath(__file__)
_BACKEND_DIR = os.path.dirname(_THIS_FILE)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)

if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ---------------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------------

from utils.debug import debug_log

# Unified extractor (safe import)
try:
    from engines.unified_extractor.unified_extractor import run_unified_extraction as _run_unified_extraction
    _EXTRACTOR_AVAILABLE = True
    debug_log("[MCP] IMPORT", "run_unified_extraction: OK")
except Exception as _e:
    _EXTRACTOR_AVAILABLE = False
    _run_unified_extraction = None
    debug_log("[MCP] IMPORT FAIL", f"run_unified_extraction: {_e}")

# Pipeline import (STRICT ABSOLUTE)
try:
    from backend.analysis import run_analysis_pipeline as _run_analysis_pipeline
    _PIPELINE_AVAILABLE = True
    debug_log("[MCP] IMPORT", "run_analysis_pipeline: OK")
except Exception as _e:
    _PIPELINE_AVAILABLE = False
    _run_analysis_pipeline = None
    debug_log("[MCP] IMPORT FAIL", f"run_analysis_pipeline: {_e}")

# ---------------------------------------------------------------------------
# MCP SERVER
# ---------------------------------------------------------------------------

mcp = FastMCP("malware-analysis")

# ---------------------------------------------------------------------------
# INTERNAL HELPERS
# ---------------------------------------------------------------------------

def _guard_file(file_path: str):
    if not file_path or not isinstance(file_path, str):
        return "file_path must be a non-empty string"

    if not os.path.isfile(file_path):
        return f"File not found: {file_path}"

    return None


def _run_pipeline(file_path: str) -> dict:
    if not _PIPELINE_AVAILABLE or _run_analysis_pipeline is None:
        debug_log("[MCP] PIPELINE UNAVAILABLE", file_path)
        return {"error": "analysis pipeline module not available"}

    debug_log("[MCP] PIPELINE START", file_path)

    try:
        result = _run_analysis_pipeline(file_path)

        if not isinstance(result, dict):
            return {"error": "pipeline returned non-dict", "raw": str(result)}

        debug_log("[MCP] PIPELINE OK", f"keys={list(result.keys())}")
        return result

    except Exception as exc:
        debug_log("[MCP] PIPELINE ERROR", str(exc))
        return {
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


def _safe_mitre_ids(result: dict) -> list:
    fm = result.get("final_mitre") or {}

    ids = fm.get("mitre_techniques") or fm.get("final_mitre") or []

    if not ids:
        mr = result.get("mitre_results") or {}
        ids = mr.get("techniques") or mr.get("mitre") or []

    return ids if isinstance(ids, list) else []


# ---------------------------------------------------------------------------
# TOOL 1 — FULL ANALYSIS
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_file(file_path: str) -> dict:

    debug_log("[MCP] analyze_file START", file_path)

    err = _guard_file(file_path)
    if err:
        return {"status": "error", "error": err}

    result = _run_pipeline(file_path)

    if "error" in result and len(result) <= 2:
        return {"status": "error", **result}

    meta = result.get("analysis_meta", {})

    return {
        "status": "success",
        "data": {
            "functions": result.get("functions", []),
            "imports": result.get("imports", []),
            "strings": result.get("strings", []),
            "calls": result.get("calls", []),
            "capabilities": result.get("capabilities", []),
            "mitre": _safe_mitre_ids(result),
            "risk_score": result.get("risk_score", 0),
            "cvss": result.get("cvss", {}),
            "verdict": result.get("verdict", {}),
            "analysis_meta": {
                "ghidra_available": meta.get("ghidra_available", False),
                "radare2_available": meta.get("radare2_available", True),
                "extraction_engine": meta.get("extraction_engine", "unknown"),
                "capa_enabled": meta.get("capa_enabled", False),
                "extraction_elapsed": meta.get("extraction_elapsed"),
            },
        },
    }


# ---------------------------------------------------------------------------
# TOOL 2 — QUICK SUMMARY
# ---------------------------------------------------------------------------

@mcp.tool()
def quick_summary(file_path: str) -> dict:

    debug_log("[MCP] quick_summary START", file_path)

    err = _guard_file(file_path)
    if err:
        return {"status": "error", "error": err}

    result = _run_pipeline(file_path)

    if "error" in result and len(result) <= 2:
        return {"status": "error", **result}

    return {
        "status": "success",
        "verdict": result.get("verdict", {}),
        "risk_score": result.get("risk_score", 0),
        "cvss": result.get("cvss", {}),
        "mitre": _safe_mitre_ids(result),
        "capabilities": result.get("capabilities", []),
    }


# ---------------------------------------------------------------------------
# TOOL 3 — EXTRACTION ONLY
# ---------------------------------------------------------------------------

@mcp.tool()
def extract_only(file_path: str) -> dict:

    debug_log("[MCP] extract_only START", file_path)

    err = _guard_file(file_path)
    if err:
        return {"status": "error", "error": err}

    if not _EXTRACTOR_AVAILABLE or _run_unified_extraction is None:
        return {"status": "error", "error": "unified extractor not available"}

    try:
        extraction = _run_unified_extraction(file_path)

        return {
            "status": "success",
            "data": extraction
        }

    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "trace": traceback.format_exc(),
        }


# ---------------------------------------------------------------------------
# TOOL 4 — MITRE EXPLAIN
# ---------------------------------------------------------------------------

@mcp.tool()
def explain_mitre(file_path: str) -> dict:

    debug_log("[MCP] explain_mitre START", file_path)

    err = _guard_file(file_path)
    if err:
        return {"status": "error", "error": err}

    result = _run_pipeline(file_path)

    if "error" in result and len(result) <= 2:
        return {"status": "error", **result}

    techniques = _safe_mitre_ids(result)
    capabilities = result.get("capabilities", [])

    explanations = []

    for t in techniques:
        explanations.append({
            "technique": t,
            "explanation": f"Technique {t} detected via behavioral patterns and capability signals."
        })

    return {
        "status": "success",
        "mitre_details": explanations
    }


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug_log("[MCP]", "Starting MCP server...")
    mcp.run()