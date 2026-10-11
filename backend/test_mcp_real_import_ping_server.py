
import os
import sys

_THIS_FILE = os.path.abspath(__file__)
_BACKEND_DIR = os.path.dirname(_THIS_FILE)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)

if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from utils.debug import debug_log

from engines.unified_extractor.unified_extractor import (
    run_unified_extraction,
)

from services.analysis_pipeline import (
    run_analysis_pipeline,
    to_legacy_result,
)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("real-import-ping")

@mcp.tool()
def ping() -> dict:
    return {"ok": True}

if __name__ == "__main__":
    debug_log("[TEST]", "Real AutoRev imports loaded")
    mcp.run()
