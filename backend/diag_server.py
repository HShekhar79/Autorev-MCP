import os
import sys
import time
import mcp_server as real
from mcp_server import mcp, _guard_file
from utils.debug import debug_log

TRACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diag_trace.log")

def trace(msg):
    with open(TRACE, "a", encoding="utf-8") as f:
        f.write(f"{time.time():.3f} {msg}\n")

for name, t in mcp._tool_manager._tools.items():
    trace(
        f"REG {name} async={t.is_async} "
        f"ctx={t.context_kwarg} "
        f"params={t.parameters.get('properties')} "
        f"fn={t.fn!r}"
    )

@mcp.tool()
def d_noarg() -> dict:
    trace("d_noarg body")
    return {"ok": True}

@mcp.tool()
def d_arg(file_path: str) -> dict:
    trace("d_arg body")
    return {"ok": True}

@mcp.tool()
def d_stderr(file_path: str) -> dict:
    trace("d_stderr before debug_log")
    debug_log("[DIAG] d_stderr", file_path)
    trace("d_stderr after debug_log")
    return {"ok": True}

@mcp.tool()
def d_isfile(file_path: str) -> dict:
    trace("d_isfile before")
    r = os.path.isfile(file_path)
    trace(f"d_isfile after {r}")
    return {"ok": r}

@mcp.tool()
def d_guard(file_path: str) -> dict:
    trace("d_guard before")
    e = _guard_file(file_path)
    trace(f"d_guard after {e}")
    return {"err": e}

for name in ("quick_summary", "analyze_file"):
    tool = mcp._tool_manager._tools[name]
    orig = tool.fn

    def make(orig, name):
        def wrapped(file_path: str) -> dict:
            trace(f"REAL {name} ENTER {file_path!r}")
            try:
                r = orig(file_path)
                trace(f"REAL {name} EXIT {str(r)[:80]!r}")
                return r
            except BaseException as e:
                trace(f"REAL {name} RAISED {e!r}")
                raise
        return wrapped

    tool.fn = make(orig, name)

if __name__ == "__main__":
    mcp.run()
