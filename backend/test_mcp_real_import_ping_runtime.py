import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_FILE = "test_mcp_real_import_ping_server.py"

server_code = r'''
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
'''

with open(SERVER_FILE, "w", encoding="utf-8") as f:
    f.write(server_code)

async def main():
    print("REAL_IMPORT_TEST_STARTED", flush=True)

    server = StdioServerParameters(
        command=sys.executable,
        args=[SERVER_FILE],
    )

    async with stdio_client(server) as (read, write):
        print("STDIO_CONNECTED", flush=True)

        async with ClientSession(read, write) as session:
            await session.initialize()
            print("INITIALIZE_OK", flush=True)

            tools = await session.list_tools()
            print("TOOLS=", [t.name for t in tools.tools], flush=True)

            print("BEFORE_PING", flush=True)

            result = await asyncio.wait_for(
                session.call_tool("ping", arguments={}),
                timeout=20,
            )

            print("PING_RETURNED", flush=True)
            print("PING_RESULT=", result, flush=True)

    print("REAL_IMPORT_TEST_FINISHED", flush=True)

asyncio.run(main())
