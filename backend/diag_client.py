import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

NOPE = r"C:\nope\x.exe"

CASES = [
    ("d_noarg", {}),
    ("d_arg", {"file_path": NOPE}),
    ("d_stderr", {"file_path": NOPE}),
    ("d_isfile", {"file_path": NOPE}),
    ("d_guard", {"file_path": NOPE}),
    ("quick_summary", {"file_path": NOPE}),
    ("analyze_file", {"file_path": NOPE}),
]

async def run(tool, args):
    params = StdioServerParameters(
        command=sys.executable,
        args=["diag_server.py"],
        env=dict(os.environ),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            try:
                result = await asyncio.wait_for(
                    session.call_tool(tool, arguments=args),
                    timeout=15,
                )
                return "OK  " + json.dumps(
                    result.model_dump(),
                    default=str,
                )[:120]
            except asyncio.TimeoutError:
                return "HANG"

async def main():
    for tool, args in CASES:
        print(f"{tool:14s}", await run(tool, args), flush=True)

asyncio.run(main())
