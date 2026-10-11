import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SAMPLE = r"C:\nope\x.exe"

async def main():
    print("MCP_TEST_STARTED", flush=True)
    print("CLIENT_PYTHON=", sys.executable, flush=True)

    server = StdioServerParameters(
        command=sys.executable,
        args=["mcp_server.py"],
        env=dict(os.environ),
    )

    async with stdio_client(server) as (read, write):
        print("STDIO_CLIENT_CONNECTED", flush=True)

        async with ClientSession(read, write) as session:
            print("SESSION_CREATED", flush=True)

            await session.initialize()
            print("INITIALIZE_OK", flush=True)

            tools = await session.list_tools()
            print("TOOL_COUNT=", len(tools.tools), flush=True)
            print("TOOLS=", [t.name for t in tools.tools], flush=True)

            print("BEFORE_CALL_TOOL", flush=True)

            result = await asyncio.wait_for(
                session.call_tool(
                    "quick_summary",
                    arguments={"file_path": SAMPLE},
                ),
                timeout=20,
            )

            print("CALL_TOOL_RETURNED", flush=True)
            print(
                "RESULT=",
                json.dumps(result.model_dump(), default=str),
                flush=True,
            )

    print("MCP_TEST_FINISHED", flush=True)

asyncio.run(main())
