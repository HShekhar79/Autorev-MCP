import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

SERVER_FILE = "test_mcp_ping_server.py"

server_code = """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ping-test")

@mcp.tool()
def ping() -> dict:
    return {"ok": True}

if __name__ == "__main__":
    mcp.run()
"""

with open(SERVER_FILE, "w", encoding="utf-8") as f:
    f.write(server_code)

async def main():
    print("PING_TEST_STARTED", flush=True)

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

    print("PING_TEST_FINISHED", flush=True)

asyncio.run(main())
