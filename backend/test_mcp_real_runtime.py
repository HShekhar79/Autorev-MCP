import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SAMPLE = r"C:\Users\Himanshu Shekhar\Desktop\autorev-mcp\project-root\test-binaries\test_mitre.exe"

async def main():
    print("MCP_REAL_TEST_STARTED", flush=True)
    print("SERVER_PYTHON=", sys.executable, flush=True)

    server = StdioServerParameters(
        command=sys.executable,
        args=[os.path.abspath(r".\backend\test_mcp_server_launcher.py")],
        env=dict(os.environ),
    )

    async with stdio_client(server) as (read, write):
        print("STDIO_CONNECTED", flush=True)

        async with ClientSession(read, write) as session:
            await session.initialize()
            print("INITIALIZE_OK", flush=True)

            tools = await session.list_tools()
            print("TOOLS=", [t.name for t in tools.tools], flush=True)

            print("BEFORE_ANALYZE", flush=True)

            result = await asyncio.wait_for(
                session.call_tool(
                    "analyze_file",
                    arguments={"file_path": SAMPLE},
                ),
                timeout=180,
            )

            print("ANALYZE_RETURNED", flush=True)

            data = result.model_dump()
            text = data.get("content", [{}])[0].get("text", "")
            payload = json.loads(text)

            print("STATUS=", payload.get("status"), flush=True)

            if payload.get("status") == "success":
                analysis = payload.get("data", {})
                print("FUNCTIONS=", len(analysis.get("functions", [])), flush=True)
                print("CALLS=", len(analysis.get("calls", [])), flush=True)
                print("CAPABILITIES=", len(analysis.get("capabilities", [])), flush=True)
                print("MITRE=", len(analysis.get("mitre", [])), flush=True)
                print("RISK=", analysis.get("risk_score"), flush=True)
                print("CVSS=", analysis.get("cvss", {}), flush=True)
                print("VERDICT=", analysis.get("verdict", {}), flush=True)
                print("META=", analysis.get("analysis_meta", {}), flush=True)
            else:
                print("ERROR=", payload.get("error"), flush=True)

    print("MCP_REAL_TEST_FINISHED", flush=True)

asyncio.run(main())

