
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ping-test")

@mcp.tool()
def ping() -> dict:
    return {"ok": True}

if __name__ == "__main__":
    mcp.run()
