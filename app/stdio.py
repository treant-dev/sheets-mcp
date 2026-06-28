"""Local stdio entry for Claude Desktop.

Registers the Sheets tools with the official MCP SDK (FastMCP) and serves over
stdio. Phase 2 reuses the same tool functions (tools.ALL) with mcp-lambda-handler.
"""
from mcp.server.fastmcp import FastMCP

import tools

mcp = FastMCP("treant-sheets-mcp")

for fn in tools.ALL:
    mcp.add_tool(fn)


def main():
    mcp.run()  # stdio transport by default


if __name__ == "__main__":
    main()
