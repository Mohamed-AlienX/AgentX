"""Tiny MCP server used by the test-suite (run as a stdio child process)."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("fake-mcp-server")


@server.tool()
def echo(msg: str) -> str:
    """Echo the message back prefixed with 'echo:'."""
    return f"echo:{msg}"


@server.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    server.run()  # transport='stdio'
