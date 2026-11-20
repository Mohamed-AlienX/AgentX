"""Low-level MCP transport adapter (mcp python-sdk 2.x).

Exposes one async context manager, ``session_scope``, that yields a connected
client with ``list_tools`` / ``call_tool`` methods across all three transports:

* stdio  -> ``mcp.Client(StdioServerParameters)``   (auto protocol negotiation)
* sse    -> legacy ``ClientSession`` over ``sse_client``  (Burp MCP server)
* http   -> ``mcp.Client(<url>)``                   (streamable HTTP)
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from mcp import Client, ClientSession, StdioServerParameters
from mcp.client.sse import sse_client

from agentx.config import MCPConfig

if TYPE_CHECKING:
    pass


class MCPServerError(RuntimeError):
    """Raised when an MCP server cannot be connected."""


@asynccontextmanager
async def session_scope(cfg: MCPConfig) -> AsyncIterator[Any]:
    """Open a connected MCP client session that supports ``list_tools`` and ``call_tool``.

    The session stays alive until the context exits (subprocess/http connection
    is shut down then).
    """
    if cfg.transport == "stdio":
        if not cfg.command:
            raise MCPServerError(f"MCP server '{cfg.name}': stdio transport requires 'command'")
        params = StdioServerParameters(command=cfg.command, args=cfg.args, env=cfg.env or None)
        client = Client(params)
        async with client as impl:
            yield impl
        return

    if cfg.transport == "sse":
        if not cfg.url:
            raise MCPServerError(f"MCP server '{cfg.name}': sse transport requires 'url'")
        async with sse_client(cfg.url, headers=cfg.headers or None) as (read, write):
            session = ClientSession(read, write)
            await session.initialize()
            try:
                yield session
            finally:
                pass
        return

    # streamable HTTP
    if not cfg.url:
        raise MCPServerError(f"MCP server '{cfg.name}': http transport requires 'url'")
    client = Client(cfg.url)
    async with client as impl:
        yield impl
