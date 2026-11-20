"""MCPManager: connect to configured MCP servers and expose OpenAI-style tool specs."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from agentx.config import MCPConfig, settings
from agentx.mcp.client import session_scope

MAX_TOOL_RESULT_CHARS = 128_000

# Playwright MCP may download on first run -> allow a generous connect window
CONNECT_TIMEOUT = 120.0
STOP_TIMEOUT = 15.0


def _render_result(res: Any) -> str:
    """Turn a CallToolResult into plain text (images become placeholders)."""
    parts: list[str] = []
    for item in getattr(res, "content", None) or []:
        text = getattr(item, "text", None)
        if isinstance(text, str) and text:
            parts.append(text)
            continue
        mime = getattr(item, "mime_type", None) or getattr(item, "mimeType", None)
        data = getattr(item, "data", None)
        if mime and data is not None:
            size = len(data) if hasattr(data, "__len__") else "?"
            parts.append(f"[binary {mime} {size} bytes]")
            continue
        parts.append(str(item))
    if parts:
        return "\n".join(parts)
    structured = getattr(res, "structured_content", None)
    if structured is not None:
        try:
            return json.dumps(structured, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001
            return str(structured)
    return "<no content>"


async def _list_tools(impl: Any) -> dict[str, dict[str, Any]]:
    res = await impl.list_tools()
    tools: dict[str, dict[str, Any]] = {}
    for t in res.tools:
        tools[t.name] = {
            "description": t.description or "",
            "input_schema": t.input_schema or {"type": "object", "properties": {}},
        }
    return tools


class _ManagedConnection:
    """Owns one MCP connection inside its own asyncio task.

    ``anyio`` task groups/cancel scopes must be exited in the task that entered
    them, so we never touch the transport CM from a different task (CLI
    shutdown vs. TUI unmount, test fixtures, ...).
    """

    def __init__(self, cfg: MCPConfig) -> None:
        self.cfg = cfg
        self.impl: Any = None
        self.tools: dict[str, dict[str, Any]] = {}
        self.error: str | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"mcp-{self.cfg.name}")
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=CONNECT_TIMEOUT)
        except TimeoutError:
            await self.stop()
            raise TimeoutError(f"{self.cfg.name}: connection timed out") from None
        if self.error:
            raise RuntimeError(self.error)

    async def _run(self) -> None:
        try:
            async with session_scope(self.cfg) as impl:
                self.impl = impl
                self.tools = await _list_tools(impl)
                self._ready.set()
                await self._stop.wait()
        except Exception as exc:  # noqa: BLE001 - captured for initialize()
            self.error = f"{self.cfg.name}: {exc}"
        finally:
            self._ready.set()
            self.impl = None

    async def stop(self) -> None:
        self._stop.set()
        task = self._task
        if task is None:
            return
        self._task = None
        try:
            await asyncio.wait_for(task, timeout=STOP_TIMEOUT)
        except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


@dataclass
class LiveServer:
    """A connected MCP server with its discovered tools."""

    cfg: MCPConfig
    impl: Any
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)


class MCPManager:
    """Connect to all enabled MCP servers and manage tool calls."""

    def __init__(self) -> None:
        self._servers: dict[str, LiveServer] = {}
        self._by_full_name: dict[str, tuple[str, str]] = {}
        self._connections: dict[str, _ManagedConnection] = {}
        self.warnings: list[str] = []

    @property
    def is_connected(self) -> bool:
        return bool(self._servers)

    @property
    def server_count(self) -> int:
        return len(self._servers)

    @property
    def tool_count(self) -> int:
        return len(self._by_full_name)

    async def initialize(self) -> int:
        """Connect every enabled server; failures are recorded as warnings."""
        if self._servers:
            return len(self._servers)
        for cfg in settings.get_enabled_mcp_servers():
            conn = _ManagedConnection(cfg)
            try:
                await conn.start()
            except Exception as exc:  # noqa: BLE001 - surface connection issues
                self.warnings.append(f"{cfg.name}: {exc}")
                await conn.stop()
                continue
            self._connections[cfg.name] = conn
            self._register(cfg, conn.impl, conn.tools)
        return len(self._servers)

    def _register(self, cfg: MCPConfig, impl: Any, tools: dict[str, dict[str, Any]]) -> None:
        server = cfg.name
        self._servers[server] = LiveServer(cfg=cfg, impl=impl, tools=tools)
        for tool_name in tools:
            full = f"mcp_{server}_{tool_name}"
            while full in self._by_full_name:  # collision guard
                full += "_"
            self._by_full_name[full] = (server, tool_name)

    def tool_specs(self) -> list[dict[str, Any]]:
        """OpenAI-style function specs so the LLM can pick tools."""
        specs: list[dict[str, Any]] = []
        for full, (server, tool) in sorted(self._by_full_name.items()):
            t = self._servers[server].tools[tool]
            description = t["description"]
            if description:
                description = f"[{server}] {description}"
            specs.append(
                {
                    "type": "function",
                    "function": {
                        "name": full,
                        "description": description,
                        "parameters": t["input_schema"],
                    },
                }
            )
        return specs

    def describe(self, full_name: str) -> tuple[str, str, bool] | None:
        """Return (server, tool, cfg_auto_approve) for a full tool name or None."""
        found = self._by_full_name.get(full_name)
        if not found:
            return None
        server, tool = found
        return server, tool, self._servers[server].cfg.auto_approve

    async def call(
        self,
        full_name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
    ) -> tuple[bool, str]:
        """Call an MCP tool; returns (ok, rendered_result_or_error)."""
        found = self._by_full_name.get(full_name)
        if not found:
            available = ", ".join(sorted(self._by_full_name)) or "(none)"
            return False, f"Unknown MCP tool {full_name!r}. Available: {available}"
        server, tool = found
        live = self._servers.get(server)
        if live is None or live.impl is None:
            return False, f"MCP server '{server}' is not connected"
        try:
            res = await live.impl.call_tool(
                tool, arguments or {}, read_timeout_seconds=read_timeout_seconds
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"MCP tool {full_name} failed: {exc}"
        text = _render_result(res)
        if len(text) > MAX_TOOL_RESULT_CHARS:
            text = text[:MAX_TOOL_RESULT_CHARS] + "\n...[truncated]"
        is_error = bool(getattr(res, "is_error", False))
        return (not is_error), text

    def summary(self) -> dict[str, Any]:
        servers = [
            {
                "name": name,
                "transport": live.cfg.transport,
                "auto_approve": live.cfg.auto_approve,
                "tools": sorted(live.tools),
            }
            for name, live in self._servers.items()
        ]
        return {"servers": servers, "tool_count": len(self._by_full_name)}

    async def close(self) -> None:
        conns = list(self._connections.values())
        self._connections.clear()
        self._servers.clear()
        self._by_full_name.clear()
        self.warnings.clear()
        if conns:
            await asyncio.gather(*(c.stop() for c in conns), return_exceptions=True)


# Process-wide singleton
mcp_manager = MCPManager()
