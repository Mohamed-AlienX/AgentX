"""End-to-end tests for the MCP client and manager (fake stdio server)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentx.config import MCPConfig, settings
from agentx.mcp.manager import MCPManager

FAKE_SERVER = Path(__file__).parent / "fake_mcp_server.py"


def _fake_cfg() -> MCPConfig:
    return MCPConfig(
        name="fake",
        transport="stdio",
        command=sys.executable,
        args=["-u", str(FAKE_SERVER)],
        enabled=True,
    )


@pytest.fixture
async def mcp_manager(monkeypatch):
    monkeypatch.setattr(settings, "mcp_servers", [_fake_cfg()])
    mgr = MCPManager()
    count = await mgr.initialize()
    assert count == 1
    yield mgr
    await mgr.close()


async def test_initialize_discovers_tools(mcp_manager: MCPManager) -> None:
    assert mcp_manager.server_count == 1
    assert mcp_manager.tool_count == 2
    assert mcp_manager.warnings == []
    specs = mcp_manager.tool_specs()
    names = [s["function"]["name"] for s in specs]
    assert names == ["mcp_fake_add", "mcp_fake_echo"]
    assert specs[0]["function"]["parameters"]["type"] == "object"


async def test_call_tool_returns_rendered_text(mcp_manager: MCPManager) -> None:
    ok, text = await mcp_manager.call("mcp_fake_echo", {"msg": "hello"})
    assert ok is True
    assert text == "echo:hello"

    ok, text = await mcp_manager.call("mcp_fake_add", {"a": 2, "b": 3})
    assert ok is True
    assert text == "5"


async def test_describe_maps_full_name(mcp_manager: MCPManager) -> None:
    assert mcp_manager.describe("mcp_fake_echo") == ("fake", "echo", False)
    assert mcp_manager.describe("mcp_nope") is None


async def test_call_unknown_tool(mcp_manager: MCPManager) -> None:
    ok, text = await mcp_manager.call("mcp_fake_missing", {})
    assert ok is False
    assert "Unknown MCP tool" in text


async def test_connection_failure_becomes_warning(monkeypatch) -> None:
    bad = MCPConfig(
        name="bad",
        transport="stdio",
        command=sys.executable,
        args=["-c", "raise SystemExit(1)"],
        enabled=True,
    )
    monkeypatch.setattr(settings, "mcp_servers", [bad])
    mgr = MCPManager()
    count = await mgr.initialize()
    assert count == 0
    assert mgr.warnings
    assert "bad" in mgr.warnings[0]
    await mgr.close()
