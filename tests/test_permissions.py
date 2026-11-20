"""Permission gate policy tests."""

from __future__ import annotations

from agentx.mcp.permissions import PermissionGate


async def test_ask_mode_sensitive_tool_denied_without_approver() -> None:
    gate = PermissionGate(mode="ask", auto_approve=[])
    assert gate.requires_approval("burp", "send_http_request")
    assert await gate.check("burp", "send_http_request", {"url": "http://x"}) is False


async def test_ask_mode_read_tools_are_automatic() -> None:
    gate = PermissionGate(mode="ask", auto_approve=[])
    assert not gate.requires_approval("browser", "get_page_snapshot")
    assert await gate.check("browser", "get_page_snapshot", {}) is True


async def test_ask_mode_approver_grants_once() -> None:
    gate = PermissionGate(mode="ask", auto_approve=[])

    async def approve(server, tool, arguments, summary) -> bool:
        return True

    gate.approver = approve
    assert await gate.check("burp", "send_http_request", {"method": "GET"}) is True


async def test_ask_mode_approver_can_deny() -> None:
    gate = PermissionGate(mode="ask", auto_approve=[])

    async def deny(server, tool, arguments, summary) -> bool:
        return False

    gate.approver = deny
    assert await gate.check("browser", "navigate", {"url": "http://x"}) is False


async def test_auto_and_yolo_never_prompt() -> None:
    for mode in ("auto", "yolo"):
        gate = PermissionGate(mode=mode, auto_approve=[])
        assert not gate.requires_approval("burp", "send_http_request")
        assert await gate.check("burp", "send_http_request", {}) is True


async def test_auto_approve_list_bypasses() -> None:
    gate = PermissionGate(mode="ask", auto_approve=["burp.send_http_request"])
    assert not gate.requires_approval("burp", "send_http_request")
    assert await gate.check("burp", "send_http_request", {}) is True


async def test_session_approval_bypasses() -> None:
    gate = PermissionGate(mode="ask", auto_approve=[])
    assert gate.requires_approval("burp", "send_http_request")
    gate.allow_session("burp.send_http_request")
    assert not gate.requires_approval("burp", "send_http_request")
    assert await gate.check("burp", "send_http_request", {}) is True


async def test_server_auto_approve_bool_bypasses() -> None:
    gate = PermissionGate(mode="ask", auto_approve=[])
    assert not gate.requires_approval("burp", "send_http_request", cfg_auto_approve=True)
    assert await gate.check("burp", "send_http_request", {}, cfg_auto_approve=True) is True
