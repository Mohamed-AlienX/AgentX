"""Permission gate for MCP tool calls (policy: ask | auto | yolo)."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from agentx.config import settings

# Substrings that mark a tool as state-changing -> requires approval in ask mode
SENSITIVE_TOOL_NAMES = (
    # Burp Suite MCP
    "send_http_request",
    "create_repeater_tab",
    "send_to_intruder",
    "start_scan",
    "stop_scan",
    "delete_scope",
    "set_scope",
    # Playwright browser MCP
    "navigate",
    "click",
    "fill",
    "type",
    "press_key",
    "select_option",
    "screenshot",
    "new_page",
    "close",
)

# (server, tool, arguments, summary) -> allow
Approver = Callable[[str, str, dict[str, Any], str], Awaitable[bool]]


class PermissionGate:
    """Decide whether a tool call needs user approval.

    Modes:
        ask  -> state-changing tools prompt for approval; reads are automatic
        auto -> never prompt (meant for CI / scripted runs)
        yolo -> never prompt AND run state-changing tools blindly (dangerous)
    """

    def __init__(
        self,
        mode: str | None = None,
        auto_approve: list[str] | None = None,
        approver: Approver | None = None,
    ) -> None:
        self.mode = mode or settings.permission_mode
        self.auto_approve = set(auto_approve) if auto_approve else set(settings.mcp_auto_approve)
        self.approver = approver
        self.session_approved: set[str] = set()

    def set_mode(self, mode: str) -> None:
        self.mode = mode

    def allow_session(self, key: str) -> None:
        """Skip approval for ``server.tool`` for the rest of this session."""
        self.session_approved.add(key)

    def requires_approval(self, server: str, tool: str, cfg_auto_approve: bool = False) -> bool:
        if self.mode in ("auto", "yolo"):
            return False
        key = f"{server}.{tool}"
        if (
            cfg_auto_approve
            or key in self.auto_approve
            or tool in self.auto_approve
            or key in self.session_approved
        ):
            return False
        return any(seg in tool for seg in SENSITIVE_TOOL_NAMES)

    async def check(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        cfg_auto_approve: bool = False,
    ) -> bool:
        """Return True when the tool call is allowed to run."""
        if not self.requires_approval(server, tool, cfg_auto_approve):
            return True
        if self.approver is None:
            return False  # safe default: deny when nobody can approve
        summary = _summarize(arguments or {})
        return await self.approver(server, tool, arguments or {}, summary)


# Process-wide singleton; the CLI/TUI attach their approver + mode here.
permission_gate = PermissionGate()


def _summarize(arguments: dict[str, Any], limit: int = 300) -> str:
    try:
        s = json.dumps(arguments, ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001
        s = repr(arguments)
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s
