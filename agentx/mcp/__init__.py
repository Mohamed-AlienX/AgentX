"""MCP (Model Context Protocol) tool integration for AgentX.

Connects the AI agent to external tools (browser, Burp Suite, ...) through a
plan->act->observe tool-calling loop with a permission gate.
"""

from agentx.mcp.client import MCPServerError, session_scope
from agentx.mcp.manager import MCPManager, mcp_manager
from agentx.mcp.permissions import PermissionGate, permission_gate

__all__ = [
    "MCPServerError",
    "session_scope",
    "MCPManager",
    "mcp_manager",
    "PermissionGate",
    "permission_gate",
]
