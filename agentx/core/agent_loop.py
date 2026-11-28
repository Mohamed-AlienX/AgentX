"""Claude-Code-style plan->act->observe tool-calling loop over MCP tools.

The LLM drives real tools (browser, Burp) through the MCPManager until it has
enough evidence to answer, hits the step limit, or stops calling tools.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agentx.ai.prompts.orchestrator import ORCHESTRATOR_PROMPT
from agentx.ai.prompts.scope_guard import SCOPE_GUARD_PROMPT
from agentx.ai.router import router
from agentx.config import settings
from agentx.core.session import HuntSession, session_manager
from agentx.mcp import mcp_manager, permission_gate

TOOL_GUIDE = """
\n\n[MCP TOOLS - COMMAND FIRST]
You have real tools attached to this conversation (declared as functions). Prefer
command-first, evidence-producing tool calls over speculative narration.
- Before acting, state the shortest command/tool intent and expected signal.
- Browser tools: open pages, read rendered/JS state, take snapshots/screenshots.
- Burp/tools: send raw requests, inspect responses/history, and capture evidence.
- Run one tool at a time; use returned output to decide the next command.
- Do not claim a vulnerability without reproducible evidence (command output,
  HTTP request/response pair, screenshot path, or shell proof).
When you have enough evidence (or the target/flow is fully inspected), stop
calling tools and write your final answer with evidence-backed findings only.
"""


@dataclass
class ToolTrace:
    """One executed MCP tool call, for display to the user."""

    server: str
    tool: str
    arguments: dict[str, Any]
    ok: bool
    summary: str


@dataclass
class LoopResult:
    """Outcome of an agent loop turn."""

    text: str = ""
    tool_calls: int = 0
    traces: list[ToolTrace] = field(default_factory=list)
    max_steps_hit: bool = False


def build_system_prompt(session: HuntSession | None = None) -> str:
    prompt = ORCHESTRATOR_PROMPT + "\n" + SCOPE_GUARD_PROMPT + TOOL_GUIDE
    if session:
        prompt += (
            "\n\n[Session context] target="
            + (session.target or "unset")
            + f", phase={session.current_phase}, "
            + f"findings={len(session.get_findings())}, "
            + f"completed_skills={session.completed_skills}"
        )
    return prompt


async def run_agent_loop(
    user_input: str,
    session: HuntSession,
    max_steps: int | None = None,
) -> LoopResult:
    """Run the tool-calling loop and return the final text + traces."""
    specs = mcp_manager.tool_specs()
    max_steps = max(1, max_steps or settings.max_agent_steps)

    messages: list[dict[str, Any]] = [{"role": "system", "content": build_system_prompt(session)}]
    history = session_manager.get_conversation_history(limit=20)
    for entry in history[-10:]:
        if entry.role in ("user", "assistant"):
            messages.append({"role": entry.role, "content": entry.content})
    messages.append({"role": "user", "content": user_input})

    result = LoopResult()
    for _ in range(max_steps):
        try:
            resp = await router.complete_response(
                messages,
                task_type="orchestrator",
                tools=specs,
                tool_choice="auto",
            )
        except Exception as exc:  # noqa: BLE001
            result.text = f"AI request failed: {exc}"
            return result

        if not resp.tool_calls:
            result.text = resp.content or ""
            return result

        assistant_msg: dict[str, Any] = {
            "role": "assistant",
            "content": resp.content or "",
            "tool_calls": resp.tool_calls,
        }
        messages.append(assistant_msg)

        result.tool_calls += len(resp.tool_calls)
        for call in resp.tool_calls:
            fn = call.get("function", {})
            full_name = fn.get("name", "")
            args = _parse_args(fn.get("arguments"))
            outcome = await _execute_tool(full_name, args)
            result.traces.append(outcome.trace)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id", ""),
                    "content": json.dumps(outcome.data, ensure_ascii=False, default=str),
                }
            )

    result.max_steps_hit = True
    result.text = (
        f"Reached the agent step limit ({max_steps}). Ask me to continue, raise "
        "`max_agent_steps` in the config, or run a specific skill manually."
    )
    return result


@dataclass
class _ToolOutcome:
    trace: ToolTrace
    data: dict[str, Any]


async def _execute_tool(full_name: str, args: dict[str, Any]) -> _ToolOutcome:
    described = mcp_manager.describe(full_name)
    if described is None:
        return _ToolOutcome(
            trace=ToolTrace(
                server="?", tool=full_name, arguments=args, ok=False, summary="unknown tool"
            ),
            data={"ok": False, "error": f"unknown tool: {full_name}"},
        )
    server, tool, cfg_auto_approve = described
    allowed = await permission_gate.check(server, tool, args, cfg_auto_approve)
    if not allowed:
        return _ToolOutcome(
            trace=ToolTrace(
                server=server,
                tool=tool,
                arguments=args,
                ok=False,
                summary="denied by permission gate",
            ),
            data={"ok": False, "denied": True, "tool": f"{server}.{tool}"},
        )
    ok, text = await mcp_manager.call(full_name, args)
    return _ToolOutcome(
        trace=ToolTrace(server=server, tool=tool, arguments=args, ok=ok, summary=_short(text)),
        data={"ok": ok, "tool": f"{server}.{tool}", "result": text},
    )


def _parse_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw or "{}")
        except json.JSONDecodeError:
            parsed = None
        return parsed if isinstance(parsed, dict) else {"value": raw}
    return {}


def _short(text: str, limit: int = 240) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
