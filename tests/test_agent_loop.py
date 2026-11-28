"""Agent loop (plan->act->observe) tests with a scripted router."""

from __future__ import annotations

import json

from agentx.ai.providers import CompletionResponse
from agentx.ai.router import router
from agentx.core.agent_loop import (
    TOOL_GUIDE,
    ToolTrace,
    _ToolOutcome,
    build_system_prompt,
    run_agent_loop,
)
from agentx.core.memory import memory
from agentx.core.orchestrator import Orchestrator
from agentx.core.session import session_manager
from agentx.mcp import mcp_manager, permission_gate

TOOL_CALL = {
    "id": "c1",
    "type": "function",
    "function": {"name": "mcp_fake_echo", "arguments": json.dumps({"msg": "hi"})},
}

SPEC = {
    "type": "function",
    "function": {"name": "mcp_fake_echo", "description": "echo", "parameters": {"type": "object"}},
}


def _session() -> object:
    return session_manager.get_session() or session_manager.create_session("")


async def _fake_execute(full_name, args):
    return _ToolOutcome(
        trace=ToolTrace(server="fake", tool="echo", arguments=args, ok=True, summary="echo:hi"),
        data={"ok": True, "result": "echo:hi"},
    )


async def test_agent_loop_calls_tools_then_answers(monkeypatch) -> None:
    class Scripted:
        def __init__(self, responses):
            self._q = list(responses)

        async def __call__(self, messages, task_type=None, preferred_provider=None, **kw):
            return self._q.pop(0)

    scripted = Scripted(
        [
            CompletionResponse(content="", model="m", tool_calls=[TOOL_CALL]),
            CompletionResponse(content="all done", model="m"),
        ]
    )
    monkeypatch.setattr(router, "complete_response", scripted)
    monkeypatch.setattr(mcp_manager, "tool_specs", lambda: [SPEC])
    monkeypatch.setattr("agentx.core.agent_loop._execute_tool", _fake_execute)

    result = await run_agent_loop("echo hi", _session())
    assert result.tool_calls == 1
    assert result.text == "all done"
    assert len(result.traces) == 1
    assert result.traces[0].server == "fake"
    assert result.traces[0].tool == "echo"
    assert not result.max_steps_hit


async def test_agent_loop_plain_answer_without_tools(monkeypatch) -> None:
    async def scripted(messages, task_type=None, preferred_provider=None, **kw):
        return CompletionResponse(content="just text", model="m")

    monkeypatch.setattr(router, "complete_response", scripted)
    monkeypatch.setattr(mcp_manager, "tool_specs", lambda: [])

    result = await run_agent_loop("hi", _session())
    assert result.text == "just text"
    assert result.tool_calls == 0
    assert result.traces == []


async def test_agent_loop_stops_at_step_limit(monkeypatch) -> None:
    async def infinite(messages, task_type=None, preferred_provider=None, **kw):
        return CompletionResponse(content="", model="m", tool_calls=[TOOL_CALL])

    monkeypatch.setattr(router, "complete_response", infinite)
    monkeypatch.setattr(mcp_manager, "tool_specs", lambda: [SPEC])
    monkeypatch.setattr("agentx.core.agent_loop._execute_tool", _fake_execute)

    result = await run_agent_loop("loop", _session(), max_steps=2)
    assert result.max_steps_hit
    assert result.tool_calls == 2
    assert "limit" in result.text


async def test_execute_tool_denied_by_gate(monkeypatch) -> None:
    monkeypatch.setattr(mcp_manager, "describe", lambda name: ("burp", "send_http_request", False))

    async def deny(server, tool, arguments=None, cfg_auto_approve=False):
        return False

    monkeypatch.setattr(permission_gate, "check", deny)

    from agentx.core.agent_loop import _execute_tool

    outcome = await _execute_tool("mcp_burp_send_http_request", {"url": "http://x"})
    assert outcome.trace.ok is False
    assert outcome.trace.summary == "denied by permission gate"
    assert outcome.data["denied"] is True


async def test_execute_tool_unknown(monkeypatch) -> None:
    monkeypatch.setattr(mcp_manager, "describe", lambda name: None)
    from agentx.core.agent_loop import _execute_tool

    outcome = await _execute_tool("mcp_nope", {})
    assert outcome.trace.ok is False
    assert "unknown tool" in outcome.data["error"]


async def test_orchestrator_routes_to_agent_loop_when_connected(monkeypatch) -> None:
    monkeypatch.setattr(type(mcp_manager), "is_connected", property(lambda self: True))

    class _Loopish:
        def __init__(self) -> None:
            self.text = "from loop"
            self.tool_calls = 1
            self.traces = [ToolTrace(server="s", tool="t", arguments={}, ok=True, summary="ok")]
            self.max_steps_hit = False

    async def _loop_return(user_input, session, max_steps=None) -> _Loopish:
        _loop_return.called = True
        return _Loopish()

    monkeypatch.setattr("agentx.core.agent_loop.run_agent_loop", _loop_return)

    session = session_manager.get_session()
    if session:
        memory.clear_conversation(session.id)
    orch = Orchestrator()
    resp = await orch.handle_message("hello", target="example.com")
    assert _loop_return.called
    assert resp.text == "from loop"
    assert len(resp.tool_traces) == 1
    assert resp.tool_traces[0].server == "s"


async def test_agent_loop_tool_guide_is_command_first() -> None:
    assert "COMMAND FIRST" in TOOL_GUIDE
    prompt = build_system_prompt()
    assert "command-first" in prompt.lower()
    assert "reproducible evidence" in prompt.lower()
