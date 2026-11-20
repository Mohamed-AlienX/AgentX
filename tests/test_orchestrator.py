"""Orchestrator tests covering the non-MCP (legacy/direct) and routing paths.

Complements ``test_agent_loop.py`` (which covers the MCP-connected path) by
exercising target handling, intent classification, plan/confirm/execute,
status reporting, legacy chat, and the formatting helpers.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agentx.ai.prompts.orchestrator import ORCHESTRATOR_PROMPT
from agentx.ai.prompts.scope_guard import SCOPE_GUARD_PROMPT
from agentx.ai.providers import CompletionResponse
from agentx.ai.router import router
from agentx.core.executor import ExecutionResult, executor
from agentx.core.memory import Finding
from agentx.core.orchestrator import Orchestrator
from agentx.core.planner import ExecutionPlan, PlanStep, planner
from agentx.core.session import HuntSession, session_manager
from agentx.mcp import mcp_manager
from agentx.skills.base import SkillResult
from agentx.skills.registry import skill_registry


def _session(
    target: str = "",
    *,
    findings: list[Finding] | None = None,
    completed: list[str] | None = None,
    active: list[str] | None = None,
    phase: str = "recon",
) -> HuntSession:
    session = HuntSession(id="sess-test", target=target)
    session.current_phase = phase
    session.completed_skills = list(completed or [])
    session.active_skills = list(active or [])
    recorded = list(findings or [])

    def _get_findings(severity: str | None = None) -> list[Finding]:
        return recorded

    session.get_findings = _get_findings  # type: ignore[method-assign]
    return session


def _finding(title: str, severity: str) -> Finding:
    return Finding(
        id=f"f-{title}",
        session_id="sess-test",
        skill_name="hunt-xss",
        title=title,
        severity=severity,
        endpoint="",
        description="",
        impact="",
        steps_to_reproduce=[],
        evidence={},
    )


def _plan(
    *,
    steps: int = 1,
    analysis: str = "analysis text",
    questions: list[str] | None = None,
    skills: list[str] | None = None,
    estimated_time: str = "5-10 min",
) -> ExecutionPlan:
    step_list = [
        PlanStep(skill="hunt-xss", description=f"step {i}", reason=f"r{i}") for i in range(steps)
    ]
    return ExecutionPlan(
        analysis=analysis,
        steps=step_list,
        selected_skills=list(skills or (["hunt-xss"] if step_list else [])),
        questions=list(questions or []),
        estimated_time=estimated_time,
        target="example.com",
    )


def _result(
    plan: ExecutionPlan,
    *,
    findings: list[dict[str, Any]] | None = None,
    steps: list[SkillResult] | None = None,
    errors: list[str] | None = None,
    validation_summary: str = "",
    success: bool = True,
) -> ExecutionResult:
    new_findings = list(findings or [])
    return ExecutionResult(
        plan=plan,
        step_results=list(steps or []),
        success=success,
        errors=list(errors or []),
        total_findings=len(new_findings),
        new_findings=new_findings,
        validation_summary=validation_summary,
    )


def _async_returning(value: Any):
    async def fake(*args: Any, **kwargs: Any) -> Any:
        return value

    return fake


def _ai(content: str = "ai reply", capture: dict[str, Any] | None = None):
    async def fake(
        messages: list[dict[str, Any]],
        task_type: str | None = None,
        preferred_provider: str | None = None,
        **kw: Any,
    ) -> CompletionResponse:
        if capture is not None:
            capture["messages"] = messages
            capture["task_type"] = task_type
        return CompletionResponse(content=content, model="m", tool_calls=[])

    return fake


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch):
    """Keep every test hermetic: no skill discovery, no MCP, no DB writes."""
    monkeypatch.setattr(skill_registry, "load_skill_configs", lambda: None)
    monkeypatch.setattr(skill_registry, "discover_skills", lambda: None)
    monkeypatch.setattr(type(mcp_manager), "is_connected", property(lambda self: False))
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: None)
    monkeypatch.setattr(
        session_manager,
        "create_session",
        lambda target="", metadata=None: HuntSession(id="sess-new", target=target),
    )
    monkeypatch.setattr(session_manager, "add_conversation", lambda *a, **k: None)
    monkeypatch.setattr(session_manager, "get_conversation_history", lambda limit=100: [])
    yield


async def test_initialize_discovers_skills_once(monkeypatch: pytest.MonkeyPatch) -> None:
    log: list[str] = []
    monkeypatch.setattr(skill_registry, "load_skill_configs", lambda: log.append("load"))
    monkeypatch.setattr(skill_registry, "discover_skills", lambda: log.append("discover"))

    orch = Orchestrator()
    await orch.initialize()
    await orch.initialize()

    assert log == ["load", "discover"]
    assert orch._initialized is True


async def test_handle_message_creates_session_and_detects_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[str] = []
    session = _session()

    def fake_create(target: str = "", metadata: dict[str, Any] | None = None) -> HuntSession:
        created.append(target)
        return session

    monkeypatch.setattr(session_manager, "create_session", fake_create)
    conversations: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        session_manager,
        "add_conversation",
        lambda role, content, metadata=None: conversations.append((role, content, metadata)),
    )
    monkeypatch.setattr(router, "complete_response", _ai("hello back"))

    resp = await Orchestrator().handle_message("hello there, example.com looks interesting")

    assert created == [""]
    assert session.target == "example.com"
    assert session.context.target == "example.com"
    assert resp.kind == "chat"
    assert resp.text == "hello back"
    assert conversations[0][0] == "user"
    assert conversations[-1] == ("assistant", "hello back", {"kind": "chat"})


async def test_handle_message_sets_explicit_target(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="old.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    monkeypatch.setattr(router, "complete_response", _ai("ok"))

    resp = await Orchestrator().handle_message("hi", target="new.com")

    assert session.target == "new.com"
    assert session.context.target == "new.com"
    assert resp.kind == "chat"


async def test_handle_message_status_reports_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(
        target="example.com",
        findings=[_finding("IDOR", "HIGH"), _finding("XSS", "MEDIUM")],
        completed=["hunt-idor"],
        active=["hunt-xss"],
        phase="hunting",
    )
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)

    seen: dict[str, Any] = {}

    async def suggest(finding_dicts: list[dict[str, Any]], completed_skills: list[str]):
        seen["findings"] = finding_dicts
        seen["completed"] = completed_skills
        return ["hunt-auth-bypass"]

    monkeypatch.setattr(planner, "suggest_next_skills", suggest)

    resp = await Orchestrator().handle_message("status")

    assert resp.kind == "info"
    assert "Findings: 2 total" in resp.text
    assert "By severity: HIGH=1, MEDIUM=1" in resp.text
    assert "Completed skills: hunt-idor" in resp.text
    assert "Active skills: hunt-xss" in resp.text
    assert "Suggested next: hunt-auth-bypass" in resp.text
    assert seen["findings"] == [{"title": "IDOR"}, {"title": "XSS"}]
    assert seen["completed"] == ["hunt-idor"]


async def test_status_survives_suggestion_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)

    async def boom(finding_dicts: list[dict[str, Any]], completed_skills: list[str]):
        raise RuntimeError("planner down")

    monkeypatch.setattr(planner, "suggest_next_skills", boom)

    resp = await Orchestrator().handle_message("status")

    assert resp.kind == "info"
    assert "Findings: 0 total" in resp.text
    assert "Completed skills: none" in resp.text
    assert "Active skills: none" in resp.text
    assert "Suggested next" not in resp.text


async def test_plan_request_without_target_prompts_for_one(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)

    resp = await Orchestrator().handle_message("make a plan")

    assert resp.kind == "info"
    assert "I need a target" in resp.text


async def test_plan_pending_then_confirmed_executes(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    plan = _plan(steps=2)
    calls: list[str] = []

    async def create_plan(user_input: str, target: str = "", context=None) -> ExecutionPlan:
        calls.append(target)
        return plan

    monkeypatch.setattr(planner, "create_plan", create_plan)
    result = _result(plan, findings=[{"title": "IDOR", "severity": "HIGH"}])
    monkeypatch.setattr(executor, "execute_plan", _async_returning(result))

    orch = Orchestrator()
    first = await orch.handle_message("make a plan for xss")

    assert first.kind == "plan"
    assert first.plan is plan
    assert "# Execution Plan" in first.text
    assert "1. [hunt-xss] step 0" in first.text
    assert "2. [hunt-xss] step 1" in first.text
    assert "_Reply `go`" in first.text
    assert orch._pending_plan is plan

    second = await orch.handle_message("go")

    assert second.kind == "execution"
    assert second.plan is plan
    assert second.result is result
    assert second.findings == result.new_findings
    assert "Executing 2 step(s)... [auto-execute]" in second.text
    assert "## Execution Result" in second.text
    assert calls == ["example.com"]
    assert orch._pending_plan is None


async def test_plan_auto_execute_runs_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    plan = _plan(steps=1)
    monkeypatch.setattr(planner, "create_plan", _async_returning(plan))
    result = _result(plan)
    monkeypatch.setattr(executor, "execute_plan", _async_returning(result))

    resp = await Orchestrator(auto_execute=True).handle_message("hunt example.com")

    assert resp.kind == "execution"
    assert resp.result is result
    assert resp.plan is plan


async def test_plan_auto_execute_param_override(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    plan = _plan(steps=1)
    monkeypatch.setattr(planner, "create_plan", _async_returning(plan))
    monkeypatch.setattr(executor, "execute_plan", _async_returning(_result(plan)))

    resp = await Orchestrator().handle_message("scan example.com", auto_execute=True)

    assert resp.kind == "execution"


async def test_plan_provider_error_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)

    async def boom(user_input: str, target: str = "", context=None) -> ExecutionPlan:
        raise RuntimeError("provider offline")

    monkeypatch.setattr(planner, "create_plan", boom)

    resp = await Orchestrator().handle_message("scan example.com")

    assert resp.kind == "error"
    assert "couldn't reach an AI provider" in resp.text
    assert "provider offline" in resp.text


async def test_plan_without_steps_returns_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    plan = _plan(steps=0, analysis="No actions yet", questions=["Which scope?"])
    monkeypatch.setattr(planner, "create_plan", _async_returning(plan))

    resp = await Orchestrator().handle_message("make a plan")

    assert resp.kind == "plan"
    assert resp.plan is plan
    assert "No actions yet" in resp.text
    assert "Questions:" in resp.text
    assert "- Which scope?" in resp.text


async def test_plan_without_steps_or_analysis_uses_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    monkeypatch.setattr(planner, "create_plan", _async_returning(_plan(steps=0, analysis="")))

    resp = await Orchestrator().handle_message("make a plan")

    assert resp.kind == "plan"
    assert "I couldn't derive an execution plan from that request." in resp.text


async def test_question_intent_uses_legacy_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="example.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    capture: dict[str, Any] = {}
    monkeypatch.setattr(router, "complete_response", _ai("xss is...", capture))

    resp = await Orchestrator().handle_message("what is xss?")

    assert resp.kind == "chat"
    assert resp.text == "xss is..."
    assert capture["task_type"] == "orchestrator"


async def test_chat_builds_system_and_context_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(
        target="t.com",
        completed=["hunt-xss"],
        findings=[_finding("X", "LOW")],
        phase="hunting",
    )
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)
    history = [
        SimpleNamespace(role="user", content="older question"),
        SimpleNamespace(role="tool", content="tool output"),
        SimpleNamespace(role="assistant", content="older answer"),
    ]
    monkeypatch.setattr(session_manager, "get_conversation_history", lambda limit=100: history)
    capture: dict[str, Any] = {}
    monkeypatch.setattr(router, "complete_response", _ai("sure", capture))

    resp = await Orchestrator().handle_message("hello there")

    messages = capture["messages"]
    expected_system = ORCHESTRATOR_PROMPT + "\n" + SCOPE_GUARD_PROMPT
    assert messages[0] == {"role": "system", "content": expected_system}
    assert {"role": "user", "content": "older question"} in messages
    assert {"role": "assistant", "content": "older answer"} in messages
    assert all(m["content"] != "tool output" for m in messages)
    last = messages[-1]
    assert last["role"] == "user"
    assert last["content"].startswith("hello there")
    assert "target=t.com" in last["content"]
    assert "phase=hunting" in last["content"]
    assert "findings=1" in last["content"]
    assert "completed_skills=['hunt-xss']" in last["content"]
    assert resp.text == "sure"


async def test_chat_provider_failure_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(target="t.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)

    async def boom(
        messages: list[dict[str, Any]],
        task_type: str | None = None,
        preferred_provider: str | None = None,
        **kw: Any,
    ) -> CompletionResponse:
        raise RuntimeError("no providers")

    monkeypatch.setattr(router, "complete_response", boom)

    resp = await Orchestrator().handle_message("hello")

    assert resp.kind == "error"
    assert resp.text == "AI request failed: no providers"


async def test_chat_uses_agent_loop_when_mcp_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(type(mcp_manager), "is_connected", property(lambda self: True))
    session = _session(target="t.com")
    monkeypatch.setattr(session_manager, "get_session", lambda *a, **k: session)

    loops: list[tuple[str, HuntSession]] = []

    class _Loop:
        def __init__(self) -> None:
            self.text = "loop answer"
            self.traces = [SimpleNamespace(server="burp", tool="scan", ok=True)]

    async def fake_loop(user_input: str, sess: HuntSession, max_steps: int | None = None) -> _Loop:
        loops.append((user_input, sess))
        return _Loop()

    monkeypatch.setattr("agentx.core.agent_loop.run_agent_loop", fake_loop)

    resp = await Orchestrator().handle_message("hello")

    assert loops == [("hello", session)]
    assert resp.kind == "chat"
    assert resp.text == "loop answer"
    assert resp.tool_traces == _Loop().traces


def test_classify_intent_question_variants() -> None:
    orch = Orchestrator()
    session = _session()

    assert orch._classify_intent("how do i start", session) == "question"
    assert orch._classify_intent("this works? maybe", session) == "question"
    assert orch._classify_intent("scan example.com now", session) == "hunt"
    assert orch._classify_intent("tell me about xss defenses", session) == "chat"
    assert orch._classify_intent("status " + "x" * 50, session) == "chat"


def test_detect_target_url_branch() -> None:
    orch = Orchestrator()
    assert orch._detect_target("go to https://a.example.com/path?q=1 now") == (
        "https://a.example.com/path?q=1"
    )


def test_format_plan_includes_all_sections() -> None:
    plan = _plan(
        steps=2,
        analysis="Look for XSS",
        questions=["Any auth?"],
        skills=["hunt-xss", "hunt-sqli"],
        estimated_time="30 min",
    )

    out = Orchestrator()._format_plan(plan)

    assert "# Execution Plan" in out
    assert "Look for XSS" in out
    assert "## Skills" in out
    assert "hunt-xss, hunt-sqli" in out
    assert "## Steps" in out
    assert "1. [hunt-xss] step 0" in out
    assert "## Questions" in out
    assert "- Any auth?" in out
    assert "Estimated time: 30 min" in out


def test_format_plan_minimal() -> None:
    plan = ExecutionPlan(
        analysis="",
        steps=[],
        selected_skills=[],
        questions=[],
        estimated_time="",
    )

    assert Orchestrator()._format_plan(plan) == "# Execution Plan"


def test_format_result_full() -> None:
    plan = _plan(steps=1)
    steps = [
        SkillResult(skill_name="hunt-xss", success=True, summary="done"),
        SkillResult(skill_name="hunt-sqli", success=False, summary="failed"),
    ]
    result = _result(
        plan,
        findings=[{}, {}, {}],
        steps=steps,
        errors=["step failed"],
        validation_summary="Triage: 2/3 finding(s) passed the automated gate.",
        success=False,
    )

    out = Orchestrator()._format_result(result)

    assert "## Execution Result" in out
    assert "Success: False" in out
    assert "Steps run: 2" in out
    assert "Findings: 3" in out
    assert "Triage: 2/3 finding(s) passed the automated gate." in out
    assert "Errors:" in out
    assert "- step failed" in out
    assert "[OK] hunt-xss: done" in out
    assert "[FAIL] hunt-sqli: failed" in out


def test_format_result_minimal() -> None:
    out = Orchestrator()._format_result(ExecutionResult(plan=_plan(steps=0)))

    assert "Success: True" in out
    assert "Steps run: 0" in out
    assert "Findings: 0" in out
    assert "Errors:" not in out
    assert "Triage" not in out


def test_execution_start_message() -> None:
    assert (
        Orchestrator()._execution_start(_plan(steps=3)) == "Executing 3 step(s)... [auto-execute]"
    )
