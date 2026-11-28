"""Tests for executor and planner with full coverage of success/failure paths."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from agentx.ai.providers import CompletionResponse
from agentx.ai.router import router
from agentx.core.executor import ExecutionResult, SkillExecutor
from agentx.core.memory import Finding, memory
from agentx.core.planner import ExecutionPlan, PlanStep, TaskPlanner, planner
from agentx.core.session import session_manager
from agentx.skills.base import SkillContext, SkillResult


@dataclass
class DummySession:
    id: str = "s-test"
    target: str = "example.com"
    current_phase: str = "recon"
    completed_skills: list[str] | None = None
    active_skills: list[str] | None = None
    findings: list[Finding] | None = None

    def __post_init__(self):
        if self.completed_skills is None:
            self.completed_skills = []
        if self.active_skills is None:
            self.active_skills = []
        if self.findings is None:
            self.findings = []

    def get_findings(self):
        return self.findings

    @property
    def context(self) -> SkillContext:
        return SkillContext(target=self.target, session_id=self.id)


def _make_session(**kw) -> DummySession:
    return DummySession(
        id=kw.get("id", "s-test"),
        target=kw.get("target", "example.com"),
        current_phase=kw.get("current_phase", "recon"),
        completed_skills=list(kw.get("completed_skills", [])),
        active_skills=list(kw.get("active_skills", [])),
        findings=list(kw.get("findings", [])),
    )


async def _fake_complete(messages, task_type=None, preferred_provider=None, **kw) -> str:
    return """## Analysis
Test analysis

## Selected Skills
- hunt-xss: XSS testing

## Execution Plan
1. [hunt-xss] Test for XSS vulnerabilities

## Questions for User
- What scope?

## Estimated Time
10-15 min"""


async def _fake_complete_response(messages, task_type=None, preferred_provider=None, **kw):
    return CompletionResponse(content="ok", model="test-model")


# Planner tests
async def test_create_plan_parses_structure(monkeypatch):
    monkeypatch.setattr(router, "complete", _fake_complete)
    t = TaskPlanner()
    plan = await t.create_plan("test task", target="example.com")
    assert isinstance(plan, ExecutionPlan)
    assert plan.analysis
    assert plan.selected_skills == ["hunt-xss"]
    assert len(plan.steps) == 1
    assert plan.steps[0].skill == "hunt-xss"
    assert plan.questions == ["What scope?"]
    assert plan.estimated_time == "10-15 min"


async def test_create_plan_fallback_when_no_steps(monkeypatch):
    async def incomplete(messages, task_type=None, preferred_provider=None, **kw):
        return """## Analysis
Only analysis

## Selected Skills
- hunt-sqli: SQL injection
- hunt-ssrf: SSRF
"""

    monkeypatch.setattr(router, "complete", incomplete)
    t = TaskPlanner()
    plan = await t.create_plan("task")
    assert len(plan.steps) == 2
    assert plan.steps[0].skill == "hunt-sqli"
    assert plan.steps[1].skill == "hunt-ssrf"


async def test_parse_plan_handles_sections(monkeypatch):
    class Dummy:
        def __init__(self):
            self._skill_descriptions = {}

    t = TaskPlanner.__new__(TaskPlanner)
    t._skill_descriptions = {}

    response = """## Analysis
A

## Selected Skills
- a: b

## Execution Plan
1. [a] do a
2. [b] do b

## Questions for User
- q1
- q2

## Estimated Time
5 min"""
    plan = t._parse_plan(response, "t")
    assert plan.steps[0].reason == "Step 1"
    assert plan.steps[1].priority == 20


async def test_suggest_next_skills_builds_chains(monkeypatch):
    t = TaskPlanner()
    findings = [{"title": "IDOR in user endpoint"}, {"title": "XSS reflected"}]
    # patch registry
    from agentx.skills import registry as registry_mod

    monkeypatch.setattr(registry_mod.skill_registry, "is_enabled", lambda s: True)
    sugg = await t.suggest_next_skills(findings, completed_skills=["hunt-idor"])
    assert "hunt-idor" not in sugg
    assert "hunt-auth-bypass" in sugg or "hunt-session" in sugg


async def test_suggest_next_skills_empty_when_no_findings():
    t = TaskPlanner()
    sugg = await t.suggest_next_skills([], [])
    assert sugg == []


async def test_suggest_next_skills_adds_core_when_no_chains(monkeypatch):
    t = TaskPlanner()
    findings = [{"title": "weird thing"}]
    from agentx.skills import registry as registry_mod

    monkeypatch.setattr(registry_mod.skill_registry, "is_enabled", lambda s: True)
    sugg = await t.suggest_next_skills(findings, [])
    assert "hunt-xss" in sugg


# Executor tests
@pytest.fixture(autouse=True)
def _reset_singletons(monkeypatch, tmp_path):
    # reset memory/session/registry/router state minimally
    monkeypatch.setattr(memory, "db_path", tmp_path / "mem.db")
    monkeypatch.setattr(session_manager, "_current_session", None)
    yield


async def test_executor_execute_plan_no_session(monkeypatch):
    ex = SkillExecutor()
    plan = ExecutionPlan(analysis="", steps=[], selected_skills=[], questions=[], estimated_time="")
    res = await ex.execute_plan(plan)
    assert isinstance(res, ExecutionResult)
    assert res.success is False
    assert "No active session" in res.errors


async def test_executor_execute_plan_runs_steps_success(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "update_phase", lambda p: None)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    monkeypatch.setattr(session_manager, "complete_skill", lambda s: None)
    monkeypatch.setattr(session_manager, "add_finding", lambda f: None)

    async def fake_exec_step(step, ctx):
        return SkillResult(
            skill_name=step.skill,
            success=True,
            findings=[
                {
                    "title": "t",
                    "severity": "HIGH",
                    "endpoint": "/",
                    "description": "d",
                    "impact": "i",
                    "steps_to_reproduce": ["s"],
                    "evidence": {"command_output": "id"},
                }
            ],
        )

    monkeypatch.setattr(ex, "_execute_step", fake_exec_step)
    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", False)

    plan = ExecutionPlan(
        analysis="",
        steps=[PlanStep(skill="hunt-xss", description="d", reason="r")],
        selected_skills=["hunt-xss"],
        questions=[],
        estimated_time="5 min",
    )
    res = await ex.execute_plan(plan)
    assert res.success is True
    assert res.total_findings == 1
    assert ex.is_running is False


async def test_executor_execute_plan_stops_when_running_false(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "update_phase", lambda p: None)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)

    async def fake_exec_step(step, ctx):
        ex.stop()
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec_step)
    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", False)

    plan = ExecutionPlan(
        analysis="",
        steps=[
            PlanStep(skill="a", description="d", reason="r"),
            PlanStep(skill="b", description="d", reason="r"),
        ],
        selected_skills=["a", "b"],
        questions=[],
        estimated_time="",
    )
    res = await ex.execute_plan(plan)
    assert "Execution stopped by user" in res.errors


async def test_executor_step_failure_accumulates_errors(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "update_phase", lambda p: None)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", False)

    async def fake_exec_step(step, ctx):
        return SkillResult(skill_name=step.skill, success=False, errors=["boom"])

    monkeypatch.setattr(ex, "_execute_step", fake_exec_step)
    plan = ExecutionPlan(
        analysis="",
        steps=[PlanStep(skill="a", description="d", reason="r")],
        selected_skills=["a"],
        questions=[],
        estimated_time="",
    )
    res = await ex.execute_plan(plan)
    assert res.success is True  # continues, success not forced False except exception
    assert "boom" in res.errors


async def test_executor_step_exception_sets_success_false(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "update_phase", lambda p: None)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", False)

    async def fake_exec_step(step, ctx):
        raise RuntimeError("bad")

    monkeypatch.setattr(ex, "_execute_step", fake_exec_step)
    plan = ExecutionPlan(
        analysis="",
        steps=[PlanStep(skill="a", description="d", reason="r")],
        selected_skills=["a"],
        questions=[],
        estimated_time="",
    )
    res = await ex.execute_plan(plan)
    assert res.success is False
    assert any("bad" in e for e in res.errors)


async def test_executor_post_triage_runs_when_enabled(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    # add untriaged finding
    sess.findings.append(
        Finding(
            id="f1",
            session_id=sess.id,
            skill_name="hunt-xss",
            title="XSS",
            severity="MEDIUM",
            endpoint="/x",
            description="",
            impact="",
            steps_to_reproduce=["step"],
            evidence={"http_response": "HTTP/1.1 200 OK"},
        )
    )
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "update_phase", lambda p: None)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    monkeypatch.setattr(session_manager, "complete_skill", lambda s: None)

    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", True)

    # patch triage (executor imported the symbol directly)
    from agentx.core import executor as executor_mod

    def fake_triage_findings(fs):
        return (1, 1)

    monkeypatch.setattr(executor_mod, "triage_findings", fake_triage_findings)

    async def fake_exec_step(step, ctx):
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec_step)
    plan = ExecutionPlan(
        analysis="",
        steps=[PlanStep(skill="a", description="d", reason="r")],
        selected_skills=["a"],
        questions=[],
        estimated_time="",
    )
    res = await ex.execute_plan(plan)
    assert "Triage:" in res.validation_summary


async def test_executor_post_triage_skips_if_all_triaged(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    f = Finding(
        id="f1",
        session_id=sess.id,
        skill_name="hunt-xss",
        title="XSS",
        severity="MEDIUM",
        endpoint="/x",
        description="",
        impact="",
        steps_to_reproduce=[],
        evidence={},
    )
    f.validation_notes = "ok"
    sess.findings.append(f)
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "update_phase", lambda p: None)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", True)

    from agentx.core import executor as executor_mod

    called = []

    def fake_triage_findings(fs):
        called.append(True)
        return (1, 1)

    monkeypatch.setattr(executor_mod, "triage_findings", fake_triage_findings)

    async def fake_exec_step(step, ctx):
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec_step)
    plan = ExecutionPlan(analysis="", steps=[], selected_skills=[], questions=[], estimated_time="")
    await ex.execute_plan(plan)
    assert not called


async def test_execute_step_skill_disabled(monkeypatch):
    ex = SkillExecutor()
    from agentx.skills import registry as registry_mod

    monkeypatch.setattr(registry_mod.skill_registry, "is_enabled", lambda s: False)
    step = PlanStep(skill="disabled", description="d", reason="r")
    res = await ex._execute_step(step, SkillContext())
    assert res.success is False
    assert "not enabled" in res.errors[0]


async def test_execute_step_executes_skill_success(monkeypatch):
    ex = SkillExecutor()
    from agentx.skills import registry as registry_mod

    monkeypatch.setattr(registry_mod.skill_registry, "is_enabled", lambda s: True)

    async def fake_exec(skill_name, ctx):
        return SkillResult(skill_name=skill_name, success=True, summary="ok")

    monkeypatch.setattr(registry_mod.skill_registry, "execute_skill", fake_exec)
    step = PlanStep(skill="hunt-xss", description="d", reason="r")
    res = await ex._execute_step(step, SkillContext())
    assert res.success is True


async def test_execute_step_executes_skill_exception(monkeypatch):
    ex = SkillExecutor()
    from agentx.skills import registry as registry_mod

    monkeypatch.setattr(registry_mod.skill_registry, "is_enabled", lambda s: True)

    async def fake_exec(skill_name, ctx):
        raise ValueError("oops")

    monkeypatch.setattr(registry_mod.skill_registry, "execute_skill", fake_exec)
    step = PlanStep(skill="hunt-xss", description="d", reason="r")
    res = await ex._execute_step(step, SkillContext())
    assert res.success is False
    assert "Execution error" in res.errors[0]


async def test_execute_single_skill_no_session():
    ex = SkillExecutor()
    res = await ex.execute_single_skill("hunt-xss")
    assert res.success is False
    assert "No active session" in res.errors


async def test_execute_single_skill_success(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    monkeypatch.setattr(session_manager, "complete_skill", lambda s: None)
    from agentx.skills import registry as registry_mod

    async def fake_exec(skill_name, ctx):
        return SkillResult(skill_name=skill_name, success=True)

    monkeypatch.setattr(registry_mod.skill_registry, "execute_skill", fake_exec)
    res = await ex.execute_single_skill("hunt-xss")
    assert res.success is True


async def test_execute_single_skill_failure(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    from agentx.skills import registry as registry_mod

    async def fake_exec(skill_name, ctx):
        return SkillResult(skill_name=skill_name, success=False, errors=["bad"])

    monkeypatch.setattr(registry_mod.skill_registry, "execute_skill", fake_exec)
    res = await ex.execute_single_skill("hunt-xss")
    assert res.success is False


async def test_execute_single_skill_exception(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    sess.active_skills.append("hunt-xss")
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: None)
    from agentx.skills import registry as registry_mod

    async def fake_exec(skill_name, ctx):
        raise RuntimeError("x")

    monkeypatch.setattr(registry_mod.skill_registry, "execute_skill", fake_exec)
    res = await ex.execute_single_skill("hunt-xss")
    assert res.success is False
    assert "x" in res.errors[0]
    assert "hunt-xss" not in sess.active_skills


async def test_execute_skill_chain_no_session(monkeypatch):
    ex = SkillExecutor()
    res = await ex.execute_skill_chain(["a", "b"])
    assert res[0].success is False
    assert "No active session" in res[0].errors


async def test_execute_skill_chain_executes(monkeypatch):
    ex = SkillExecutor()
    sess = _make_session()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    from agentx.skills import registry as registry_mod

    async def fake_chain(skills, ctx):
        return [SkillResult(skill_name=s, success=True) for s in skills]

    monkeypatch.setattr(registry_mod.skill_registry, "execute_skill_chain", fake_chain)
    res = await ex.execute_skill_chain(["a", "b"])
    assert len(res) == 2


def test_executor_stop_and_properties():
    ex = SkillExecutor()
    assert ex.is_running is False
    ex.stop()
    assert ex.is_running is False


# Additional planner edge cases
async def test_create_plan_with_context_and_session(monkeypatch):
    monkeypatch.setattr(router, "complete", _fake_complete)
    t = TaskPlanner()
    sess = _make_session()
    sess.findings = [
        Finding(
            id="f1",
            session_id=sess.id,
            skill_name="hunt-xss",
            title="t",
            severity="LOW",
            endpoint="/",
            description="",
            impact="",
            steps_to_reproduce=[],
            evidence={},
        )
    ]
    sess.completed_skills = ["done"]
    sess.active_skills = ["active"]
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    plan = await t.create_plan("task", target="t.com", context={"k": "v"})
    assert isinstance(plan, ExecutionPlan)


def test_parse_plan_with_bullets_and_no_numbers(monkeypatch):
    t = TaskPlanner.__new__(TaskPlanner)
    t._skill_descriptions = {}
    response = """## Analysis
A

## Selected Skills
? skill1: desc1
- skill2: desc2

## Execution Plan
1. [skill1] step1
1. [skill2] step2

## Questions for User
? q1
- q2

## Estimated Time
unknown"""
    plan = t._parse_plan(response, "t")
    assert "skill1" in plan.selected_skills
    assert "skill2" in plan.selected_skills
    assert len(plan.questions) == 2


def test_parse_plan_handles_no_sections():
    t = TaskPlanner.__new__(TaskPlanner)
    t._skill_descriptions = {}
    plan = t._parse_plan("plain text", "t")
    assert plan.steps == []
    assert plan.analysis == ""


def test_planstep_and_executionplan_defaults():
    ps = PlanStep(skill="s", description="d", reason="r")
    assert ps.dependencies == []
    assert ps.estimated_time == "5-10 min"
    assert ps.priority == 10
    ep = ExecutionPlan(analysis="a", steps=[], selected_skills=[], questions=[], estimated_time="e")
    assert ep.target == ""


# Global planner instance exists and works
async def test_global_planner_instance(monkeypatch):
    monkeypatch.setattr(router, "complete", _fake_complete)
    plan = await planner.create_plan("hi")
    assert isinstance(plan, ExecutionPlan)
