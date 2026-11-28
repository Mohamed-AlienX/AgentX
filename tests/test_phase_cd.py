"""Phase C+D tests for executor hardening, scope/proof/trace, and report attestation."""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from agentx.core.executor import SkillExecutor
from agentx.core.handoff import FallbackHandoff
from agentx.core.intelligence import AttackVector
from agentx.core.planner import ExecutionPlan, PlanStep
from agentx.core.proof import ProofGate
from agentx.core.scope_control import ScopeGuard
from agentx.core.session import session_manager
from agentx.core.trace import AuditTrace
from agentx.reporting.generator import ReportGenerator
from agentx.skills.base import SkillContext, SkillResult


@dataclass
class DummySession:
    id: str = "s1"
    target: str = "https://example.com"
    current_phase: str = "recon"
    completed_skills: list | None = None
    active_skills: list | None = None
    findings: list | None = None

    def __post_init__(self):
        self.completed_skills = self.completed_skills or []
        self.active_skills = self.active_skills or []
        self.findings = self.findings or []

    def get_findings(self):
        return self.findings

    @property
    def context(self):
        return SkillContext(target=self.target, session_id=self.id)


@pytest.fixture(autouse=True)
def _patch_session(monkeypatch):
    sess = DummySession()
    monkeypatch.setattr(session_manager, "get_session", lambda: sess)
    monkeypatch.setattr(
        session_manager, "update_phase", lambda p: setattr(sess, "current_phase", p)
    )
    monkeypatch.setattr(session_manager, "add_active_skill", lambda s: sess.active_skills.append(s))
    monkeypatch.setattr(
        session_manager,
        "complete_skill",
        lambda s: sess.completed_skills.append(s) if s not in sess.completed_skills else None,
    )
    monkeypatch.setattr(session_manager, "add_finding", lambda f: sess.findings.append(f))
    from agentx import config as config_mod

    monkeypatch.setattr(config_mod.settings, "auto_triage", False)
    return sess


async def test_execute_plan_plan_only_skips_execution(monkeypatch, _patch_session):
    ex = SkillExecutor()
    called = []

    async def fake_exec(step, ctx):
        called.append(step.skill)
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec)
    plan = ExecutionPlan(
        analysis="a",
        steps=[PlanStep(skill="hunt-xss", description="d", reason="r")],
        selected_skills=["hunt-xss"],
        questions=[],
        estimated_time="1m",
    )
    res = await ex.execute_plan(plan, plan_only=True)
    assert res.plan_only is True
    assert res.step_results == []
    assert called == []


async def test_scope_guard_preflight_blocks_tool_invocation(monkeypatch, _patch_session):
    ex = SkillExecutor()
    called = []

    async def fake_exec(step, ctx):
        called.append(step.skill)
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec)
    guard = ScopeGuard(allowed_targets=["allowed.example"])
    plan = ExecutionPlan(
        analysis="a",
        steps=[PlanStep(skill="hunt-xss", description="d", reason="r")],
        selected_skills=["hunt-xss"],
        questions=[],
        estimated_time="1m",
    )
    res = await ex.execute_plan(plan, scope_guard=guard)
    assert res.success is False
    assert called == []
    assert any("outside allowed scope" in e for e in res.errors)


async def test_scope_guard_abort_kill_switch(monkeypatch, _patch_session):
    ex = SkillExecutor()
    called = []

    async def fake_exec(step, ctx):
        called.append(step.skill)
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec)
    guard = ScopeGuard(allowed_targets=["example.com"])
    guard.abort("kill switch")
    plan = ExecutionPlan(
        analysis="a",
        steps=[PlanStep(skill="hunt-xss", description="d", reason="r")],
        selected_skills=["hunt-xss"],
        questions=[],
        estimated_time="1m",
    )
    res = await ex.execute_plan(plan, scope_guard=guard)
    assert res.aborted is True
    assert "kill switch" in res.abort_reason
    assert called == []


async def test_proof_gate_rejects_unproven_finding_and_triggers_fallback(
    monkeypatch, _patch_session
):
    ex = SkillExecutor()

    async def fake_exec(step, ctx):
        return SkillResult(
            skill_name=step.skill,
            success=True,
            findings=[
                {
                    "title": "claim",
                    "severity": "HIGH",
                    "endpoint": "/",
                    "description": "d",
                    "impact": "i",
                    "steps_to_reproduce": ["s"],
                    "evidence": {},
                }
            ],
        )

    monkeypatch.setattr(ex, "_execute_step", fake_exec)
    vectors = [
        AttackVector(id="v1", name="v1", target_service={"service": "http", "port": 80}),
        AttackVector(id="v2", name="v2", target_service={"service": "ssh", "port": 22}),
    ]
    plan = ExecutionPlan(
        analysis="a",
        steps=[
            PlanStep(skill="v1", description="d", reason="r"),
            PlanStep(skill="v2", description="d2", reason="r2"),
        ],
        selected_skills=["v1", "v2"],
        questions=[],
        estimated_time="1m",
    )
    res = await ex.execute_plan(plan, proof_gate=ProofGate(), attack_vectors=vectors)
    assert res.total_findings == 0
    assert len(res.fallback_handoffs) >= 1
    assert "proof missing" in res.fallback_handoffs[0].failure_reason.lower()
    assert res.fallback_handoffs[0].next_vector_id == "v2"


async def test_fallback_handoff_captures_required_fields(monkeypatch, _patch_session):
    ex = SkillExecutor()

    async def fake_exec(step, ctx):
        return SkillResult(skill_name=step.skill, success=False, errors=["proof missing"])

    monkeypatch.setattr(ex, "_execute_step", fake_exec)
    vectors = [
        AttackVector(
            id="AV-1",
            cve_id="CVE-2024-0001",
            name="AV-1",
            target_service={"service": "smb", "port": 445},
        ),
        AttackVector(id="AV-2", name="AV-2", target_service={"service": "http", "port": 80}),
    ]
    plan = ExecutionPlan(
        analysis="a",
        steps=[
            PlanStep(skill="AV-1", description="d", reason="r"),
            PlanStep(skill="AV-2", description="d2", reason="r2"),
        ],
        selected_skills=["AV-1", "AV-2"],
        questions=[],
        estimated_time="1m",
    )
    res = await ex.execute_plan(plan, attack_vectors=vectors)
    fb = res.fallback_handoffs[0]
    assert isinstance(fb, FallbackHandoff)
    assert fb.attempted_vector_id == "AV-1"
    assert fb.attempted_cve == "CVE-2024-0001"
    assert "proof missing" in fb.failure_reason
    assert fb.service == "smb"
    assert fb.port == 445
    assert fb.duration_seconds >= 0
    assert fb.next_vector_id == "AV-2"


async def test_trace_is_hash_chained_and_redacts_secrets(tmp_path, monkeypatch, _patch_session):
    ex = SkillExecutor()

    async def fake_exec(step, ctx):
        return SkillResult(skill_name=step.skill, success=True)

    monkeypatch.setattr(ex, "_execute_step", fake_exec)
    trace_path = tmp_path / "audit.jsonl"
    trace = AuditTrace(trace_path)
    plan = ExecutionPlan(
        analysis="use token=secret123",
        steps=[PlanStep(skill="hunt-xss", description="d", reason="r")],
        selected_skills=["hunt-xss"],
        questions=[],
        estimated_time="1m",
    )
    await ex.execute_plan(plan, trace=trace)
    records = trace.read_all()
    assert records
    assert trace.verify() is True
    dumped = json.dumps(records)
    assert "secret123" not in dumped
    assert "[REDACTED]" in dumped


def test_report_includes_attestation_and_filters_unproven():
    gen = ReportGenerator()
    proven = {
        "id": "f1",
        "session_id": "s1",
        "skill_name": "hunt-xss",
        "title": "XSS",
        "severity": "HIGH",
        "endpoint": "/",
        "description": "d",
        "impact": "i",
        "steps_to_reproduce": ["s"],
        "evidence": {"http_response": "HTTP/1.1 200 OK"},
        "cvss_score": None,
        "validated": False,
        "validation_notes": "",
        "reported": False,
    }
    unproven = dict(proven)
    unproven["id"] = "f2"
    unproven["title"] = "Unproven"
    unproven["evidence"] = {}
    from datetime import datetime

    from agentx.core.memory import Finding

    findings = [
        Finding(**proven, timestamp=datetime.now()),
        Finding(**unproven, timestamp=datetime.now()),
    ]
    md = gen.generate(findings, target="t", session_id="s", fmt="markdown")
    assert "XSS" in md
    assert "Unproven" not in md
    assert "Methodology & Human Attestation" in md
