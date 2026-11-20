"""Basic tests for AgentX."""

from __future__ import annotations

from pathlib import Path

from agentx.config import AgentXSettings
from agentx.core.memory import Finding, MemoryManager
from agentx.core.orchestrator import Orchestrator
from agentx.reporting.generator import ReportGenerator
from agentx.skills.registry import SkillRegistry


def test_settings_defaults() -> None:
    s = AgentXSettings()
    assert s.orchestrator_model
    assert "hunt-xss" in s.default_skills
    assert s.data_dir.is_absolute()
    assert s.auto_triage is True


def test_base_skill_create_result() -> None:
    from agentx.skills.base import HuntingSkill, SkillResult

    class _Skill(HuntingSkill):
        name = "_test"

        async def execute(self, context):  # pragma: no cover
            raise NotImplementedError

    skill = _Skill()
    result = skill._create_result("do the thing")
    assert isinstance(result, SkillResult)
    assert result.success
    assert result.skill_name == "_test"


def test_skill_discovery() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    discovered = reg.discover_skills()
    assert len(discovered) > 0
    # Categories should be inferred
    assert all("category" in meta for meta in discovered.values())


def test_skill_category_inference() -> None:
    assert SkillRegistry._infer_category("hunt-xss") == "hunting"
    assert SkillRegistry._infer_category("web2-recon") == "recon"
    assert SkillRegistry._infer_category("triage-validation") == "validation"
    assert SkillRegistry._infer_category("report-writing") == "reporting"


def test_memory_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    mem = MemoryManager(db_path=db)
    sid = mem.create_session("https://example.com")

    finding = Finding(
        id="f1",
        session_id=sid,
        skill_name="hunt-idor",
        title="IDOR",
        severity="HIGH",
        endpoint="/api/users/1",
        description="desc",
        impact="impact",
        steps_to_reproduce=["step1"],
        evidence={"status": 200},
    )
    mem.add_finding(finding)

    found = mem.get_findings_by_session(sid)
    assert len(found) == 1
    assert found[0].title == "IDOR"
    assert found[0].severity == "HIGH"


def test_report_generation(tmp_path: Path) -> None:
    gen = ReportGenerator()
    finding = Finding(
        id="f1",
        session_id="s1",
        skill_name="hunt-xss",
        title="Reflected XSS",
        severity="MEDIUM",
        endpoint="/search?q=",
        description="desc",
        impact="impact",
        steps_to_reproduce=["open", "inject"],
        evidence={},
    )
    md = gen.generate([finding], target="example.com", session_id="s1", fmt="markdown")
    assert "Reflected XSS" in md
    assert "MEDIUM" in md

    js = gen.generate([finding], target="example.com", session_id="s1", fmt="json")
    assert '"title": "Reflected XSS"' in js

    html = gen.generate([finding], target="example.com", session_id="s1", fmt="html")
    assert "<html" in html
    assert "Reflected XSS" in html


def test_target_detection() -> None:
    orch = Orchestrator()
    assert (
        orch._detect_target("scan https://foo.example.com/path") == "https://foo.example.com/path"
    )
    assert orch._detect_target("test example.com now") == "example.com"
    assert orch._detect_target("no target here") == ""


def test_intent_classification() -> None:
    orch = Orchestrator()

    class _S:
        target = "example.com"
        completed_skills: list[str] = []
        active_skills: list[str] = []
        current_phase = "recon"

    assert orch._classify_intent("status", _S()) == "status"
    assert orch._classify_intent("hunt example.com for xss", _S()) == "hunt"
    assert orch._classify_intent("make a plan", _S()) == "plan"


def test_is_confirmation() -> None:
    orch = Orchestrator()
    assert orch._is_confirmation("go")
    assert orch._is_confirmation("execute")
    assert not orch._is_confirmation("what is xss")
