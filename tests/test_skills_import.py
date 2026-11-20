"""Tests for skills imported from pentest-ai-agents (MIT)."""

from __future__ import annotations

from pathlib import Path

from agentx.config import AgentXSettings
from agentx.skills.registry import SkillRegistry

IMPORTED = [
    # A — web/bug-bounty core
    "llm-redteam",
    "ai-recon",
    "poc-validator",
    "fix-verifier",
    "report-generator",
    "exploit-chainer",
    "attack-planner",
    "code-auditor",
    "vuln-scanner",
    "database-attacker",
    "credential-tester",
    "crypto-analyzer",
    "supply-chain-auditor",
    "ctf-solver",
    "password-auditor",
    # B — infrastructure / post-exploitation
    "ad-attacker",
    "privesc-advisor",
    "lateral-movement",
    "c2-operator",
    "container-breakout",
    "persistence-planner",
    "evasion-specialist",
    "data-exfiltrator",
    "payload-crafter",
    "reverse-engineer",
    "network-attacker",
    "wireless-pentester",
    "mobile-pentester",
    "traffic-analyzer",
    "social-engineer",
    "phishing-operator",
    "threat-modeler",
    "engagement-planner",
    "opsec-anonymizer",
    "swarm-orchestrator",
    "exploit-guide",
    "detection-engineer",
]


def test_all_imported_skills_discovered() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    discovered = reg.discover_skills()
    assert len(discovered) >= 68, f"expected >=68 skills, got {len(discovered)}"
    for name in IMPORTED:
        assert name in discovered, f"{name} not discovered"
        meta = discovered[name]
        assert meta.get("description"), f"{name} has empty description"
        assert meta.get("category"), f"{name} has no category"


def test_default_skills_all_discoverable() -> None:
    s = AgentXSettings()
    reg = SkillRegistry()
    reg.load_skill_configs()
    discovered = reg.discover_skills()
    missing = [n for n in s.default_skills if n not in discovered]
    assert not missing, f"default_skills missing from discovery: {missing}"
    assert len(s.default_skills) >= 70


def test_imported_frontmatter_categories() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    discovered = reg.discover_skills()
    assert discovered["ad-attacker"]["category"] == "post-exploitation"
    assert discovered["wireless-pentester"]["category"] == "infrastructure"
    assert discovered["ai-recon"]["category"] == "recon"
    assert discovered["poc-validator"]["category"] == "validation"
    assert discovered["report-generator"]["category"] == "reporting"
    assert discovered["threat-modeler"]["category"] == "methodology"
    assert discovered["ad-attacker"]["priority"] == 7
    assert discovered["wireless-pentester"]["priority"] == 7


def test_new_category_inference() -> None:
    assert SkillRegistry._infer_category("ad-attacker") == "post-exploitation"
    assert SkillRegistry._infer_category("privesc-advisor") == "post-exploitation"
    assert SkillRegistry._infer_category("network-attacker") == "infrastructure"
    assert SkillRegistry._infer_category("phishing-operator") == "infrastructure"
    assert SkillRegistry._infer_priority("post-exploitation") == 7
    assert SkillRegistry._infer_priority("infrastructure") == 7


def test_imported_skill_files_hygiene() -> None:
    skills_dir = Path("skills")
    for name in IMPORTED:
        path = skills_dir / name / "SKILL.md"
        assert path.exists(), f"missing {path}"
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{name} missing frontmatter"
        assert "Claude Code" not in text, f"{name} still references Claude Code"
        frontmatter = text[: text.index("---", 3)]
        assert "pentest-ai-agents" in frontmatter, f"{name} missing MIT attribution"


async def test_imported_skill_loads_as_dynamic_skill() -> None:
    """The markdown-only load path every imported skill goes through."""
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg.discover_skills()

    skill = await reg.load_skill("ad-attacker")
    assert skill is not None
    assert skill.name == "ad-attacker"
    assert skill.description
    assert skill.category == "post-exploitation"

    assert await reg.load_skill("not-a-real-skill") is None


async def test_dynamic_skill_execute_builds_prompt(monkeypatch) -> None:
    """DynamicSkill.execute must read SKILL.md and produce an AI plan."""
    from agentx.skills.base import SkillContext

    reg = SkillRegistry()
    reg.load_skill_configs()
    reg.discover_skills()

    skill = await reg.load_skill("llm-redteam")
    assert skill is not None

    async def fake_call_ai(prompt, task_type=None, **kw):
        assert "llm-redteam" in prompt
        assert "prompt injection" in prompt.lower() or "Markdown Documentation" in prompt
        return "next actions: map the AI surface, then test direct injection"

    monkeypatch.setattr(skill, "call_ai", fake_call_ai)
    ctx = SkillContext(target="example.com", user_input="test chatbot")
    result = await skill.execute(ctx)
    assert result.success
    assert result.skill_name == "llm-redteam"
    assert result.summary
