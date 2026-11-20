"""Coverage tests for agentx.skills.registry and agentx.skills.base."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from agentx.ai.providers import CompletionResponse
from agentx.ai.router import router
from agentx.config import SkillConfig, settings
from agentx.skills.base import (
    SKILL_REGISTRY,
    BaseSkill,
    HuntingSkill,
    ReconSkill,
    ReportingSkill,
    SkillContext,
    SkillResult,
    ToolResult,
    ValidationSkill,
    get_all_skills,
    get_skill_class,
    register_skill,
)
from agentx.skills.registry import SkillRegistry


class _RecordingSkill(BaseSkill):
    name = "_rec-skill"
    description = "records lifecycle calls"

    def __init__(self, config: SkillConfig | None = None):
        super().__init__(config)
        self.init_called = False
        self.cleanup_called = False

    async def initialize(self) -> None:
        self.init_called = True

    async def cleanup(self) -> None:
        self.cleanup_called = True

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True, summary="rec")


class _BoomSkill(BaseSkill):
    name = "_boom-skill"
    description = "always raises on execute"

    async def execute(self, context: SkillContext) -> SkillResult:
        raise RuntimeError("boom")


class _BadCleanupSkill(BaseSkill):
    name = "_bad-cleanup"

    async def cleanup(self) -> None:
        raise RuntimeError("cleanup failed")

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True)


class _FindingSkill(BaseSkill):
    name = "_chain-findings"

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(
            skill_name=self.name,
            success=True,
            summary="one finding",
            findings=[{"title": "t", "severity": "high"}],
        )


class _RecorderSkill(BaseSkill):
    name = "_chain-recorder"
    seen_prev: int = 0

    async def execute(self, context: SkillContext) -> SkillResult:
        self.seen_prev = len(context.previous_findings)
        return SkillResult(skill_name=self.name, success=True, summary="recorded")


class _ToolSkill(BaseSkill):
    name = "_tool-skill"
    required_tools = ["nmap", "httpx"]

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True)


class _ReconImpl(ReconSkill):
    name = "_recon-impl"

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True)


class _HuntImpl(HuntingSkill):
    name = "_hunt-impl"

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True)


class _ValidImpl(ValidationSkill):
    name = "_valid-impl"

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True)


class _ReportImpl(ReportingSkill):
    name = "_report-impl"

    async def execute(self, context: SkillContext) -> SkillResult:
        return SkillResult(skill_name=self.name, success=True)


# --- registry: metadata parsing -------------------------------------------------


def test_parse_skill_metadata_without_frontmatter(tmp_path) -> None:
    skill_dir = tmp_path / "hunt-nofm"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("plain body, no frontmatter\n", encoding="utf-8")
    meta = SkillRegistry()._parse_skill_metadata(skill_dir)
    assert meta["name"] == "hunt-nofm"
    assert meta["path"] == str(skill_dir)
    assert meta["category"] == "hunting"
    assert meta["priority"] == 5
    assert meta["description"] == ""
    assert meta["version"] == "1.0.0"
    assert meta["requires_target"] is True
    assert meta["required_tools"] == []
    assert meta["required_providers"] == []


def test_parse_skill_metadata_unterminated_frontmatter(tmp_path) -> None:
    skill_dir = tmp_path / "report-unterminated"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: broken\nno closing fence", encoding="utf-8")
    meta = SkillRegistry()._parse_skill_metadata(skill_dir)
    assert meta["description"] == ""
    assert meta["category"] == "reporting"
    assert meta["priority"] == 9


def test_parse_skill_metadata_invalid_yaml(tmp_path) -> None:
    skill_dir = tmp_path / "plain-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nfoo: [1, 2\n---\nbody\n", encoding="utf-8")
    meta = SkillRegistry()._parse_skill_metadata(skill_dir)
    assert meta["description"] == ""
    assert meta["category"] == "general"
    assert meta["priority"] == 10


def test_parse_skill_metadata_frontmatter_updates(tmp_path) -> None:
    skill_dir = tmp_path / "custom-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: renamed\n"
        "description: from frontmatter\n"
        "version: 2.5.0\n"
        "category: recon\n"
        "priority: 3\n"
        "requires_target: false\n"
        "required_tools: [nmap, httpx]\n"
        "required_providers: [openai]\n"
        "---\n"
        "body\n",
        encoding="utf-8",
    )
    meta = SkillRegistry()._parse_skill_metadata(skill_dir)
    assert meta["name"] == "renamed"
    assert meta["description"] == "from frontmatter"
    assert meta["version"] == "2.5.0"
    assert meta["category"] == "recon"
    assert meta["requires_target"] is False
    assert meta["required_tools"] == ["nmap", "httpx"]
    assert meta["required_providers"] == ["openai"]
    assert meta["priority"] == 3, "explicit frontmatter priority is honored"


def test_parse_skill_metadata_reinfers_missing_category(tmp_path) -> None:
    skill_dir = tmp_path / "report-notes"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\ndescription: no category key\n---\nbody\n", encoding="utf-8"
    )
    meta = SkillRegistry()._parse_skill_metadata(skill_dir)
    assert meta["category"] == "reporting"
    assert meta["priority"] == 9


# --- registry: configs and category queries -------------------------------------


def test_config_defaults_and_enabled_lists() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    cfg = reg.get_skill_config("never-configured")
    assert cfg.enabled is True
    assert cfg.priority == 10
    assert cfg.config == {}
    assert reg.is_enabled("never-configured") is True
    enabled = reg.get_enabled_skills()
    assert enabled
    assert "hunt-xss" in enabled
    assert all(reg.is_enabled(name) for name in enabled)


def test_load_skill_configs_from_settings(monkeypatch) -> None:
    reg = SkillRegistry()
    configured = SkillConfig(name="_cfg-skill", enabled=False, priority=3)
    monkeypatch.setattr(settings, "skills", [configured])
    reg.load_skill_configs()
    assert reg._skill_configs["_cfg-skill"] is configured
    assert reg.is_enabled("_cfg-skill") is False


def test_get_skills_by_category_sorted() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg.discover_skills()
    recon = reg.get_skills_by_category("recon")
    hunting = reg.get_skills_by_category("hunting")
    assert recon
    assert hunting
    for name in recon:
        assert reg._skill_metadata[name]["category"] == "recon"
    assert recon == sorted(recon, key=lambda n: reg.get_skill_config(n).priority)
    assert reg.get_skills_by_category("no-such-category") == []


# --- registry: load_skill paths --------------------------------------------------


async def test_load_skill_registered_class_cached() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    register_skill(_RecordingSkill)
    try:
        assert get_skill_class("_rec-skill") is _RecordingSkill
        skill = await reg.load_skill("_rec-skill")
        assert isinstance(skill, _RecordingSkill)
        assert skill.init_called
        assert skill.config.name == "_rec-skill"
        assert await reg.load_skill("_rec-skill") is skill
    finally:
        SKILL_REGISTRY.pop("_rec-skill", None)


async def test_load_skill_disabled_returns_none() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg._skill_configs["_rec-skill"] = SkillConfig(name="_rec-skill", enabled=False)
    assert reg.is_enabled("_rec-skill") is False
    assert await reg.load_skill("_rec-skill") is None


async def test_load_skill_from_builtin_module(monkeypatch) -> None:
    class _FakeBuiltin(BaseSkill):
        name = "_fake_builtin"

        async def execute(self, context: SkillContext) -> SkillResult:
            return SkillResult(skill_name=self.name, success=True)

    module = types.ModuleType("agentx.skills.builtin._fake_builtin")
    module.Skill = _FakeBuiltin
    monkeypatch.setitem(sys.modules, "agentx.skills.builtin._fake_builtin", module)

    reg = SkillRegistry()
    reg.load_skill_configs()
    skill = await reg.load_skill("_fake_builtin")
    assert isinstance(skill, _FakeBuiltin)
    assert skill.config.name == "_fake_builtin"
    assert await reg.load_skill("_fake_builtin") is skill


async def test_load_skill_builtin_failure_is_swallowed(monkeypatch) -> None:
    class _Exploding(BaseSkill):
        name = "_exploding_builtin"

        def __init__(self, config: SkillConfig | None = None):
            raise RuntimeError("bad builtin skill")

        async def execute(self, context: SkillContext) -> SkillResult:
            return SkillResult(skill_name=self.name, success=True)

    module = types.ModuleType("agentx.skills.builtin._exploding_builtin")
    module.Skill = _Exploding
    monkeypatch.setitem(sys.modules, "agentx.skills.builtin._exploding_builtin", module)

    reg = SkillRegistry()
    reg.load_skill_configs()
    assert await reg.load_skill("_exploding_builtin") is None


def _make_external_skill_dir(tmp_path, name: str, module_source: str):
    skill_dir = tmp_path / name
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(f"---\nname: {name}\n---\nbody\n", encoding="utf-8")
    (skill_dir / "skill.py").write_text(module_source, encoding="utf-8")
    return skill_dir


async def test_load_external_skill_py_module(tmp_path) -> None:
    source = (
        "from agentx.skills.base import BaseSkill, SkillResult\n"
        "\n"
        "\n"
        "class TmpExtSkill(BaseSkill):\n"
        "    name = 'tmp-ext'\n"
        "\n"
        "    async def execute(self, context):\n"
        "        return SkillResult(skill_name=self.name, success=True, summary='ext')\n"
    )
    skill_dir = _make_external_skill_dir(tmp_path, "tmp-ext", source)
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg._skill_metadata["tmp-ext"] = {"name": "tmp-ext", "path": str(skill_dir)}

    skill = await reg.load_skill("tmp-ext")
    assert type(skill).__name__ == "TmpExtSkill"
    assert skill.name == "tmp-ext"
    assert skill.description == ""
    result = await skill.execute(SkillContext(target="example.com"))
    assert result.success
    assert result.summary == "ext"
    assert await reg.load_skill("tmp-ext") is skill


async def test_load_external_skill_without_class_returns_none(tmp_path) -> None:
    skill_dir = _make_external_skill_dir(tmp_path, "tmp-noclass", "X = 1\n")
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg._skill_metadata["tmp-noclass"] = {"name": "tmp-noclass", "path": str(skill_dir)}
    assert await reg.load_skill("tmp-noclass") is None


async def test_load_external_skill_exec_error_is_swallowed(tmp_path) -> None:
    skill_dir = _make_external_skill_dir(tmp_path, "tmp-bad", "raise RuntimeError('bad import')\n")
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg._skill_metadata["tmp-bad"] = {"name": "tmp-bad", "path": str(skill_dir)}
    assert await reg.load_skill("tmp-bad") is None


async def test_load_external_markdown_only_skill(tmp_path, monkeypatch) -> None:
    skill_dir = tmp_path / "md-only"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# Markdown Only\n\nstep one\n", encoding="utf-8")
    reg = SkillRegistry()
    reg.load_skill_configs()
    reg._skill_metadata["md-only"] = {
        "name": "md-only",
        "path": str(skill_dir),
        "description": "markdown only",
        "version": "2.0.0",
        "category": "recon",
        "priority": 4,
        "requires_target": False,
        "required_tools": [],
        "required_providers": ["openai"],
    }
    skill = await reg.load_skill("md-only")
    assert isinstance(skill, HuntingSkill)
    assert skill.name == "md-only"
    assert skill.description == "markdown only"
    assert skill.category == "recon"
    assert skill.priority == 4
    assert skill.requires_target is False
    assert skill.required_tools == []
    assert skill.required_providers == ["openai"]
    assert await reg.load_skill("md-only") is skill

    prompts: list[str] = []

    async def fake_call_ai(prompt, task_type=None, **kwargs):
        prompts.append(prompt)
        return "plan: run subfinder then httpx"

    monkeypatch.setattr(skill, "call_ai", fake_call_ai)
    ctx = SkillContext(target="example.com", user_input="recon now")
    first = await skill.execute(ctx)
    second = await skill.execute(ctx)
    assert first.success
    assert first.summary == "plan: run subfinder then httpx"
    assert second.summary == first.summary
    assert "# Markdown Only" in prompts[0]
    assert "example.com" in prompts[0]
    assert len(prompts) == 2


# --- registry: execute / chain / cleanup ----------------------------------------


async def test_execute_skill_dispatch_sets_context() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    register_skill(_RecordingSkill)
    try:
        ctx = SkillContext(target="example.com")
        result = await reg.execute_skill("_rec-skill", ctx)
        assert result.success
        assert result.summary == "rec"
        assert reg._loaded_skills["_rec-skill"].context is ctx
    finally:
        SKILL_REGISTRY.pop("_rec-skill", None)


async def test_execute_skill_error_paths() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    register_skill(_BoomSkill)
    try:
        ctx = SkillContext(target="example.com")
        failed = await reg.execute_skill("_boom-skill", ctx)
        assert failed.success is False
        assert failed.errors == ["Skill execution failed: boom"]
        missing = await reg.execute_skill("_no-such-skill", ctx)
        assert missing.success is False
        assert missing.errors == ["Skill '_no-such-skill' not found or not enabled"]
    finally:
        SKILL_REGISTRY.pop("_boom-skill", None)


async def test_execute_skill_chain_updates_context() -> None:
    reg = SkillRegistry()
    reg.load_skill_configs()
    register_skill(_FindingSkill)
    register_skill(_RecorderSkill)
    try:
        ctx = SkillContext(target="example.com")
        names = ["_chain-findings", "_chain-recorder", "_chain-missing"]
        results = await reg.execute_skill_chain(names, ctx)
        assert len(results) == 3
        assert results[0].success
        assert results[1].success
        assert results[2].success is False
        assert ctx.previous_findings == [{"title": "t", "severity": "high"}]
        assert ctx.state["_chain-findings_findings"] == [{"title": "t", "severity": "high"}]
        assert reg._loaded_skills["_chain-recorder"].seen_prev == 1
    finally:
        SKILL_REGISTRY.pop("_chain-findings", None)
        SKILL_REGISTRY.pop("_chain-recorder", None)


async def test_cleanup_all_swallows_errors() -> None:
    reg = SkillRegistry()
    ok = _RecordingSkill()
    bad = _BadCleanupSkill()
    reg._loaded_skills["_rec-skill"] = ok
    reg._loaded_skills["_bad-cleanup"] = bad
    await reg.cleanup_all()
    assert ok.cleanup_called
    assert reg._loaded_skills == {}


# --- registry: register_skill / get_all_skills ----------------------------------


def test_register_skill_and_lookup() -> None:
    register_skill(_RecordingSkill)
    try:
        assert get_skill_class("_rec-skill") is _RecordingSkill
        assert get_all_skills()["_rec-skill"] is _RecordingSkill
        snapshot = get_all_skills()
        snapshot.clear()
        assert get_skill_class("_rec-skill") is _RecordingSkill
    finally:
        SKILL_REGISTRY.pop("_rec-skill", None)

    class _NoName(BaseSkill):
        description = "missing name attribute"

        async def execute(self, context: SkillContext) -> SkillResult:
            return SkillResult(skill_name="", success=True)

    with pytest.raises(ValueError, match="must have a 'name'"):
        register_skill(_NoName)


# --- base: context, lifecycle, tool install --------------------------------------


def test_context_property_lazy_and_setter() -> None:
    skill = _ReconImpl()
    assert skill._context is None
    ctx = skill.context
    assert isinstance(ctx, SkillContext)
    assert skill.context is ctx
    other = SkillContext(target="example.com")
    skill.context = other
    assert skill.context is other


async def test_base_skill_execute_body_is_noop() -> None:
    class _Probe(BaseSkill):
        name = "_probe"

        async def execute(self, context: SkillContext) -> SkillResult:
            await BaseSkill.execute(self, context)
            return SkillResult(skill_name=self.name, success=True)

    result = await _Probe().execute(SkillContext())
    assert result.success


async def test_default_initialize_and_cleanup() -> None:
    skill = _ReconImpl()
    await skill.initialize()
    await skill.cleanup()


async def test_install_required_tools(monkeypatch) -> None:
    from agentx.tools import installer

    installed: list[str] = []

    async def fake_install(tool: str) -> None:
        installed.append(tool)

    monkeypatch.setattr(installer, "install_tool", fake_install)
    skill = _ToolSkill()
    await skill.initialize()
    assert installed == ["nmap", "httpx"]

    async def failing_install(tool: str) -> None:
        raise RuntimeError("install failed")

    monkeypatch.setattr(installer, "install_tool", failing_install)
    await skill.initialize()
    assert installed == ["nmap", "httpx"]


# --- base: AI helpers ------------------------------------------------------------


async def test_call_ai_builds_messages(monkeypatch) -> None:
    captured: list[list[dict[str, Any]]] = []

    async def fake_complete(messages, task_type="skill", preferred_provider=None, **kwargs):
        captured.append(list(messages))
        return CompletionResponse(content="ai says hi", model="m")

    monkeypatch.setattr(router, "complete_response", fake_complete)
    skill = _HuntImpl()
    out = await skill.call_ai("hello", system_prompt="be brief", task_type="fast")
    assert out == "ai says hi"
    out2 = await skill.call_ai("plain")
    assert out2 == "ai says hi"
    assert captured[0][0] == {"role": "system", "content": "be brief"}
    assert captured[0][1] == {"role": "user", "content": "hello"}
    assert captured[1] == [{"role": "user", "content": "plain"}]


async def test_stream_ai_yields_chunks(monkeypatch) -> None:
    async def fake_stream(messages, task_type="skill", preferred_provider=None, **kwargs):
        yield "first"
        yield "second"

    monkeypatch.setattr(router, "stream_complete", fake_stream)
    skill = _HuntImpl()
    chunks = [chunk async for chunk in skill.stream_ai("hi", system_prompt="sys")]
    assert chunks == ["first", "second"]


# --- base: result helpers, markdown, extraction ----------------------------------


def test_skill_and_tool_result_defaults() -> None:
    result = SkillResult(skill_name="s", success=False)
    assert result.findings == []
    assert result.errors == []
    assert result.metadata == {}
    assert result.next_actions == []
    assert result.summary == ""
    tool = ToolResult(tool="nmap", success=False, exit_code=2, stderr="bad args")
    assert tool.stdout == ""
    assert tool.parsed_output is None
    assert tool.duration_ms == 0


def test_create_result_empty_and_truncated() -> None:
    skill = _HuntImpl()
    empty = skill._create_result("   ")
    assert empty.success is False
    assert empty.summary == ""
    assert empty.metadata["raw_response"] == ""
    long = skill._create_result("x" * 900)
    assert long.success is True
    assert len(long.summary) == 500


def test_load_skill_markdown_paths(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "skills_dir", tmp_path)
    (tmp_path / "_md-skill").mkdir()
    (tmp_path / "_md-skill" / "SKILL.md").write_text("# My Skill\n", encoding="utf-8")
    skill = _ReconImpl()
    assert skill.load_skill_markdown("_md-skill") == "# My Skill\n"
    assert skill.load_skill_markdown() == ""
    assert skill.load_skill_markdown("_missing-skill") == ""


def test_discover_skills_includes_builtin_markdown(tmp_path, monkeypatch) -> None:
    pkg = tmp_path / "pkg"
    builtin = pkg / "builtin"
    (builtin / "extra-skill").mkdir(parents=True)
    (builtin / "extra-skill" / "SKILL.md").write_text(
        "---\nname: extra-skill\ncategory: recon\n---\nbody\n", encoding="utf-8"
    )
    monkeypatch.setattr(settings, "skills_dir", tmp_path / "user_skills")
    monkeypatch.setattr("agentx.skills.registry.__file__", str(pkg / "registry.py"))

    discovered = SkillRegistry().discover_skills()
    assert discovered["extra-skill"]["category"] == "recon"


def test_load_skill_markdown_builtin_fallback(tmp_path, monkeypatch) -> None:
    class _FakePath:
        def __init__(self, *args) -> None:
            pass

        @property
        def parent(self):
            return self

        def __truediv__(self, other):
            return self

        def exists(self) -> bool:
            return True

        def read_text(self, encoding=None) -> str:
            return "# builtin markdown\n"

    monkeypatch.setattr(settings, "skills_dir", tmp_path)
    monkeypatch.setattr("agentx.skills.base.Path", _FakePath)
    assert _ReconImpl().load_skill_markdown("_builtin-skill") == "# builtin markdown\n"


def test_extract_payloads() -> None:
    skill = _HuntImpl()
    content = (
        "## Payloads\n"
        "```bash\n"
        "curl https://x.test/' OR 1=1--\n"
        "# a comment\n"
        "\n"
        "echo done\n"
        "```\n"
        "## Other\n"
        "text\n"
    )
    assert skill.extract_payloads(content, "Payloads") == [
        "curl https://x.test/' OR 1=1--",
        "echo done",
    ]
    assert skill.extract_payloads(content, "Missing Section") == []
    assert skill.extract_payloads("## Payloads\nno code here\n", "Payloads") == []


def test_extract_tables() -> None:
    skill = _ReconImpl()
    content = (
        "## Endpoints\n"
        "| Name | Value |\n"
        "|------|-------|\n"
        "| alpha | 1 |\n"
        "| only-one-cell |\n"
        "| beta | 2 |\n"
        "\n"
        "## Next\n"
        "| A | B |\n"
        "|---|---|\n"
        "| 1 | 2 |\n"
    )
    tables = skill.extract_tables(content, "Endpoints")
    assert len(tables) == 2
    assert tables[0] == {"Name": "alpha", "Value": "1"}
    assert tables[1] == {"Name": "beta", "Value": "2"}
    assert skill.extract_tables(content, "Nope") == []


def test_create_and_validate_finding() -> None:
    skill = _ReconImpl()
    finding = skill.create_finding(
        title="SQLi",
        severity="high",
        endpoint="/api",
        description="error-based sqli",
        impact="full database read",
        steps_to_reproduce=["1", "2"],
        evidence={"status": 500},
        cvss_score=9.8,
        references=["https://cwe.mitre.org"],
    )
    assert finding["severity"] == "HIGH"
    assert finding["skill"] == "_recon-impl"
    assert finding["validated"] is False
    assert finding["cvss_score"] == 9.8
    assert skill.validate_finding(finding) is True

    bare = skill.create_finding("t", "low", "/x", "d", "i", ["s"])
    assert bare["evidence"] == {}
    assert bare["references"] == []
    assert bare["cvss_score"] is None

    missing_impact = dict(finding)
    missing_impact["impact"] = ""
    assert skill.validate_finding(missing_impact) is False

    theoretical = dict(finding)
    theoretical["impact"] = "this could potentially lead to takeover"
    assert skill.validate_finding(theoretical) is False


# --- base: concrete subclasses ---------------------------------------------------


async def test_concrete_subclass_default_helpers() -> None:
    recon, hunting = _ReconImpl(), _HuntImpl()
    validation, reporting = _ValidImpl(), _ReportImpl()
    assert await recon.discover_assets("example.com") == []
    assert await hunting.hunt("example.com", []) == []
    assert await validation.validate([{"title": "x"}]) == []
    assert await reporting.generate_report([{"title": "x"}]) == ""
    assert await reporting.generate_report([], format="json") == ""
    assert (recon.category, hunting.category) == ("recon", "hunting")
    assert (validation.category, reporting.category) == ("validation", "reporting")
    assert recon.requires_target is True
    assert recon.required_tools == []
    assert recon.required_providers == []
