"""Coverage top-up tests for remaining gaps: agent_loop, memory, planner, config,
permissions, orchestrator prompt loader, __main__, and tui entrypoint.

Only still-missing branches are covered; all tests are hermetic (tmp_path +
monkeypatch, no real network/provider).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentx.ai.prompts import orchestrator as orch_mod
from agentx.ai.providers import CompletionResponse
from agentx.ai.router import router
from agentx.config import AgentXSettings, AIProviderConfig, SkillConfig
from agentx.core.agent_loop import _execute_tool, _parse_args, _short, run_agent_loop
from agentx.core.memory import Finding, MemoryManager, memory
from agentx.core.session import HuntSession, session_manager
from agentx.mcp import mcp_manager, permission_gate

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolate_global_memory(tmp_path, monkeypatch):
    """Keep the global memory/session singletons on a private DB."""
    monkeypatch.setattr(memory, "db_path", tmp_path / "agentx.db")
    memory._init_db()
    monkeypatch.setattr(session_manager, "_current_session", None)
    monkeypatch.setattr(session_manager, "_sessions", {})


def _finding(fid: str, sid: str, severity: str = "HIGH") -> Finding:
    return Finding(
        id=fid,
        session_id=sid,
        skill_name="hunt-xss",
        title=f"finding {fid}",
        severity=severity,
        endpoint="/x",
        description="desc",
        impact="impact",
        steps_to_reproduce=[],
        evidence={},
    )


# --- agent_loop.py -----------------------------------------------------------


async def test_agent_loop_injects_history_roles(monkeypatch) -> None:
    captured: dict = {}

    async def scripted(messages, task_type=None, preferred_provider=None, **kw):
        captured["messages"] = list(messages)
        return CompletionResponse(content="done", model="m")

    monkeypatch.setattr(router, "complete_response", scripted)
    monkeypatch.setattr(mcp_manager, "tool_specs", lambda: [])

    history = [
        SimpleNamespace(role="user", content="first question"),
        SimpleNamespace(role="assistant", content="first answer"),
        SimpleNamespace(role="system", content="skip-system"),
        SimpleNamespace(role="tool", content="skip-tool"),
    ]

    class StubSessionManager:
        def get_conversation_history(self, limit: int = 100):
            return history

    monkeypatch.setattr("agentx.core.agent_loop.session_manager", StubSessionManager())

    result = await run_agent_loop("latest question", HuntSession(id="s1"))
    msgs = captured["messages"]
    contents = [m.get("content", "") for m in msgs[1:]]
    assert ("first question" in contents) and ("first answer" in contents)
    assert "skip-system" not in contents and "skip-tool" not in contents
    assert msgs[-1] == {"role": "user", "content": "latest question"}
    assert result.text == "done"


async def test_agent_loop_router_failure_returns_error(monkeypatch) -> None:
    async def boom(messages, task_type=None, preferred_provider=None, **kw):
        raise RuntimeError("provider down")

    monkeypatch.setattr(router, "complete_response", boom)
    monkeypatch.setattr(mcp_manager, "tool_specs", lambda: [])

    result = await run_agent_loop("hi", HuntSession(id="s1"))
    assert result.text == "AI request failed: provider down"
    assert result.tool_calls == 0
    assert result.traces == []


async def test_execute_tool_success_records_trace(monkeypatch) -> None:
    monkeypatch.setattr(mcp_manager, "describe", lambda name: ("fake", "echo", True))

    async def allow(server, tool, arguments=None, cfg_auto_approve=False):
        return True

    async def call(name, args):
        return True, "hello world"

    monkeypatch.setattr(permission_gate, "check", allow)
    monkeypatch.setattr(mcp_manager, "call", call)

    outcome = await _execute_tool("mcp_fake_echo", {"msg": "hi"})
    assert outcome.trace.ok is True
    assert outcome.trace.server == "fake"
    assert outcome.trace.tool == "echo"
    assert outcome.trace.summary == "hello world"
    assert outcome.data == {"ok": True, "tool": "fake.echo", "result": "hello world"}


def test_parse_args_covers_fallbacks() -> None:
    assert _parse_args({"a": 1}) == {"a": 1}
    assert _parse_args('not json {"') == {"value": 'not json {"'}
    assert _parse_args(None) == {}
    assert _parse_args([1, 2]) == {}
    assert _parse_args(42) == {}


def test_short_normalizes_and_truncates() -> None:
    assert _short("  a\n\tb  ") == "a b"
    out = _short("x" * 300)
    assert len(out) == 240
    assert out.endswith("…")


# --- memory.py ---------------------------------------------------------------


def test_memory_delete_finding(tmp_path) -> None:
    mem = MemoryManager(db_path=tmp_path / "m.db")
    sid = mem.create_session("http://t")
    mem.add_finding(_finding("f1", sid))
    assert len(mem.get_findings_by_session(sid)) == 1
    mem.delete_finding("f1")
    assert mem.get_findings_by_session(sid) == []


def test_memory_get_chain_unknown_returns_none(tmp_path) -> None:
    mem = MemoryManager(db_path=tmp_path / "m.db")
    assert mem.get_chain("does-not-exist") is None


def test_memory_get_stats_without_session(tmp_path) -> None:
    mem = MemoryManager(db_path=tmp_path / "m.db")
    sid = mem.create_session("http://t")
    mem.add_finding(_finding("f1", sid, severity="HIGH"))
    mem.add_finding(_finding("f2", sid, severity="LOW"))
    stats = mem.get_stats()
    assert stats["total_findings"] == 2
    assert stats["by_severity"] == {"HIGH": 1, "LOW": 1}
    assert stats["total_conversations"] == 0


# --- planner.py --------------------------------------------------------------


def test_planner_load_skill_descriptions_with_class(monkeypatch) -> None:
    import agentx.core.planner as planner_mod

    class FakeSkill:
        description = "fake skill desc"

    monkeypatch.setattr(planner_mod.skill_registry, "get_enabled_skills", lambda: ["fake-skill"])
    monkeypatch.setattr(planner_mod, "get_skill_class", lambda name: FakeSkill)
    t = planner_mod.TaskPlanner()
    assert t._skill_descriptions == {"fake-skill": "fake skill desc"}


async def test_suggest_next_skills_covers_all_finding_types(monkeypatch) -> None:
    import agentx.core.planner as planner_mod

    monkeypatch.setattr(planner_mod.skill_registry, "is_enabled", lambda s: True)
    t = planner_mod.TaskPlanner()
    core = ["hunt-xss", "hunt-sqli", "hunt-ssrf", "hunt-idor", "hunt-rce"]
    first = await t.suggest_next_skills(
        [{"title": "SSRF to cloud metadata"}, {"title": "SQL injection in search"}],
        completed_skills=core,
    )
    assert "hunt-cloud-misconfig" in first  # ssrf + sqli chains
    second = await t.suggest_next_skills(
        [
            {"title": "JWT auth bypass on login"},
            {"title": "Race condition on coupon redeem"},
        ],
        completed_skills=core,
    )
    assert "hunt-mfa-bypass" in second  # auth chain
    assert "hunt-business-logic" in second  # race chain


# --- config.py ---------------------------------------------------------------


def test_settings_enabled_skills_and_provider_lookup() -> None:
    s = AgentXSettings(
        skills=[
            SkillConfig(name="a", enabled=True),
            SkillConfig(name="b", enabled=False),
        ],
        ai_providers=[
            AIProviderConfig(name="openai", type="openai", model="m1", enabled=True),
            AIProviderConfig(name="ollama", type="ollama", model="m2", enabled=False),
        ],
    )
    assert [x.name for x in s.get_enabled_skills()] == ["a"]
    provider = s.get_provider("ollama")
    assert provider is not None and provider.model == "m2"
    assert s.get_provider("nope") is None


# --- mcp/permissions.py ------------------------------------------------------


def test_summarize_fallback_on_circular_args() -> None:
    from agentx.mcp.permissions import _summarize

    circular: dict = {}
    circular["self"] = circular
    out = _summarize(circular)
    assert isinstance(out, str)
    assert "{...}" in out


def test_summarize_truncates_long_args() -> None:
    from agentx.mcp.permissions import _summarize

    out = _summarize({"x": "y" * 400})
    assert len(out) == 300
    assert out.endswith("…")


# --- ai/prompts/orchestrator.py ---------------------------------------------


def test_orchestrator_prompt_loader_fallback(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(orch_mod, "_PROMPT_PATH", tmp_path / "missing.md")
    assert orch_mod._load() == orch_mod._DEFAULT_PROMPT

    class BoomPath:
        def exists(self) -> bool:
            raise OSError("disk unavailable")

    monkeypatch.setattr(orch_mod, "_PROMPT_PATH", BoomPath())
    assert orch_mod._load() == orch_mod._DEFAULT_PROMPT


# --- __main__.py -------------------------------------------------------------


def test_main_module_runs_cli_help() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "agentx", "--help"],
        capture_output=True,
        text=True,
        timeout=90,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    assert "Usage" in proc.stdout


def test_main_module_guard_invokes_app(monkeypatch) -> None:
    import runpy
    import warnings

    import agentx.cli as cli_mod

    calls: list[str] = []

    def fake_app() -> None:
        calls.append("app")

    monkeypatch.setattr(cli_mod, "app", fake_app)
    monkeypatch.setattr(sys, "argv", ["agentx", "--help"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        runpy.run_module("agentx", run_name="__main__")
    assert calls == ["app"]


# --- tui/__init__.py ---------------------------------------------------------


def test_run_tui_launches_app(monkeypatch) -> None:
    from agentx import tui

    calls: list[str] = []

    class FakeTui:
        def __init__(self) -> None:
            calls.append("init")

        def run(self) -> None:
            calls.append("run")

    monkeypatch.setattr("agentx.tui.app.AgentXTui", FakeTui)
    tui.run_tui()
    assert calls == ["init", "run"]
