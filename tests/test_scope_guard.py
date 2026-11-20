"""Tests for the shared scope-guard prompt block."""

from __future__ import annotations

from agentx.ai.prompts.scope_guard import SCOPE_GUARD_PROMPT
from agentx.core.agent_loop import build_system_prompt


def test_scope_guard_prompt_loaded() -> None:
    assert len(SCOPE_GUARD_PROMPT) > 500
    assert "Scope Enforcement (MANDATORY)" in SCOPE_GUARD_PROMPT
    assert "Hard Refusal List" in SCOPE_GUARD_PROMPT
    assert "OPSEC Tagging" in SCOPE_GUARD_PROMPT
    assert "QUIET" in SCOPE_GUARD_PROMPT
    assert "masscan" in SCOPE_GUARD_PROMPT


def test_scope_guard_has_no_claude_references() -> None:
    assert "Claude Code" not in SCOPE_GUARD_PROMPT
    assert "AgentX's permission gate" in SCOPE_GUARD_PROMPT


def test_build_system_prompt_includes_scope_guard() -> None:
    prompt = build_system_prompt(None)
    assert "Scope Enforcement (MANDATORY)" in prompt
    assert "Hard Refusal List" in prompt


def test_planner_and_orchestrator_prompts_wire_scope_guard() -> None:
    import agentx.core.orchestrator as orch_mod
    import agentx.core.planner as planner_mod

    assert orch_mod.SCOPE_GUARD_PROMPT == SCOPE_GUARD_PROMPT
    assert planner_mod.SCOPE_GUARD_PROMPT == SCOPE_GUARD_PROMPT


def test_scope_guard_loader_fallback(monkeypatch) -> None:
    from pathlib import Path

    import agentx.ai.prompts.scope_guard as sg

    monkeypatch.setattr(sg, "_PROMPT_PATH", Path("does/not/exist.md"))
    assert "Scope Enforcement (MANDATORY)" in sg._load()


def test_scope_guard_loader_swallows_oserror(monkeypatch) -> None:
    import agentx.ai.prompts.scope_guard as sg

    class BoomPath:
        def exists(self) -> bool:
            raise OSError("boom")

    monkeypatch.setattr(sg, "_PROMPT_PATH", BoomPath())
    assert "Scope Enforcement (MANDATORY)" in sg._load()
