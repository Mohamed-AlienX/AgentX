"""Orchestrator system prompt loader."""

from __future__ import annotations

from pathlib import Path

_PROMPT_PATH = Path(__file__).parent / "orchestrator.md"

_DEFAULT_PROMPT = """
You are AgentX, an expert penetration-testing and bug-bounty orchestrator.
Analyze the user's request, select the most relevant skills, and produce an
execution plan. Always favor evidence-backed, reproducible findings.
"""


def _load() -> str:
    try:
        if _PROMPT_PATH.exists():
            return _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        pass
    return _DEFAULT_PROMPT


ORCHESTRATOR_PROMPT = _load()

__all__ = ["ORCHESTRATOR_PROMPT"]
