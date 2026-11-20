"""Scope-guard system prompt loader (adapted from pentest-ai-agents `_scope-guard.md`, MIT)."""

from __future__ import annotations

from pathlib import Path

_PROMPT_PATH = Path(__file__).parent / "scope_guard.md"

_DEFAULT_PROMPT = """
## Scope Enforcement (MANDATORY)
Before executing any command against a target, verify the declared scope,
refuse out-of-scope or destructive actions, and tag each command QUIET/MODERATE/LOUD.
"""


def _load() -> str:
    try:
        if _PROMPT_PATH.exists():
            return _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        pass
    return _DEFAULT_PROMPT


SCOPE_GUARD_PROMPT = _load()

__all__ = ["SCOPE_GUARD_PROMPT"]
