"""Automated post-hunt triage gate for AgentX.

Applies a lightweight version of the 7-Question Gate to every finding produced
by a hunt, so reports can distinguish findings that at least clear the
deterministic checks (complete fields, reproduction steps, no theoretical
language) from those that do not.
"""

from __future__ import annotations

from typing import Any

from agentx.core.memory import memory

REQUIRED_FIELDS = ("title", "severity", "endpoint", "impact", "steps_to_reproduce")

THEORETICAL_PHRASES = (
    "could potentially",
    "may allow",
    "might enable",
    "theoretically",
    "in theory",
    "possible to",
    "hypothetically",
)


def _get(finding: Any, key: str) -> Any:
    if isinstance(finding, dict):
        return finding.get(key)
    return getattr(finding, key, None)


def triage_finding(finding: Any) -> tuple[bool, str]:
    """Run the automated triage gate on a single finding.

    Accepts either a ``Finding`` object or a plain dict and returns
    ``(passed, notes)``.
    """
    missing = [field for field in REQUIRED_FIELDS if not _get(finding, field)]
    if missing:
        return False, "Missing required field(s): " + ", ".join(missing)

    text = f"{_get(finding, 'description') or ''} {_get(finding, 'impact') or ''}".lower()
    for phrase in THEORETICAL_PHRASES:
        if phrase in text:
            return False, f"Theoretical language detected: '{phrase}'"

    return True, "Passed automated triage gate."


def triage_findings(findings: list[Any], *, persist: bool = True) -> tuple[int, int]:
    """Triage any findings that have not been triaged yet.

    Mutates ``Finding`` objects in place and (by default) persists the result.
    Returns ``(passed, total_triaged)``.
    """
    untriaged = [f for f in findings if not _get(f, "validation_notes")]
    passed = 0
    for finding in untriaged:
        ok, notes = triage_finding(finding)
        if not isinstance(finding, dict):
            finding.validated = ok
            finding.validation_notes = notes
            if persist:
                memory.update_finding(finding)
        passed += 1 if ok else 0
    return passed, len(untriaged)
