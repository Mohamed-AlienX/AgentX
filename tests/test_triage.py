"""Tests for the automated post-hunt triage gate."""

from __future__ import annotations

from agentx.core.memory import Finding
from agentx.core.triage import triage_finding, triage_findings


def _finding(**overrides) -> Finding:
    data = {
        "id": "f1",
        "session_id": "s1",
        "skill_name": "hunt-xss",
        "title": "Reflected XSS",
        "severity": "MEDIUM",
        "endpoint": "/search?q=",
        "description": "user input is reflected unescaped",
        "impact": "session theft",
        "steps_to_reproduce": ["open URL", "inject payload"],
        "evidence": {"status": 200},
    }
    data.update(overrides)
    return Finding(**data)


def test_triage_passes_complete_finding() -> None:
    ok, notes = triage_finding(_finding())
    assert ok
    assert "passed" in notes.lower()


def test_triage_rejects_missing_repro_steps() -> None:
    ok, notes = triage_finding(_finding(steps_to_reproduce=[]))
    assert not ok
    assert "steps_to_reproduce" in notes


def test_triage_rejects_theoretical_language() -> None:
    ok, notes = triage_finding(
        _finding(impact="An attacker could potentially take over the account")
    )
    assert not ok
    assert "theoretical" in notes.lower()


def test_triage_rejects_missing_required_field() -> None:
    ok, notes = triage_finding(_finding(impact=""))
    assert not ok
    assert "impact" in notes


def test_triage_findings_is_idempotent() -> None:
    findings = [
        _finding(id="a"),
        _finding(id="b", impact="could potentially leak data"),
    ]
    passed, total = triage_findings(findings, persist=False)
    assert (passed, total) == (1, 2)
    assert findings[0].validated is True
    assert findings[1].validated is False
    assert findings[0].validation_notes

    passed2, total2 = triage_findings(findings, persist=False)
    assert (passed2, total2) == (0, 0)
