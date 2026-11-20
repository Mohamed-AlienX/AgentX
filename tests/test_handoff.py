"""Tests for the /handoff cross-session report."""

from __future__ import annotations

from pathlib import Path

from agentx.core.handoff import _mask_secret, generate_handoff
from agentx.core.memory import AttackChain, Credential, Finding, MemoryManager
from agentx.core.session import HuntSession


def _setup(tmp_path: Path, monkeypatch) -> tuple[HuntSession, MemoryManager]:
    mem = MemoryManager(db_path=tmp_path / "t.db")
    sid = mem.create_session("https://example.com")
    monkeypatch.setattr("agentx.core.handoff.memory", mem)
    monkeypatch.setattr("agentx.core.session.memory", mem)

    session = HuntSession(id=sid, target="https://example.com")
    session.completed_skills.append("web2-recon")

    mem.add_finding(
        Finding(
            id="f1",
            session_id=sid,
            skill_name="hunt-idor",
            title="IDOR on /api/users",
            severity="HIGH",
            endpoint="/api/users/{id}",
            description="desc",
            impact="cross-tenant read",
            steps_to_reproduce=["step1"],
            evidence={},
            validated=True,
        )
    )
    mem.add_finding(
        Finding(
            id="f2",
            session_id=sid,
            skill_name="hunt-xss",
            title="Reflected XSS",
            severity="MEDIUM",
            endpoint="/search",
            description="desc",
            impact="session theft",
            steps_to_reproduce=["step1"],
            evidence={},
            validated=False,
        )
    )
    mem.add_credential(
        Credential(
            id="c1", session_id=sid, username="admin", secret="hunter2", cred_type="password"
        )
    )
    mem.add_chain(AttackChain(id="ch1", session_id=sid, name="XSS -> ATO", steps=[{}, {}], score=7))
    return session, mem


def test_handoff_contains_all_sections(tmp_path: Path, monkeypatch) -> None:
    session, _ = _setup(tmp_path, monkeypatch)
    report = generate_handoff(session)

    assert report.startswith("# Handoff")
    assert "https://example.com" in report
    assert "## Findings" in report
    assert "IDOR on /api/users" in report
    assert "**HIGH**" in report
    assert "## Credentials" in report
    assert "## Attack Chains" in report
    assert "XSS -> ATO" in report
    assert "## Suggested Next Steps" in report
    assert "web2-recon" in report


def test_handoff_masks_secrets(tmp_path: Path, monkeypatch) -> None:
    session, _ = _setup(tmp_path, monkeypatch)
    report = generate_handoff(session)

    assert "hunter2" not in report
    assert "hu*****" in report


def test_mask_secret_edge_cases() -> None:
    assert _mask_secret("") == "(empty)"
    assert _mask_secret("abc") == "***"
    assert _mask_secret("abcd") == "****"
    assert _mask_secret("abcdef") == "ab****"


def test_handoff_empty_session(tmp_path: Path, monkeypatch) -> None:
    mem = MemoryManager(db_path=tmp_path / "t.db")
    sid = mem.create_session("")
    monkeypatch.setattr("agentx.core.handoff.memory", mem)
    monkeypatch.setattr("agentx.core.session.memory", mem)

    report = generate_handoff(HuntSession(id=sid))
    assert "_No findings recorded yet._" in report
    assert "_No credentials captured._" in report
    assert "_No attack chains defined._" in report
    assert "Declare the target" in report
