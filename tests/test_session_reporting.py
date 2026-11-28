"""Coverage tests for session management, report generation, and triage."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from agentx.config import settings
from agentx.core import session as session_mod
from agentx.core import triage as triage_mod
from agentx.core.memory import Finding, MemoryManager
from agentx.core.session import HuntSession, SessionManager
from agentx.core.triage import triage_finding, triage_findings
from agentx.reporting.generator import ReportGenerator


def _finding(**overrides: Any) -> Finding:
    data: dict[str, Any] = {
        "id": "f1",
        "session_id": "s1",
        "skill_name": "hunt-xss",
        "title": "Reflected XSS",
        "severity": "MEDIUM",
        "endpoint": "/search?q=",
        "description": "user input is reflected unescaped",
        "impact": "session token theft",
        "steps_to_reproduce": ["open URL", "inject payload"],
        "evidence": {
            "http_request": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
            "http_response": "HTTP/1.1 200 OK\n...<script>alert(1)</script>...",
        },
    }
    data.update(overrides)
    return Finding(**data)


def _rich_finding() -> Finding:
    return _finding(
        id="c1",
        severity="CRITICAL",
        title="RCE via upload",
        description="unrestricted file upload",
        impact="full server compromise",
        steps_to_reproduce=["upload shell", "browse to shell"],
        evidence={"command_output": "uid=0(root) gid=0(root)"},
        cvss_score=9.8,
    )


def _sparse_finding() -> Finding:
    return _finding(
        id="l1",
        severity="LOW",
        title="Missing header",
        description="",
        impact="",
        steps_to_reproduce=[],
        evidence={"http_response": "HTTP/1.1 200 OK\nX-Test: missing"},
        cvss_score=None,
    )


def _manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[SessionManager, MemoryManager]:
    mem = MemoryManager(db_path=tmp_path / "session.db")
    monkeypatch.setattr(session_mod, "memory", mem)
    return SessionManager(), mem


# ---------------------------------------------------------------------------
# agentx.core.session
# ---------------------------------------------------------------------------


def test_hunt_session_defaults_and_to_dict() -> None:
    s = HuntSession(id="abc", target="https://t.example")
    assert s.current_phase == "recon"
    d = s.to_dict()
    assert d["id"] == "abc"
    assert d["target"] == "https://t.example"
    assert d["current_phase"] == "recon"
    assert d["active_skills"] == []
    assert d["completed_skills"] == []
    assert d["metadata"] == {}
    datetime.fromisoformat(d["created_at"])
    datetime.fromisoformat(d["updated_at"])


def test_create_session_sets_current_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    s = mgr.create_session("https://app.example", {"note": "n1"})
    assert mgr.get_session() is s
    assert mgr.get_session(s.id) is s
    assert s.target == "https://app.example"
    assert s.metadata == {"note": "n1"}
    assert s.context.target == "https://app.example"
    assert s.context.session_id == s.id
    assert mem.get_session(s.id) is not None

    s2 = mgr.create_session()
    assert s2.metadata == {}
    assert mgr.get_session() is s2


def test_get_session_loads_from_db_and_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mgr, _ = _manager(tmp_path, monkeypatch)
    created = mgr.create_session("https://db.example")

    other = SessionManager()
    loaded = other.get_session(created.id)
    assert loaded is not None
    assert loaded.id == created.id
    assert loaded.target == "https://db.example"
    assert other.get_session(created.id) is loaded  # cached after first load
    assert other.get_session("missing") is None
    assert other.get_session() is None  # no current session


def test_set_current_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr, _ = _manager(tmp_path, monkeypatch)
    created = mgr.create_session("https://a.example")
    mgr.close_session()
    assert mgr.get_session() is None

    restored = mgr.set_current_session(created.id)
    assert restored is not None
    assert mgr.get_session() is restored
    assert mgr.set_current_session("nope") is None
    assert mgr.get_session() is restored  # unchanged on miss


def test_list_sessions_merges_in_memory_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    a = mgr.create_session("https://a.example")
    b = mgr.create_session("https://b.example")
    mem.create_session("https://db-only.example")  # not cached in mgr

    sessions = mgr.list_sessions()
    by_id = {s["id"]: s for s in sessions}
    assert len(by_id) == 3
    assert a.id in by_id and b.id in by_id
    assert by_id[b.id]["current_phase"] == "recon"  # merged from cache
    assert by_id[b.id]["metadata"] == {}
    assert by_id[a.id]["target"] == "https://a.example"
    db_only = next(s for s in sessions if s["target"] == "https://db-only.example")
    assert "current_phase" not in db_only


def test_update_phase_and_persist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    s = mgr.create_session("https://x.example")
    before = s.updated_at
    mgr.update_phase("hunting")
    assert s.current_phase == "hunting"
    assert s.updated_at >= before
    assert mem.get_session(s.id) is not None


def test_skill_lifecycle_on_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr, _ = _manager(tmp_path, monkeypatch)
    mgr.create_session("https://x.example")
    mgr.add_active_skill("hunt-xss")
    mgr.add_active_skill("hunt-xss")  # duplicate ignored
    sess = mgr.get_session()
    assert sess is not None
    assert sess.active_skills == ["hunt-xss"]

    mgr.complete_skill("hunt-xss")
    assert sess.active_skills == []
    assert sess.completed_skills == ["hunt-xss"]
    mgr.complete_skill("hunt-xss")  # completed dedup
    assert sess.completed_skills == ["hunt-xss"]
    mgr.complete_skill("never-added")  # not active -> still recorded once
    assert sess.completed_skills == ["hunt-xss", "never-added"]


def test_update_context_sets_attributes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr, _ = _manager(tmp_path, monkeypatch)
    mgr.create_session()
    mgr.update_context(user_input="find XSS", state={"step": 1})
    sess = mgr.get_session()
    assert sess is not None
    assert sess.context.user_input == "find XSS"
    assert sess.context.state == {"step": 1}


def test_add_and_get_findings_via_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    s = mgr.create_session("https://x.example")
    mgr.add_finding(_finding(id="fx", session_id="wrong"))
    mgr.add_finding(_finding(id="fy", session_id="wrong", severity="CRITICAL"))

    all_findings = mgr.get_findings()
    assert {f.id for f in all_findings} == {"fx", "fy"}
    assert {f.session_id for f in all_findings} == {s.id}  # session id reassigned
    assert mem.get_finding("fx") is not None
    assert mem.get_finding("fx").session_id == s.id

    crit = mgr.get_findings(severity="CRITICAL")
    assert [f.id for f in crit] == ["fy"]

    # HuntSession.get_findings reads the same store (all + by severity)
    assert {f.id for f in s.get_findings()} == {"fx", "fy"}
    assert [f.id for f in s.get_findings("CRITICAL")] == ["fy"]


def test_conversation_history_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    s = mgr.create_session("https://x.example")
    mgr.add_conversation("user", "start hunt", {"via": "test"})
    mgr.add_conversation("assistant", "ok")

    hist = mgr.get_conversation_history()
    assert [e.role for e in hist] == ["user", "assistant"]
    assert hist[0].content == "start hunt"
    assert hist[0].metadata == {"via": "test"}
    assert mem.get_stats(s.id)["total_conversations"] == 2
    assert len(mgr.get_conversation_history(limit=1)) == 1


def test_noop_guards_without_current_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    mgr.update_phase("recon")
    mgr.add_active_skill("x")
    mgr.complete_skill("x")
    mgr.update_context(user_input="y")
    mgr.add_conversation("user", "hi")
    mgr.add_finding(_finding(id="nop"))
    mgr.close_session()
    assert mgr.get_session() is None
    assert mgr.get_findings() == []
    assert mgr.get_conversation_history() == []
    assert mem.get_finding("nop") is None


def test_close_session_persists_and_allows_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mgr, mem = _manager(tmp_path, monkeypatch)
    s = mgr.create_session("https://x.example")
    mgr.close_session()
    assert mgr.get_session() is None
    assert mem.get_session(s.id) is not None
    assert mgr.get_session(s.id) is not None


# ---------------------------------------------------------------------------
# agentx.reporting.generator
# ---------------------------------------------------------------------------


def test_markdown_report_sections_order_and_details() -> None:
    gen = ReportGenerator()
    md = gen.generate(
        [_sparse_finding(), _rich_finding()],
        target="https://app.example",
        session_id="sess1",
        fmt="markdown",
        title="Custom Title",
    )
    assert md.startswith("# Custom Title")
    assert "**Target:** https://app.example" in md
    assert "**Session:** sess1" in md
    assert "**Total Findings:** 2" in md
    assert "## Summary" in md
    assert "| CRITICAL | 1 |" in md
    assert "| LOW | 1 |" in md
    assert "## Findings" in md
    # severity-sorted: CRITICAL before LOW
    assert md.index("[CRITICAL] RCE via upload") < md.index("[LOW] Missing header")
    assert "- **Endpoint:** `/search?q=`" in md
    assert "- **Skill:** hunt-xss" in md
    assert "- **CVSS:** 9.8" in md
    assert "- **Validated:** No" in md
    assert "**Evidence**" in md
    assert '"command_output"' in md
    assert "1. upload shell" in md
    # sparse finding fallbacks
    assert "_No description provided._" in md
    assert "_No impact provided._" in md
    assert "_None provided._" in md
    assert "## Methodology & Human Attestation" in md
    assert "human operator must review scope" in md


def test_markdown_empty_session_report() -> None:
    md = ReportGenerator().generate([], fmt="markdown")
    assert md.startswith("# Security Assessment Report - Target")
    assert "**Target:** N/A" in md
    assert "**Session:** N/A" in md
    assert "**Total Findings:** 0" in md
    assert "| CRITICAL | 0 |" in md
    assert "| INFO | 0 |" in md


def test_json_report_sorted_and_serializable() -> None:
    findings = [
        _sparse_finding(),
        _rich_finding(),
        _finding(id="u1", severity="WEIRD", title="Unknown severity"),
    ]
    data = json.loads(ReportGenerator().generate(findings, target="t", session_id="s", fmt="JSON"))
    assert data["target"] == "t"
    assert data["session_id"] == "s"
    assert "generated_at" in data
    assert data["summary"] == {"LOW": 1, "CRITICAL": 1, "WEIRD": 1}
    # known severities first (CRITICAL), unknown severity last
    assert [f["id"] for f in data["findings"]] == ["c1", "l1", "u1"]
    first = data["findings"][0]
    assert first["skill"] == "hunt-xss"
    assert first["cvss_score"] == 9.8
    assert first["validated"] is False
    assert first["steps_to_reproduce"] == ["upload shell", "browse to shell"]
    assert first["timestamp"]


def test_html_report_with_findings() -> None:
    html = ReportGenerator().generate(
        [_rich_finding()],
        target="app",
        session_id="s",
        fmt="html",
        title="HTML Report",
    )
    assert "<title>HTML Report</title>" in html
    assert "<h1>HTML Report</h1>" in html
    assert "<strong>Target:</strong> app" in html
    assert "<strong>Session:</strong> s" in html
    assert "<h2>Summary</h2>" in html
    assert "<td>CRITICAL</td><td>1</td>" in html
    assert "<h2>Findings</h2>" in html
    assert 'class="sev-critical"' in html
    assert "RCE via upload" in html
    assert "<code>/search?q=</code>" in html
    assert "<li>upload shell</li>" in html
    assert "Methodology &amp; Human Attestation" in html
    assert "human operator must review scope" in html


def test_html_empty_findings_branch() -> None:
    html = ReportGenerator().generate([], fmt="html")
    assert "Security Assessment Report - Target" in html
    assert "<strong>Target:</strong> N/A" in html
    assert "<p>No findings.</p>" in html


def test_unknown_format_falls_back_to_markdown() -> None:
    out = ReportGenerator().generate([], fmt="xml")
    assert out.startswith("# Security Assessment Report")


def test_save_default_and_custom_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    gen = ReportGenerator()

    p = gen.save([_rich_finding()], target="t", session_id="abc", fmt="markdown")
    assert p.parent == tmp_path / "reports"
    assert p.suffix == ".md"
    assert p.name.startswith("report_abc_")
    assert p.read_text(encoding="utf-8").startswith("# ")

    p_html = gen.save([], session_id="h1", fmt="html")
    assert p_html.suffix == ".html"

    custom = tmp_path / "out" / "r.json"
    p2 = gen.save([_rich_finding()], session_id="abc", fmt="json", output_path=custom)
    assert p2 == custom
    assert json.loads(custom.read_text(encoding="utf-8"))["session_id"] == "abc"

    # unsupported fmt -> default .md extension
    p3 = gen.save([], session_id="z", fmt="xml")
    assert p3.suffix == ".md"


# ---------------------------------------------------------------------------
# agentx.core.triage
# ---------------------------------------------------------------------------


def test_triage_finding_accepts_plain_dict() -> None:
    ok, notes = triage_finding(
        {
            "title": "SQLi",
            "severity": "HIGH",
            "endpoint": "/api",
            "impact": "full DB read",
            "steps_to_reproduce": ["send payload"],
            "description": "blind sqli confirmed",
            "evidence": {"http_response": "HTTP/1.1 200 OK\nid=1"},
        }
    )
    assert ok
    assert "passed" in notes.lower()

    bad_ok, bad_notes = triage_finding({"title": "only"})
    assert not bad_ok
    assert "severity" in bad_notes

    no_proof_ok, no_proof_notes = triage_finding(
        {
            "title": "SQLi",
            "severity": "HIGH",
            "endpoint": "/api",
            "impact": "full DB read",
            "steps_to_reproduce": ["send payload"],
            "description": "blind sqli confirmed",
        }
    )
    assert not no_proof_ok
    assert "proof missing" in no_proof_notes.lower()


def test_triage_findings_persists_validated_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mem = MemoryManager(db_path=tmp_path / "triage.db")
    monkeypatch.setattr(triage_mod, "memory", mem)
    sid = mem.create_session("https://x.example")

    ok_f = _finding(id="ok1", session_id=sid)
    bad_f = _finding(id="bad1", session_id=sid, impact="this could potentially leak data")
    mem.add_finding(ok_f)
    mem.add_finding(bad_f)

    passed, total = triage_findings([ok_f, bad_f], persist=True)
    assert (passed, total) == (1, 2)

    stored_ok = mem.get_finding("ok1")
    stored_bad = mem.get_finding("bad1")
    assert stored_ok is not None and stored_bad is not None
    assert stored_ok.validated is True
    assert stored_ok.validation_notes == "Passed automated triage gate."
    assert stored_bad.validated is False
    assert "theoretical" in stored_bad.validation_notes.lower()
    # re-running skips already-triaged findings
    assert triage_findings([ok_f, bad_f], persist=True) == (0, 0)


def test_triage_findings_dict_paths_and_skips() -> None:
    good: dict[str, Any] = {
        "title": "SQLi",
        "severity": "HIGH",
        "endpoint": "/api",
        "impact": "full DB read",
        "steps_to_reproduce": ["send payload"],
        "description": "blind sqli confirmed",
        "evidence": {"http_response": "HTTP/1.1 200 OK"},
    }
    done = {**good, "validation_notes": "already done"}
    passed, total = triage_findings([good, done], persist=True)
    assert (passed, total) == (1, 1)  # done is excluded from untriaged
    assert "validated" not in good  # dicts are counted but never mutated
    assert triage_findings([], persist=False) == (0, 0)
