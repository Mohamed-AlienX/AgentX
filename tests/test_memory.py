"""Tests for credentials + attack-chains DB additions."""

from __future__ import annotations

from pathlib import Path

from agentx.core.memory import AttackChain, Credential, MemoryManager


def _mem(tmp_path: Path) -> tuple[MemoryManager, str]:
    mem = MemoryManager(db_path=tmp_path / "t.db")
    sid = mem.create_session("https://example.com")
    return mem, sid


def test_credential_roundtrip(tmp_path: Path) -> None:
    mem, sid = _mem(tmp_path)
    cred = Credential(
        id="c1",
        session_id=sid,
        username="admin",
        secret="s3cr3t",
        cred_type="password",
        domain="corp.local",
        source="hunt-source-leak",
        host="app.example.com",
        notes="from .env",
    )
    mem.add_credential(cred)

    creds = mem.get_credentials_by_session(sid)
    assert len(creds) == 1
    assert creds[0].username == "admin"
    assert creds[0].secret == "s3cr3t"
    assert creds[0].cred_type == "password"

    mem.delete_credential("c1")
    assert mem.get_credentials_by_session(sid) == []


def test_attack_chain_roundtrip(tmp_path: Path) -> None:
    mem, sid = _mem(tmp_path)
    chain = AttackChain(
        id="ch1",
        session_id=sid,
        name="IDOR -> ATO",
        steps=[
            {"finding": "f1", "action": "leak user id"},
            {"finding": "f2", "action": "reset password"},
        ],
        score=8,
        mitre=["T1078"],
        notes="needs 2 accounts",
    )
    mem.add_chain(chain)

    chains = mem.get_chains_by_session(sid)
    assert len(chains) == 1
    assert chains[0].name == "IDOR -> ATO"
    assert len(chains[0].steps) == 2
    assert chains[0].mitre == ["T1078"]
    assert chains[0].status == "draft"

    fetched = mem.get_chain("ch1")
    assert fetched is not None
    fetched.status = "validated"
    fetched.score = 9
    mem.update_chain(fetched)

    updated = mem.get_chain("ch1")
    assert updated is not None
    assert updated.status == "validated"
    assert updated.score == 9
    assert updated.updated_at >= updated.created_at


def test_chains_scoped_per_session(tmp_path: Path) -> None:
    mem = MemoryManager(db_path=tmp_path / "t.db")
    sid1 = mem.create_session("https://a.example")
    sid2 = mem.create_session("https://b.example")
    mem.add_chain(
        AttackChain(id="x1", session_id=sid1, name="chain-a", steps=[{}]),
    )
    mem.add_credential(Credential(id="u1", session_id=sid2, username="bob"))

    assert len(mem.get_chains_by_session(sid1)) == 1
    assert mem.get_chains_by_session(sid2) == []
    assert len(mem.get_credentials_by_session(sid2)) == 1
    assert mem.get_credentials_by_session(sid1) == []
