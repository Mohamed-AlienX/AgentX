"""Memory management for AgentX - conversation history and findings storage."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from agentx.config import settings


@dataclass
class ConversationEntry:
    """Single conversation entry."""

    id: str
    session_id: str
    role: str  # user, assistant, system, tool
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Finding:
    """Vulnerability finding."""

    id: str
    session_id: str
    skill_name: str
    title: str
    severity: str
    endpoint: str
    description: str
    impact: str
    steps_to_reproduce: list[str]
    evidence: dict[str, Any]
    cvss_score: float | None = None
    validated: bool = False
    validation_notes: str = ""
    reported: bool = False
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Credential:
    """Discovered credential."""

    id: str
    session_id: str
    username: str = ""
    secret: str = ""
    cred_type: str = ""  # password, hash, token, key, cookie, session
    domain: str = ""
    source: str = ""
    host: str = ""
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackChain:
    """Multi-step attack chain linking findings toward an objective."""

    id: str
    session_id: str
    name: str
    steps: list[dict[str, Any]]
    score: int = 0
    mitre: list[str] = field(default_factory=list)
    status: str = "draft"  # draft, validated, blocked
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class MemoryManager:
    """Manages conversation history and findings persistence."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or settings.data_dir / "agentx.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    description TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    steps_to_reproduce TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    cvss_score REAL,
                    validated INTEGER DEFAULT 0,
                    validation_notes TEXT,
                    reported INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    username TEXT,
                    secret TEXT,
                    cred_type TEXT,
                    domain TEXT,
                    source TEXT,
                    host TEXT,
                    notes TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chains (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    mitre TEXT,
                    status TEXT DEFAULT 'draft',
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_conversations_session ON conversations(session_id);
                CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
                CREATE INDEX IF NOT EXISTS idx_chains_session ON chains(session_id);
            """)

    @contextmanager
    def _get_conn(self):
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # Session management
    def create_session(self, target: str = "", metadata: dict[str, Any] | None = None) -> str:
        """Create a new hunting session."""
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()

        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO sessions (id, target, created_at, updated_at, metadata) VALUES (?, ?, ?, ?, ?)",
                (session_id, target, now, now, json.dumps(metadata or {})),
            )

        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session by ID."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if row:
                return dict(row)
        return None

    def update_session(self, session_id: str, metadata: dict[str, Any]) -> None:
        """Update session metadata."""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE sessions SET updated_at = ?, metadata = ? WHERE id = ?",
                (datetime.now().isoformat(), json.dumps(metadata), session_id),
            )

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent sessions."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    # Conversation management
    def add_conversation(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> ConversationEntry:
        """Add a conversation entry."""
        entry = ConversationEntry(
            id=str(uuid.uuid4()),
            session_id=session_id,
            role=role,
            content=content,
            metadata=metadata or {},
        )

        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO conversations (id, session_id, role, content, metadata, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.id,
                    entry.session_id,
                    entry.role,
                    entry.content,
                    json.dumps(entry.metadata),
                    entry.timestamp.isoformat(),
                ),
            )

        return entry

    def get_conversation_history(
        self,
        session_id: str,
        limit: int = 100,
    ) -> list[ConversationEntry]:
        """Get conversation history for a session."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM conversations WHERE session_id = ? ORDER BY timestamp ASC LIMIT ?",
                (session_id, limit),
            ).fetchall()

        return [
            ConversationEntry(
                id=row["id"],
                session_id=row["session_id"],
                role=row["role"],
                content=row["content"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                timestamp=datetime.fromisoformat(row["timestamp"]),
            )
            for row in rows
        ]

    def clear_conversation(self, session_id: str) -> None:
        """Clear conversation history for a session."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM conversations WHERE session_id = ?", (session_id,))

    # Findings management
    def add_finding(self, finding: Finding) -> Finding:
        """Add a finding."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO findings
                (id, session_id, skill_name, title, severity, endpoint, description,
                 impact, steps_to_reproduce, evidence, cvss_score, validated,
                 validation_notes, reported, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id,
                    finding.session_id,
                    finding.skill_name,
                    finding.title,
                    finding.severity,
                    finding.endpoint,
                    finding.description,
                    finding.impact,
                    json.dumps(finding.steps_to_reproduce),
                    json.dumps(finding.evidence),
                    finding.cvss_score,
                    1 if finding.validated else 0,
                    finding.validation_notes,
                    1 if finding.reported else 0,
                    finding.timestamp.isoformat(),
                ),
            )
        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        """Get finding by ID."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row:
                return self._row_to_finding(row)
        return None

    def get_findings_by_session(self, session_id: str) -> list[Finding]:
        """Get all findings for a session."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY timestamp DESC",
                (session_id,),
            ).fetchall()
            return [self._row_to_finding(row) for row in rows]

    def get_findings_by_severity(self, session_id: str, severity: str) -> list[Finding]:
        """Get findings by severity for a session."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? AND severity = ? ORDER BY timestamp DESC",
                (session_id, severity.upper()),
            ).fetchall()
            return [self._row_to_finding(row) for row in rows]

    def update_finding(self, finding: Finding) -> None:
        """Update a finding."""
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE findings SET
                title = ?, severity = ?, endpoint = ?, description = ?, impact = ?,
                steps_to_reproduce = ?, evidence = ?, cvss_score = ?, validated = ?,
                validation_notes = ?, reported = ?
                WHERE id = ?""",
                (
                    finding.title,
                    finding.severity,
                    finding.endpoint,
                    finding.description,
                    finding.impact,
                    json.dumps(finding.steps_to_reproduce),
                    json.dumps(finding.evidence),
                    finding.cvss_score,
                    1 if finding.validated else 0,
                    finding.validation_notes,
                    1 if finding.reported else 0,
                    finding.id,
                ),
            )

    def delete_finding(self, finding_id: str) -> None:
        """Delete a finding."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        """Convert database row to Finding object."""
        return Finding(
            id=row["id"],
            session_id=row["session_id"],
            skill_name=row["skill_name"],
            title=row["title"],
            severity=row["severity"],
            endpoint=row["endpoint"],
            description=row["description"],
            impact=row["impact"],
            steps_to_reproduce=json.loads(row["steps_to_reproduce"]),
            evidence=json.loads(row["evidence"]),
            cvss_score=row["cvss_score"],
            validated=bool(row["validated"]),
            validation_notes=row["validation_notes"] or "",
            reported=bool(row["reported"]),
            timestamp=datetime.fromisoformat(row["timestamp"]),
        )

    # Credentials management
    def add_credential(self, credential: Credential) -> Credential:
        """Add a discovered credential."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO credentials
                (id, session_id, username, secret, cred_type, domain, source, host, notes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    credential.id,
                    credential.session_id,
                    credential.username,
                    credential.secret,
                    credential.cred_type,
                    credential.domain,
                    credential.source,
                    credential.host,
                    credential.notes,
                    credential.timestamp.isoformat(),
                ),
            )
        return credential

    def get_credentials_by_session(self, session_id: str) -> list[Credential]:
        """Get all credentials for a session."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM credentials WHERE session_id = ? ORDER BY timestamp DESC",
                (session_id,),
            ).fetchall()
            return [
                Credential(
                    id=row["id"],
                    session_id=row["session_id"],
                    username=row["username"] or "",
                    secret=row["secret"] or "",
                    cred_type=row["cred_type"] or "",
                    domain=row["domain"] or "",
                    source=row["source"] or "",
                    host=row["host"] or "",
                    notes=row["notes"] or "",
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                )
                for row in rows
            ]

    def delete_credential(self, credential_id: str) -> None:
        """Delete a credential."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))

    # Attack chains management
    def add_chain(self, chain: AttackChain) -> AttackChain:
        """Add an attack chain."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO chains
                (id, session_id, name, steps, score, mitre, status, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    chain.id,
                    chain.session_id,
                    chain.name,
                    json.dumps(chain.steps),
                    chain.score,
                    json.dumps(chain.mitre),
                    chain.status,
                    chain.notes,
                    chain.created_at.isoformat(),
                    chain.updated_at.isoformat(),
                ),
            )
        return chain

    def get_chains_by_session(self, session_id: str) -> list[AttackChain]:
        """Get all attack chains for a session."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM chains WHERE session_id = ? ORDER BY updated_at DESC",
                (session_id,),
            ).fetchall()
            return [self._row_to_chain(row) for row in rows]

    def get_chain(self, chain_id: str) -> AttackChain | None:
        """Get chain by ID."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM chains WHERE id = ?", (chain_id,)).fetchone()
            if row:
                return self._row_to_chain(row)
        return None

    def update_chain(self, chain: AttackChain) -> None:
        """Update an attack chain."""
        chain.updated_at = datetime.now()
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE chains SET
                name = ?, steps = ?, score = ?, mitre = ?, status = ?, notes = ?, updated_at = ?
                WHERE id = ?""",
                (
                    chain.name,
                    json.dumps(chain.steps),
                    chain.score,
                    json.dumps(chain.mitre),
                    chain.status,
                    chain.notes,
                    chain.updated_at.isoformat(),
                    chain.id,
                ),
            )

    def _row_to_chain(self, row: sqlite3.Row) -> AttackChain:
        """Convert database row to AttackChain object."""
        return AttackChain(
            id=row["id"],
            session_id=row["session_id"],
            name=row["name"],
            steps=json.loads(row["steps"]),
            score=row["score"] or 0,
            mitre=json.loads(row["mitre"]) if row["mitre"] else [],
            status=row["status"] or "draft",
            notes=row["notes"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # Statistics
    def get_stats(self, session_id: str | None = None) -> dict[str, Any]:
        """Get statistics."""
        with self._get_conn() as conn:
            if session_id:
                findings = conn.execute(
                    "SELECT severity, COUNT(*) as count FROM findings WHERE session_id = ? GROUP BY severity",
                    (session_id,),
                ).fetchall()
                total_findings = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE session_id = ?", (session_id,)
                ).fetchone()[0]
                total_conversations = conn.execute(
                    "SELECT COUNT(*) FROM conversations WHERE session_id = ?", (session_id,)
                ).fetchone()[0]
            else:
                findings = conn.execute(
                    "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
                ).fetchall()
                total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                total_conversations = conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[
                    0
                ]

        severity_counts = {row["severity"]: row["count"] for row in findings}

        return {
            "total_findings": total_findings,
            "total_conversations": total_conversations,
            "by_severity": severity_counts,
        }


# Global memory manager
memory = MemoryManager()
