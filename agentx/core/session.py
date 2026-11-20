"""Session management for AgentX."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agentx.core.memory import Finding, memory
from agentx.skills.base import SkillContext


@dataclass
class HuntSession:
    """Active hunting session."""

    id: str
    target: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)
    current_phase: str = "recon"  # recon, mapping, hunting, validation, reporting
    active_skills: list[str] = field(default_factory=list)
    completed_skills: list[str] = field(default_factory=list)
    context: SkillContext = field(default_factory=SkillContext)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
            "current_phase": self.current_phase,
            "active_skills": self.active_skills,
            "completed_skills": self.completed_skills,
        }

    def get_findings(self, severity: str | None = None) -> list[Finding]:
        """Return the findings recorded for this session."""
        if severity:
            return memory.get_findings_by_severity(self.id, severity)
        return memory.get_findings_by_session(self.id)


class SessionManager:
    """Manages active hunting sessions."""

    def __init__(self):
        self._current_session: HuntSession | None = None
        self._sessions: dict[str, HuntSession] = {}

    def create_session(
        self, target: str = "", metadata: dict[str, Any] | None = None
    ) -> HuntSession:
        """Create a new hunting session."""
        session_id = memory.create_session(target, metadata)
        session = HuntSession(
            id=session_id,
            target=target,
            metadata=metadata or {},
            context=SkillContext(target=target, session_id=session_id),
        )
        self._sessions[session_id] = session
        self._current_session = session
        return session

    def get_session(self, session_id: str | None = None) -> HuntSession | None:
        """Get session by ID or current session."""
        if session_id:
            return self._sessions.get(session_id) or self._load_session(session_id)
        return self._current_session

    def _load_session(self, session_id: str) -> HuntSession | None:
        """Load session from database."""
        session_data = memory.get_session(session_id)
        if not session_data:
            return None

        session = HuntSession(
            id=session_data["id"],
            target=session_data["target"],
            created_at=datetime.fromisoformat(session_data["created_at"]),
            updated_at=datetime.fromisoformat(session_data["updated_at"]),
            metadata=session_data.get("metadata", {}),
        )
        self._sessions[session_id] = session
        return session

    def set_current_session(self, session_id: str) -> HuntSession | None:
        """Set current session by ID."""
        session = self.get_session(session_id)
        if session:
            self._current_session = session
        return session

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all sessions."""
        db_sessions = memory.list_sessions()
        for s in db_sessions:
            if s["id"] in self._sessions:
                s.update(self._sessions[s["id"]].to_dict())
        return db_sessions

    def update_phase(self, phase: str) -> None:
        """Update current phase."""
        if self._current_session:
            self._current_session.current_phase = phase
            self._current_session.updated_at = datetime.now()
            memory.update_session(self._current_session.id, self._current_session.metadata)

    def add_active_skill(self, skill_name: str) -> None:
        """Add skill to active skills."""
        if self._current_session and skill_name not in self._current_session.active_skills:
            self._current_session.active_skills.append(skill_name)

    def complete_skill(self, skill_name: str) -> None:
        """Mark skill as completed."""
        if self._current_session:
            if skill_name in self._current_session.active_skills:
                self._current_session.active_skills.remove(skill_name)
            if skill_name not in self._current_session.completed_skills:
                self._current_session.completed_skills.append(skill_name)
            self._current_session.updated_at = datetime.now()

    def update_context(self, **kwargs: Any) -> None:
        """Update session context."""
        if self._current_session:
            for key, value in kwargs.items():
                setattr(self._current_session.context, key, value)
            self._current_session.updated_at = datetime.now()

    def add_finding(self, finding: Finding) -> None:
        """Add finding to current session."""
        if self._current_session:
            finding.session_id = self._current_session.id
            memory.add_finding(finding)

    def get_findings(self, severity: str | None = None) -> list[Finding]:
        """Get findings for current session."""
        if not self._current_session:
            return []
        if severity:
            return memory.get_findings_by_severity(self._current_session.id, severity)
        return memory.get_findings_by_session(self._current_session.id)

    def get_conversation_history(self, limit: int = 100) -> list[Any]:
        """Get conversation history for current session."""
        if not self._current_session:
            return []
        return memory.get_conversation_history(self._current_session.id, limit)

    def add_conversation(
        self, role: str, content: str, metadata: dict[str, Any] | None = None
    ) -> None:
        """Add to conversation history."""
        if self._current_session:
            memory.add_conversation(self._current_session.id, role, content, metadata)

    def close_session(self) -> None:
        """Close current session."""
        if self._current_session:
            self._current_session.updated_at = datetime.now()
            memory.update_session(self._current_session.id, self._current_session.metadata)
            self._current_session = None


# Global session manager
session_manager = SessionManager()
