"""Deterministic, code-level scope control for AgentX executor runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from time import monotonic
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ScopeDecision:
    """Result of a scope-control preflight check."""

    allowed: bool
    reason: str = ""
    category: str = "ok"


@dataclass
class ScopeGuard:
    """Preflight guard for target, action, and rate-limit enforcement."""

    allowed_targets: list[str] = field(default_factory=list)
    denied_targets: list[str] = field(default_factory=list)
    destructive_actions: list[str] = field(
        default_factory=lambda: [
            "rm -rf",
            "mkfs",
            "shutdown",
            "reboot",
            "poweroff",
            "drop database",
            "drop table",
            ":(){:|:&};:",
        ]
    )
    rate_limit: int = 60
    rate_window_seconds: float = 60.0
    _aborted: bool = field(default=False, init=False, repr=False)
    _abort_reason: str = field(default="aborted", init=False, repr=False)
    _events: dict[str, list[float]] = field(default_factory=dict, init=False, repr=False)

    def abort(self, reason: str = "aborted") -> None:
        """Trip the kill-switch so subsequent checks fail immediately."""
        self._aborted = True
        self._abort_reason = reason or "aborted"

    def reset_abort(self) -> None:
        self._aborted = False
        self._abort_reason = "aborted"

    @property
    def aborted(self) -> bool:
        return self._aborted

    @property
    def abort_reason(self) -> str:
        return self._abort_reason

    def check_abort(self) -> ScopeDecision:
        if self._aborted:
            return ScopeDecision(False, self._abort_reason, "abort")
        return ScopeDecision(True)

    def check_target(self, target: str) -> ScopeDecision:
        host = self._normalize_target(target)
        if not host:
            return ScopeDecision(False, "target is empty", "target")
        for pattern in self.denied_targets:
            if self._matches(host, pattern):
                return ScopeDecision(False, f"target denied by scope: {pattern}", "target")
        if self.allowed_targets and not any(
            self._matches(host, pattern) for pattern in self.allowed_targets
        ):
            return ScopeDecision(False, "target is outside allowed scope", "target")
        return ScopeDecision(True)

    def check_action(self, action: str) -> ScopeDecision:
        text = (action or "").strip().lower()
        if not text:
            return ScopeDecision(True)
        for pattern in self.destructive_actions:
            if pattern.lower() in text:
                return ScopeDecision(False, f"destructive action denied: {pattern}", "destructive")
        return ScopeDecision(True)

    def check_rate_limit(self, target: str, now: float | None = None) -> ScopeDecision:
        host = self._normalize_target(target) or (target or "").strip().lower() or "*"
        timestamp = monotonic() if now is None else now
        window_start = timestamp - self.rate_window_seconds
        events = [event for event in self._events.get(host, []) if event >= window_start]
        if len(events) >= self.rate_limit:
            self._events[host] = events
            return ScopeDecision(
                False,
                f"rate limit exceeded for {host}: {self.rate_limit}/{self.rate_window_seconds}s",
                "rate_limit",
            )
        events.append(timestamp)
        self._events[host] = events
        return ScopeDecision(True)

    def preflight(self, target: str, action: str = "", now: float | None = None) -> ScopeDecision:
        for decision in (
            self.check_abort(),
            self.check_target(target),
            self.check_action(action),
            self.check_rate_limit(target, now=now),
        ):
            if not decision.allowed:
                return decision
        return ScopeDecision(True)

    @staticmethod
    def _normalize_target(target: str) -> str:
        raw = (target or "").strip()
        if not raw:
            return ""
        if "://" in raw:
            host = urlsplit(raw).hostname or ""
        else:
            host = raw.split("/")[0]
        host = host.strip().lower().strip("[]")
        if host.count(":") == 1 and not host.startswith("["):
            host = host.split(":", 1)[0]
        return host.strip(".")

    @classmethod
    def _matches(cls, host: str, pattern: str) -> bool:
        pat = cls._normalize_target(pattern) or pattern.strip().lower().strip(".")
        if not pat:
            return False
        if pat.startswith("*."):
            suffix = pat[2:]
            return host == suffix or host.endswith("." + suffix)
        if any(ch in pat for ch in "*?[]"):
            return fnmatch(host, pat)
        return host == pat


__all__ = ["ScopeDecision", "ScopeGuard"]
