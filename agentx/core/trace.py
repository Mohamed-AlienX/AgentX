"""Append-only JSONL audit trace with hash chaining and secret redaction."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|authorization|bearer)\b\s*[:=]\s*([^\s,;]+)"
        ),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "[REDACTED_API_KEY]"),
)
_SECRET_KEYS = {
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "authorization",
    "cookie",
    "session",
    "private_key",
}


def redact_secrets(value: Any) -> Any:
    """Redact secrets from strings, mappings, and sequences."""
    if isinstance(value, str):
        redacted = value
        for pattern, replacement in _SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, inner in value.items():
            if str(key).lower() in _SECRET_KEYS:
                sanitized[str(key)] = "[REDACTED]"
            else:
                sanitized[str(key)] = redact_secrets(inner)
        return sanitized
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    return value


@dataclass
class TraceRecord:
    timestamp: str
    phase: str
    prompt: str
    tool_call: dict[str, Any]
    decision_rationale: str
    target: str
    prev_hash: str
    hash: str
    index: int


class AuditTrace:
    """Append-only JSONL audit log with per-record hash chaining."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        phase: str,
        prompt: str,
        tool_call: dict[str, Any] | None = None,
        decision_rationale: str = "",
        target: str = "",
        timestamp: str | None = None,
    ) -> TraceRecord:
        prev_hash = self._last_hash()
        index = self._next_index()
        ts = timestamp or datetime.now(UTC).isoformat()
        payload = {
            "timestamp": ts,
            "phase": phase,
            "prompt": redact_secrets(prompt),
            "tool_call": redact_secrets(tool_call or {}),
            "decision_rationale": redact_secrets(decision_rationale),
            "target": redact_secrets(target),
            "prev_hash": prev_hash,
            "index": index,
        }
        record_hash = self._hash_payload(payload)
        payload["hash"] = record_hash
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        return TraceRecord(**payload)

    def verify(self) -> bool:
        prev_hash = "GENESIS"
        for index, record in enumerate(self.read_all()):
            if record.get("prev_hash") != prev_hash:
                return False
            expected = self._hash_payload({k: v for k, v in record.items() if k != "hash"})
            if record.get("hash") != expected:
                return False
            if record.get("index") != index:
                return False
            prev_hash = str(record.get("hash", ""))
        return True

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records

    def _last_hash(self) -> str:
        records = self.read_all()
        if not records:
            return "GENESIS"
        return str(records[-1].get("hash", "GENESIS"))

    def _next_index(self) -> int:
        return len(self.read_all())

    @staticmethod
    def _hash_payload(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["AuditTrace", "TraceRecord", "redact_secrets"]
