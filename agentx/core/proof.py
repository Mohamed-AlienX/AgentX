"""Proof gate for executor findings and report candidates."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_EVIDENCE_KEYS = {
    "command_output",
    "http_request",
    "http_response",
    "http_pair",
    "request_response",
    "screenshot",
    "screenshot_path",
    "shell_proof",
}


@dataclass(frozen=True)
class ProofResult:
    """Outcome of proof validation."""

    accepted: bool
    reason: str = ""
    evidence_types: list[str] = field(default_factory=list)


class ProofGate:
    """Accept findings only when reproducible evidence is attached."""

    def evaluate(self, finding: Any) -> ProofResult:
        evidence = self._extract_evidence(finding)
        evidence_types = self._evidence_types(evidence)
        if evidence_types:
            return ProofResult(True, "reproducible evidence attached", evidence_types)
        return ProofResult(False, "proof missing: reproducible evidence required", [])

    def accept(self, finding: Any) -> bool:
        return self.evaluate(finding).accepted

    @staticmethod
    def _extract_evidence(finding: Any) -> Any:
        if isinstance(finding, dict):
            return finding.get("evidence")
        return getattr(finding, "evidence", None)

    @classmethod
    def _evidence_types(cls, evidence: Any) -> list[str]:
        found: list[str] = []
        if evidence is None:
            return found
        if isinstance(evidence, str):
            return ["evidence"] if evidence.strip() else []
        if isinstance(evidence, dict):
            for key, value in evidence.items():
                if key not in _EVIDENCE_KEYS:
                    continue
                if cls._has_value(value):
                    found.append(key)
            return sorted(set(found))
        if isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, dict):
                    found.extend(cls._evidence_types(item))
                elif cls._has_value(item):
                    found.append("evidence")
            return sorted(set(found))
        return ["evidence"] if cls._has_value(evidence) else []

    @staticmethod
    def _has_value(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, Path):
            return bool(str(value).strip())
        if isinstance(value, (dict, list, tuple, set)):
            return len(value) > 0
        return True


__all__ = ["ProofGate", "ProofResult"]
