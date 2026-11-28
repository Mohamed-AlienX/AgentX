"""Typed Brain -> Executor handoff payloads.

The wire format uses camelCase keys; Python internals use snake_case.  Use
:func:`from_handoff` at the ingress boundary and :func:`to_handoff` when
serialising back to the wire.
"""

from __future__ import annotations

import re
import types
from collections.abc import Callable
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Union, get_args, get_origin, get_type_hints

_ACRONYM_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_WORD_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")


def _camel_to_snake_name(name: str) -> str:
    """Convert a single camelCase key to snake_case (acronym aware)."""
    spaced = _ACRONYM_RE.sub(r"\1_\2", name)
    return _WORD_BOUNDARY_RE.sub(r"\1_\2", spaced).lower()


def _snake_to_camel_name(name: str) -> str:
    """Convert a single snake_case key to camelCase."""
    head, *tail = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def _convert_keys(value: Any, convert: Callable[[str], str]) -> Any:
    """Recursively convert keys in mappings, sequences and dataclass instances."""
    if is_dataclass(value) and not isinstance(value, type):
        result: dict[str, Any] = {}
        for item in fields(value):
            if not item.metadata.get("wire", True):
                continue
            inner = getattr(value, item.name)
            if inner is None:
                continue
            result[convert(item.name)] = _convert_keys(inner, convert)
        return result
    if isinstance(value, dict):
        return {convert(str(key)): _convert_keys(inner, convert) for key, inner in value.items()}
    if isinstance(value, list):
        return [_convert_keys(item, convert) for item in value]
    if isinstance(value, tuple):
        return tuple(_convert_keys(item, convert) for item in value)
    return value


def camel_to_snake(value: Any) -> Any:
    """Convert a key name, or recursively convert every key in a nested value."""
    if isinstance(value, str):
        return _camel_to_snake_name(value)
    return _convert_keys(value, _camel_to_snake_name)


def snake_to_camel(value: Any) -> Any:
    """Convert a key name, or recursively convert every key in a nested value."""
    if isinstance(value, str):
        return _snake_to_camel_name(value)
    return _convert_keys(value, _snake_to_camel_name)


@dataclass
class ExploitCandidate:
    """A single exploit option attached to a vulnerability."""

    id: str = ""
    type: str = ""
    module: str | None = None
    script_path: str = ""
    reliability: str = ""
    expected_outcome: str = ""
    # Internal linkage populated from the parent vulnerability; never sent on the wire.
    cve_id: str | None = field(default=None, metadata={"wire": False})


@dataclass
class Vulnerability:
    """A vulnerability reported by the Brain, with its exploit candidates."""

    cve_id: str = ""
    name: str | None = None
    version_range: str | None = None
    severity: str = ""
    exploit_type: str = ""
    available_exploits: list[ExploitCandidate] = field(default_factory=list)

    def __post_init__(self) -> None:
        for exploit in self.available_exploits:
            if isinstance(exploit, ExploitCandidate) and exploit.cve_id is None:
                exploit.cve_id = self.cve_id


@dataclass
class DiscoveredService:
    """A service discovered during reconnaissance."""

    port: int = 0
    service: str = ""
    priority: int = 0
    software: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class AttackVector:
    """A candidate path from the Brain toward a target service."""

    id: str = ""
    name: str = ""
    target_service: dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    success_probability: float = 0.0
    # Scoring metadata is internal and is not emitted on the wire.
    cve_id: str | None = field(default=None, metadata={"wire": False})
    expected_outcome: str | None = field(default=None, metadata={"wire": False})
    reliability: str | None = field(default=None, metadata={"wire": False})
    exploit_scope: str | None = field(default=None, metadata={"wire": False})

    @property
    def target_port(self) -> int | None:
        """Convenience accessor for the target service port."""
        port = self.target_service.get("port") if isinstance(self.target_service, dict) else None
        return int(port) if port is not None else None


@dataclass
class TargetProfile:
    """High-level target assessment from the Brain."""

    target_type: str = ""
    operating_system: str = ""
    security_posture: str = ""
    recommended_approach: str = ""
    assessment_confidence: int | None = None


@dataclass
class TargetIntelligence:
    """Raw target facts gathered by the Brain (profile is a free-form mapping)."""

    profile: dict[str, Any] = field(default_factory=dict)
    tech_stack: dict[str, Any] = field(default_factory=dict)
    confidence: int | None = None


@dataclass
class ToolStrategy:
    """Tool preference ordering from the Brain."""

    primary_tools: list[dict[str, Any]] = field(default_factory=list)
    execution_order: list[str] = field(default_factory=list)


@dataclass
class BrainIntelligence:
    """The full intelligence bundle carried by a handoff."""

    target_profile: TargetProfile = field(default_factory=TargetProfile)
    target_intelligence: TargetIntelligence = field(default_factory=TargetIntelligence)
    tool_strategy: ToolStrategy = field(default_factory=ToolStrategy)
    discovered_services: list[DiscoveredService] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    attack_vectors: list[AttackVector] = field(default_factory=list)
    confidence: int | None = None
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutorInput:
    """Executor-side echo of the target and scan identifiers."""

    target: str = ""
    attacker_port: int | None = None
    scan_id: str = ""


@dataclass
class HandoffEnvelope:
    """Top-level Brain -> Executor handoff message."""

    phase: str = ""
    scan_id: str = ""
    target: str = ""
    attacker_port: int | None = None
    brain_intelligence: BrainIntelligence = field(default_factory=BrainIntelligence)
    executor_input: ExecutorInput = field(default_factory=ExecutorInput)
    unknown_fields: list[str] = field(default_factory=list, metadata={"wire": False})
    null_paths: list[_Path] = field(default_factory=list, metadata={"wire": False})


def _coerce_primitive(value: Any, annotation: type) -> Any:
    """Coerce a scalar wire value, rejecting values that cannot be parsed."""
    if annotation is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            if lowered in {"false", "0", "no", "off"}:
                return False
        raise ValueError(f"invalid bool value {value!r}")
    if isinstance(value, annotation):
        return value
    if annotation in (int, float):
        try:
            return annotation(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid {annotation.__name__} value {value!r}") from exc
    if isinstance(value, (int, float, bool)):
        return str(value)
    raise ValueError(f"invalid str value {value!r}")


def _coerce(value: Any, annotation: Any) -> Any:
    """Coerce a nested value into the type declared on its dataclass field."""
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if value is None:
            return None
        return _coerce(value, args[0]) if args else value
    if annotation in (int, float, str, bool):
        return _coerce_primitive(value, annotation)
    if origin in (list, tuple):
        args = get_args(annotation)
        item_type = args[0] if args else Any
        if isinstance(value, list):
            return [_coerce(item, item_type) for item in value]
        return value
    if origin is dict:
        return dict(value) if isinstance(value, dict) else value
    if isinstance(annotation, type) and is_dataclass(annotation) and isinstance(value, dict):
        return _build_dataclass(annotation, value)
    return value


def _build_dataclass(cls: type, data: dict[str, Any]) -> Any:
    """Instantiate a dataclass from snake_case data, ignoring unknown keys."""
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for item in fields(cls):
        if not item.init or item.name not in data:
            continue
        try:
            kwargs[item.name] = _coerce(data[item.name], hints.get(item.name, Any))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid handoff value for '{item.name}': {exc}") from exc
    return cls(**kwargs)


_Path = tuple[str | int, ...]


def _collect_null_paths(value: Any, prefix: _Path = ()) -> list[_Path]:
    """Record paths of explicit nulls in the incoming wire payload."""
    paths: list[_Path] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            path = prefix + (str(key),)
            if inner is None:
                paths.append(path)
            else:
                paths.extend(_collect_null_paths(inner, path))
    elif isinstance(value, list):
        for index, inner in enumerate(value):
            path = prefix + (index,)
            if inner is None:
                paths.append(path)
            else:
                paths.extend(_collect_null_paths(inner, path))
    return paths


def _apply_null_paths(result: dict[str, Any], paths: list[_Path]) -> None:
    """Restore explicit nulls that dataclass serialisation would otherwise drop."""
    for path in paths:
        target: Any = result
        for part in path[:-1]:
            if isinstance(part, int):
                if not isinstance(target, list):
                    break
                while len(target) <= part:
                    target.append(None)
                if target[part] is None:
                    target[part] = {}
                target = target[part]
            else:
                if not isinstance(target, dict):
                    break
                target = target.setdefault(part, {})
        else:
            last = path[-1]
            if isinstance(last, int) and isinstance(target, list):
                while len(target) <= last:
                    target.append(None)
                target[last] = None
            elif isinstance(last, str) and isinstance(target, dict):
                target[last] = None


def from_handoff(payload: dict[str, Any]) -> HandoffEnvelope:
    """Parse a camelCase wire payload into typed snake_case dataclasses."""
    if not isinstance(payload, dict):
        raise TypeError("handoff payload must be a dict")
    normalized = camel_to_snake(payload)
    if not isinstance(normalized, dict):
        raise TypeError("handoff payload must be a dict")
    envelope = _build_dataclass(HandoffEnvelope, normalized)
    known = {item.name for item in fields(HandoffEnvelope) if item.init}
    envelope.unknown_fields = sorted(set(normalized) - known)
    envelope.null_paths = [
        path for path in _collect_null_paths(normalized) if path and path[0] in known
    ]
    return envelope


def to_handoff(envelope: HandoffEnvelope) -> dict[str, Any]:
    """Serialise a typed envelope back to the camelCase wire format."""
    if not isinstance(envelope, HandoffEnvelope):
        raise TypeError("expected a HandoffEnvelope")
    result = snake_to_camel(envelope)
    if not isinstance(result, dict):
        return {}
    camel_paths: list[_Path] = [
        tuple(_snake_to_camel_name(part) if isinstance(part, str) else part for part in path)
        for path in envelope.null_paths
    ]
    _apply_null_paths(result, camel_paths)
    return result


__all__ = [
    "AttackVector",
    "BrainIntelligence",
    "DiscoveredService",
    "ExecutorInput",
    "ExploitCandidate",
    "HandoffEnvelope",
    "TargetIntelligence",
    "TargetProfile",
    "ToolStrategy",
    "Vulnerability",
    "camel_to_snake",
    "from_handoff",
    "snake_to_camel",
    "to_handoff",
]
