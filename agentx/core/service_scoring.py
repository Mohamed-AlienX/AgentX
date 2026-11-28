"""Service canonicalisation, exploit hygiene and attack-vector ranking."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from agentx.core.intelligence import (
    AttackVector,
    BrainIntelligence,
    DiscoveredService,
    ExploitCandidate,
    Vulnerability,
    camel_to_snake,
)

SERVICE_ALIASES: dict[str, str] = {
    "netbios-ssn": "smb",
    "netbios-ns": "smb",
    "netbios-dgm": "smb",
    "microsoft-ds": "smb",
}

SMB_PREFERRED_PORT = 445
SMB_PORTS = (139, 445)

BASE_SCORE = 30
HIGH_VALUE_WEIGHT = 50
RCE_PRONE_WEIGHT = 30
VERSION_DETECTED_WEIGHT = 20
COMMON_PORT_WEIGHT = 10

SMB_BASE_SCORE = BASE_SCORE
SMB_HIGH_VALUE_WEIGHT = HIGH_VALUE_WEIGHT
SMB_RCE_PRONE_WEIGHT = RCE_PRONE_WEIGHT
SMB_VERSION_DETECTED_WEIGHT = VERSION_DETECTED_WEIGHT
SMB_COMMON_PORT_WEIGHT = COMMON_PORT_WEIGHT
SMB_TOTAL_SCORE = 110

COMMON_PORTS = frozenset({21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080})

SHELL_BONUS = 50
INFO_DISCLOSURE_PENALTY = -100
GREAT_RELIABILITY_BONUS = 30
GOOD_RELIABILITY_BONUS = 15
PREFERRED_SMB_PORT_BONUS = 10
LOCAL_EXPLOIT_PENALTY = -100

_RELIABILITY_BONUSES = {
    "great": GREAT_RELIABILITY_BONUS,
    "good": GOOD_RELIABILITY_BONUS,
    "normal": 0,
    "average": 0,
}
_OUTCOME_BONUSES = {
    "shell": SHELL_BONUS,
    "info_disclosure": INFO_DISCLOSURE_PENALTY,
}
_INFO_DISCLOSURE_MARKERS = (
    "enumeration",
    "information disclosure",
    "info disclosure",
    "info_disclosure",
    "(poc)",
)
_LOCAL_MARKERS = ("local privilege escalation", "local exploit")
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d+|EDB-\d+)\b", re.IGNORECASE)
_VERSION_TOKEN_RE = re.compile(r"(<=|>=|<|>|=)?\s*(\d[\w.\-]*)")


def canonical_service_name(service: str | None) -> str:
    """Map wire service names (for example netbios-ssn) to canonical names."""
    name = (service or "").strip().lower()
    return SERVICE_ALIASES.get(name, name)


def score_service(service: DiscoveredService) -> int:
    """Score a service; SMB bonuses total 110 on a detected common port.

    ``BASE_SCORE`` is the floor for an otherwise unremarkable service, not an
    extra additive term on top of the SMB bonuses.
    """
    name = canonical_service_name(service.service)
    has_version = bool((service.version or "").strip())
    if name == "smb":
        score = HIGH_VALUE_WEIGHT + RCE_PRONE_WEIGHT
        if has_version:
            score += VERSION_DETECTED_WEIGHT
        if service.port in SMB_PORTS:
            score += COMMON_PORT_WEIGHT
        return max(BASE_SCORE, score)
    score = BASE_SCORE
    if has_version:
        score += VERSION_DETECTED_WEIGHT
    if service.port in COMMON_PORTS:
        score += COMMON_PORT_WEIGHT
    return score


def score_smb_service(service: DiscoveredService) -> int:
    """Score a service as SMB regardless of its wire name or port."""
    return score_service(replace(service, service="smb", port=SMB_PREFERRED_PORT))


def _merge_smb(base: DiscoveredService, extra: DiscoveredService) -> DiscoveredService:
    """Combine two SMB records while retaining the richest identifying metadata."""
    return replace(
        base,
        service="smb",
        port=SMB_PREFERRED_PORT,
        software=extra.software or base.software,
        version=extra.version or base.version,
        banner=extra.banner or base.banner,
        priority=max(base.priority, extra.priority),
    )


def normalize_services(services: list[DiscoveredService]) -> list[DiscoveredService]:
    """Canonicalise names and collapse SMB ports 139/445 into one service on 445."""
    normalized: list[DiscoveredService] = []
    smb_record: DiscoveredService | None = None
    smb_index: int | None = None

    for service in services:
        name = canonical_service_name(service.service)
        if name == "smb":
            candidate = replace(service, service="smb", port=SMB_PREFERRED_PORT)
            if smb_record is None:
                smb_record = candidate
                smb_index = len(normalized)
                normalized.append(candidate)
            else:
                smb_record = _merge_smb(smb_record, candidate)
            continue
        normalized.append(replace(service, service=name))

    if smb_record is not None and smb_index is not None:
        smb_record.priority = score_service(smb_record)
        normalized[smb_index] = smb_record
    return normalized


def deduplicate_exploits(exploits: list[ExploitCandidate]) -> list[ExploitCandidate]:
    """Drop repeat exploit candidates sharing a CVE id and script path."""
    seen: set[tuple[str, str]] = set()
    unique: list[ExploitCandidate] = []
    for exploit in exploits:
        key = (getattr(exploit, "cve_id", None) or "", exploit.script_path or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(exploit)
    return unique


def classify_exploit_scope(script_path: str) -> str:
    """Return ``local`` for local exploit paths, otherwise ``remote``."""
    normalized = (script_path or "").replace("\\", "/").lower()
    return "local" if "/local/" in f"/{normalized}/" else "remote"


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version or ""))


def _padded(
    left: tuple[int, ...], right: tuple[int, ...]
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    length = max(len(left), len(right))
    return left + (0,) * (length - len(left)), right + (0,) * (length - len(right))


def version_is_vulnerable(version: str, version_range: str) -> bool:
    """Strictly test a detected version against a declared version range."""
    if not version_range or not version_range.strip():
        return True
    detected = _version_tuple(version)
    if not detected:
        return True
    tokens = _VERSION_TOKEN_RE.findall(version_range)
    if not tokens:
        return True

    for index, (operator, raw_bound) in enumerate(tokens):
        bound = _version_tuple(raw_bound)
        if not bound:
            continue
        if not operator:
            operator = ">=" if index == 0 and len(tokens) > 1 else "="
        left, right = _padded(detected, bound)
        if operator == "<" and not left < right:
            return False
        if operator == "<=" and not left <= right:
            return False
        if operator == ">" and not left > right:
            return False
        if operator == ">=" and not left >= right:
            return False
        if operator in ("", "=") and left != right:
            return False
    return True


def _extract_cve_id(text: str) -> str | None:
    match = _CVE_RE.search(text or "")
    return match.group(1).upper() if match else None


def _is_info_disclosure(vulnerability: Vulnerability, exploit: ExploitCandidate) -> bool:
    haystack = " ".join(
        part.lower()
        for part in (
            vulnerability.name or "",
            vulnerability.cve_id or "",
            exploit.module or "",
            exploit.script_path or "",
        )
    )
    return any(marker in haystack for marker in _INFO_DISCLOSURE_MARKERS)


def _is_local_by_name(vulnerability: Vulnerability) -> bool:
    name = (vulnerability.name or "").lower()
    return any(marker in name for marker in _LOCAL_MARKERS)


def _best_exploit(vulnerability: Vulnerability) -> ExploitCandidate | None:
    exploits = deduplicate_exploits(vulnerability.available_exploits)
    if not exploits:
        return None

    def desirability(exploit: ExploitCandidate) -> tuple[int, int, int]:
        outcome = (exploit.expected_outcome or "").lower()
        reliability = (exploit.reliability or "").lower()
        return (
            1 if outcome == "shell" else 0,
            1 if reliability == "great" else 0,
            1 if classify_exploit_scope(exploit.script_path) == "remote" else 0,
        )

    return max(exploits, key=desirability)


def _profile_service_versions(intelligence: BrainIntelligence) -> dict[int, str]:
    profile = intelligence.target_intelligence.profile
    raw_services = profile.get("services", []) if isinstance(profile, dict) else []
    versions: dict[int, str] = {}
    for raw in raw_services if isinstance(raw_services, list) else []:
        if not isinstance(raw, dict):
            continue
        normalized = camel_to_snake(raw)
        port = normalized.get("port")
        version = normalized.get("version")
        if isinstance(port, int) and isinstance(version, str):
            versions[port] = version
    return versions


def _to_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _matching_service(
    services: list[DiscoveredService], port: int | None, name: str
) -> DiscoveredService | None:
    for service in services:
        if canonical_service_name(service.service) == name and service.port == port:
            return service
    if name:
        for service in services:
            if canonical_service_name(service.service) == name:
                return service
    return None


def rank_attack_vectors(intelligence: BrainIntelligence) -> list[AttackVector]:
    """Score and order attack vectors using normalized service and exploit data."""
    services = normalize_services(intelligence.discovered_services)
    profile_versions = _profile_service_versions(intelligence)
    vulnerabilities = {
        vulnerability.cve_id.upper(): vulnerability
        for vulnerability in intelligence.vulnerabilities
        if vulnerability.cve_id
    }

    ranked: list[AttackVector] = []
    for vector in intelligence.attack_vectors:
        cve_id = vector.cve_id or _extract_cve_id(vector.name)
        vulnerability = vulnerabilities.get((cve_id or "").upper())

        target_service = dict(vector.target_service or {})
        name = canonical_service_name(str(target_service.get("service", "")))
        if name == "smb":
            target_service["port"] = SMB_PREFERRED_PORT
            target_service["service"] = "smb"
        port = _to_int(target_service.get("port"))
        service = _matching_service(services, port, name)
        service_priority = service.priority if service is not None else 0

        exploit = _best_exploit(vulnerability) if vulnerability is not None else None
        if vulnerability is not None and vulnerability.version_range:
            detected_version = ""
            if service is not None:
                detected_version = service.version or ""
            if not detected_version:
                if name == "smb":
                    # The vector was rewritten to 445, but the profile may only
                    # declare a version on the original 139 record.
                    detected_version = next(
                        (profile_versions[p] for p in SMB_PORTS if p in profile_versions), ""
                    )
                elif port is not None:
                    detected_version = profile_versions.get(port, "")
            if detected_version and not version_is_vulnerable(
                detected_version, vulnerability.version_range
            ):
                continue

        outcome = "shell"
        if exploit is not None:
            outcome = (exploit.expected_outcome or "shell").lower()
        if (
            vulnerability is not None
            and exploit is not None
            and _is_info_disclosure(vulnerability, exploit)
        ):
            outcome = "info_disclosure"

        reliability = (exploit.reliability or "").lower() if exploit is not None else ""
        scope = classify_exploit_scope(exploit.script_path) if exploit is not None else "remote"
        if scope == "local" or (vulnerability is not None and _is_local_by_name(vulnerability)):
            # A local-only exploit cannot be used from a remotely discovered service.
            continue

        priority = max(vector.priority or 0, service_priority)
        priority += _OUTCOME_BONUSES.get(outcome, 0)
        priority += _RELIABILITY_BONUSES.get(reliability, 0)
        if name == "smb" and port == SMB_PREFERRED_PORT:
            priority += PREFERRED_SMB_PORT_BONUS
        priority = max(0, priority)

        success_probability = float(vector.success_probability or 0.0)
        if outcome == "info_disclosure":
            success_probability = min(success_probability, 0.1)

        ranked.append(
            replace(
                vector,
                target_service=target_service,
                priority=priority,
                success_probability=success_probability,
                cve_id=cve_id,
                expected_outcome=outcome,
                reliability=reliability,
                exploit_scope=scope,
            )
        )

    ranked.sort(key=lambda item: (-item.priority, -item.success_probability, item.name))
    return ranked


__all__ = [
    "BASE_SCORE",
    "COMMON_PORT_WEIGHT",
    "GREAT_RELIABILITY_BONUS",
    "HIGH_VALUE_WEIGHT",
    "INFO_DISCLOSURE_PENALTY",
    "LOCAL_EXPLOIT_PENALTY",
    "PREFERRED_SMB_PORT_BONUS",
    "RCE_PRONE_WEIGHT",
    "SERVICE_ALIASES",
    "SHELL_BONUS",
    "SMB_BASE_SCORE",
    "SMB_COMMON_PORT_WEIGHT",
    "SMB_HIGH_VALUE_WEIGHT",
    "SMB_PREFERRED_PORT",
    "SMB_RCE_PRONE_WEIGHT",
    "SMB_TOTAL_SCORE",
    "SMB_VERSION_DETECTED_WEIGHT",
    "VERSION_DETECTED_WEIGHT",
    "canonical_service_name",
    "classify_exploit_scope",
    "deduplicate_exploits",
    "normalize_services",
    "rank_attack_vectors",
    "score_service",
    "score_smb_service",
    "version_is_vulnerable",
]
