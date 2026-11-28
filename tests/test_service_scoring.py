"""Tests for service normalization, exploit hygiene and vector ranking."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from agentx.core.intelligence import (
    AttackVector,
    DiscoveredService,
    ExploitCandidate,
    Vulnerability,
    from_handoff,
)
from agentx.core.service_scoring import (
    BASE_SCORE,
    COMMON_PORT_WEIGHT,
    HIGH_VALUE_WEIGHT,
    RCE_PRONE_WEIGHT,
    VERSION_DETECTED_WEIGHT,
    canonical_service_name,
    classify_exploit_scope,
    deduplicate_exploits,
    normalize_services,
    rank_attack_vectors,
    score_service,
    version_is_vulnerable,
)

FIXTURE = Path(__file__).parent / "fixtures" / "executor_handoff.json"


def _intelligence():
    return from_handoff(json.loads(FIXTURE.read_text(encoding="utf-8"))).brain_intelligence


def test_smb_score_weights_sum_to_110() -> None:
    assert (BASE_SCORE, HIGH_VALUE_WEIGHT, RCE_PRONE_WEIGHT) == (30, 50, 30)
    assert (VERSION_DETECTED_WEIGHT, COMMON_PORT_WEIGHT) == (20, 10)
    smb = DiscoveredService(port=445, service="netbios-ssn", priority=0, version="3.0.20")
    assert score_service(smb) == 110


def test_normalize_services_collapses_smb_ports() -> None:
    services = normalize_services(_intelligence().discovered_services)

    assert [service.port for service in services] == [21, 22, 445]
    smb = services[-1]
    assert smb.service == "smb"
    assert smb.version == "3.0.20"
    assert smb.software == "Samba"
    assert smb.priority == 110
    assert canonical_service_name("netbios-ns") == "smb"


def test_deduplicate_exploits_removes_repeat_entries() -> None:
    vulnerability = next(
        vuln for vuln in _intelligence().vulnerabilities if vuln.cve_id == "CVE-2007-2447"
    )

    assert len(vulnerability.available_exploits) == 2
    unique = deduplicate_exploits(vulnerability.available_exploits)
    assert len(unique) == 1
    assert unique[0].cve_id == "CVE-2007-2447"


def test_version_range_comparisons_are_strict() -> None:
    assert version_is_vulnerable("3.0.20", "< 3.0.20") is False
    assert version_is_vulnerable("3.0.19", "< 3.0.20") is True
    assert version_is_vulnerable("3.0.20", "<= 3.0.20") is True
    assert version_is_vulnerable("3.0.21", "<= 3.0.20") is False
    assert version_is_vulnerable("3.0.20", "> 3.0.19") is True
    assert version_is_vulnerable("3.0.20", ">= 3.0.21") is False
    assert version_is_vulnerable("3.0.20", "3.0.10 < 3.3.5") is True
    assert version_is_vulnerable("3.3.5", "3.0.10 < 3.3.5") is False
    assert version_is_vulnerable("3.0.20", "") is True


def test_local_exploit_paths_are_classified() -> None:
    assert classify_exploit_scope("/opt/exploitdb/exploits/linux/local/40962.txt") == "local"
    assert classify_exploit_scope("/opt/exploitdb/exploits/unix/remote/16320.rb") == "remote"


def test_ranking_puts_smb_usermap_script_first() -> None:
    ranked = rank_attack_vectors(_intelligence())

    assert ranked[0].cve_id == "CVE-2007-2447"
    assert ranked[0].target_port == 445
    assert ranked[0].target_service["port"] == 445
    assert ranked[0].target_service["service"] == "smb"
    assert ranked[0].priority > 100
    assert ranked[0].expected_outcome == "shell"
    assert ranked[0].reliability == "great"


def test_ranking_excludes_incompatible_and_local_exploits() -> None:
    intelligence = _intelligence()
    outdated = AttackVector(
        id="av-7701",
        name="EDB-7701 via netbios-ssn",
        target_service={"port": 139, "service": "netbios-ssn", "priority": 110},
        priority=100,
        success_probability=0.9,
    )
    local = AttackVector(
        id="av-local",
        name="CVE-2016-10010 via ssh",
        target_service={"port": 22, "service": "ssh", "priority": 80},
        priority=100,
        success_probability=0.9,
    )
    intelligence.attack_vectors = [outdated, local, *intelligence.attack_vectors]

    ranked = rank_attack_vectors(intelligence)
    names = [vector.cve_id for vector in ranked]

    assert "EDB-7701" not in names
    assert "CVE-2016-10010" not in names
    assert ranked[0].cve_id == "CVE-2007-2447"


def test_enumeration_vector_is_downgraded_to_info_disclosure() -> None:
    intelligence = _intelligence()
    intelligence.attack_vectors.append(
        AttackVector(
            id="av-enum",
            name="CVE-2018-15473 via ssh",
            target_service={"port": 22, "service": "ssh", "priority": 80},
            priority=100,
            success_probability=0.75,
        )
    )

    vector = next(
        item for item in rank_attack_vectors(intelligence) if item.cve_id == "CVE-2018-15473"
    )
    assert vector.expected_outcome == "info_disclosure"
    assert vector.priority < 100
    assert vector.success_probability <= 0.1


def test_smb_merge_preserves_first_record_metadata() -> None:
    first = DiscoveredService(
        port=139, service="netbios-ssn", priority=110, version="3.0.20", software="Samba"
    )
    second = replace(first, port=445)

    merged = normalize_services([first, second])

    assert len(merged) == 1
    assert merged[0].port == 445
    assert merged[0].version == "3.0.20"


def test_exploit_candidates_accept_explicit_cve_link() -> None:
    exploit = ExploitCandidate(id="x", script_path="/tmp/x.rb", cve_id="CVE-1-1")

    assert deduplicate_exploits([exploit, replace(exploit)]) == [exploit]


def test_empty_vulnerability_has_no_best_exploit() -> None:
    vulnerability = Vulnerability(cve_id="CVE-0-0", available_exploits=[])

    assert (
        rank_attack_vectors(
            replace(_intelligence(), attack_vectors=[], vulnerabilities=[vulnerability])
        )
        == []
    )


def test_relative_local_paths_are_classified_as_local() -> None:
    assert classify_exploit_scope("local/40962.txt") == "local"
    assert classify_exploit_scope("exploits/local") == "local"
    assert classify_exploit_scope("exploits/remote/16320.rb") == "remote"


def test_string_typed_numeric_fields_do_not_break_ranking() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["brainIntelligence"]["discoveredServices"][3]["port"] = "445"
    vector = payload["brainIntelligence"]["attackVectors"][1]
    vector["priority"] = "100"
    vector["targetService"]["port"] = "139"

    envelope = from_handoff(payload)
    intelligence = envelope.brain_intelligence

    assert isinstance(intelligence.discovered_services[3].port, int)
    assert score_service(intelligence.discovered_services[3]) == 110
    ranked = rank_attack_vectors(intelligence)
    assert ranked[0].cve_id == "CVE-2007-2447"
    assert ranked[0].target_port == 445
    assert ranked[0].priority > 100


def test_smb_profile_version_on_139_blocks_stale_vector() -> None:
    intelligence = _intelligence()
    intelligence.discovered_services = []
    profile = intelligence.target_intelligence.profile
    profile["services"] = [service for service in profile["services"] if service["port"] != 445]
    assert [service["port"] for service in profile["services"]] == [21, 22, 139]
    intelligence.attack_vectors.append(
        AttackVector(
            id="av-stale",
            name="EDB-7701 via netbios-ssn",
            target_service={"port": 139, "service": "netbios-ssn", "priority": 110},
            priority=100,
            success_probability=0.9,
        )
    )

    ranked = rank_attack_vectors(intelligence)

    assert "EDB-7701" not in [vector.cve_id for vector in ranked]
    assert ranked[0].cve_id == "CVE-2007-2447"
    assert ranked[0].target_port == 445
