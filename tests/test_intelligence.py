"""Tests for typed Brain -> Executor handoff parsing and serialisation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentx.core.intelligence import (
    AttackVector,
    BrainIntelligence,
    DiscoveredService,
    ExecutorInput,
    ExploitCandidate,
    HandoffEnvelope,
    Vulnerability,
    camel_to_snake,
    from_handoff,
    snake_to_camel,
    to_handoff,
)

FIXTURE = Path(__file__).parent / "fixtures" / "executor_handoff.json"


def _payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_parses_into_typed_dataclasses() -> None:
    envelope = from_handoff(_payload())

    assert isinstance(envelope, HandoffEnvelope)
    assert envelope.unknown_fields == []
    assert envelope.scan_id == "hybrid-1767007979956-8h3wsf"
    assert envelope.attacker_port == 4444
    assert isinstance(envelope.brain_intelligence, BrainIntelligence)
    assert isinstance(envelope.executor_input, ExecutorInput)
    assert isinstance(envelope.brain_intelligence.discovered_services[0], DiscoveredService)
    assert isinstance(envelope.brain_intelligence.vulnerabilities[0], Vulnerability)
    assert isinstance(
        envelope.brain_intelligence.vulnerabilities[0].available_exploits[0], ExploitCandidate
    )
    assert isinstance(envelope.brain_intelligence.attack_vectors[0], AttackVector)


def test_round_trip_preserves_wire_keys() -> None:
    payload = _payload()
    wire = to_handoff(from_handoff(payload))

    assert wire["scanId"] == payload["scanId"]
    assert wire["attackerPort"] == payload["attackerPort"]
    assert wire["executorInput"]["scanId"] == payload["executorInput"]["scanId"]
    assert [s["port"] for s in wire["brainIntelligence"]["discoveredServices"]] == [
        21,
        22,
        139,
        445,
    ]
    assert [v["cveId"] for v in wire["brainIntelligence"]["vulnerabilities"]] == [
        "CVE-2011-2523",
        "CVE-2007-2447",
        "EDB-7701",
        "CVE-2018-15473",
        "CVE-2016-10010",
    ]
    assert wire == payload


def test_key_helpers_handle_names_and_nested_values() -> None:
    assert camel_to_snake("scanId") == "scan_id"
    assert camel_to_snake("CVEId") == "cve_id"
    assert snake_to_camel("cve_id") == "cveId"
    assert camel_to_snake({"scanId": 1, "items": [{"attackerPort": 2}]}) == {
        "scan_id": 1,
        "items": [{"attacker_port": 2}],
    }
    assert snake_to_camel(ExecutorInput(scan_id="s", attacker_port=1)) == {
        "target": "",
        "attackerPort": 1,
        "scanId": "s",
    }


def test_missing_optional_keys_are_tolerated() -> None:
    envelope = from_handoff({"phase": "executor-handoff", "scanId": "minimal"})

    assert envelope.scan_id == "minimal"
    assert envelope.brain_intelligence.discovered_services == []
    assert envelope.executor_input.target == ""


def test_unknown_keys_are_ignored_and_reported() -> None:
    payload = _payload()
    payload["futureBrainField"] = {"nestedKey": 1}

    envelope = from_handoff(payload)

    assert envelope.unknown_fields == ["future_brain_field"]
    assert to_handoff(envelope) == _payload()


def test_invalid_payload_type_is_rejected() -> None:
    for bad_payload, converter in (([], from_handoff), ("text", from_handoff)):
        try:
            converter(bad_payload)
        except TypeError:
            continue
        raise AssertionError(f"expected TypeError for {bad_payload!r}")


def test_string_typed_numeric_fields_are_coerced() -> None:
    payload = _payload()
    payload["attackerPort"] = "4444"
    payload["brainIntelligence"]["discoveredServices"][3]["port"] = "445"
    payload["brainIntelligence"]["attackVectors"][1]["priority"] = "100"

    envelope = from_handoff(payload)

    assert envelope.attacker_port == 4444
    assert envelope.brain_intelligence.discovered_services[3].port == 445
    assert envelope.brain_intelligence.attack_vectors[1].priority == 100


def test_unparseable_numeric_values_fail_at_ingress() -> None:
    with pytest.raises(ValueError, match="attacker_port"):
        from_handoff({"attackerPort": "not-a-port"})

    payload = _payload()
    payload["brainIntelligence"]["discoveredServices"][0]["port"] = "abc"
    with pytest.raises(ValueError, match="discovered_services"):
        from_handoff(payload)


def test_explicit_null_wire_values_round_trip() -> None:
    payload = _payload()
    exploits = payload["brainIntelligence"]["vulnerabilities"][0]["availableExploits"]
    exploits[0]["module"] = None
    payload["brainIntelligence"]["targetIntelligence"]["techStack"]["extra"] = None

    assert to_handoff(from_handoff(payload)) == payload
