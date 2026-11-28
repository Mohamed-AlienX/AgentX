"""Tests for the MITRE ATT&CK integration (catalog, mapping, artifacts, CLI)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentx import cli
from agentx.attack_lookup import AttackIndex, get_attack_index
from agentx.core.memory import Finding
from agentx.mitre import TACTICS, TECHNIQUES, tactic_name, technique_url
from agentx.mitre_annotate import (
    annotation_gaps,
    current_mitre,
    update_text,
)
from agentx.mitre_mapping import SKILL_MITRE, get_mitre_for_skill, mapped_skills
from agentx.mitre_navigator import (
    build_coverage_markdown,
    build_navigator_layer,
    check_artifacts,
    write_coverage_markdown,
    write_navigator_layer,
)
from agentx.reporting.generator import ReportGenerator
from agentx.skills.qa.__main__ import main as qa_main

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO_ROOT / "skills"


def _write_skill(root: Path, slug: str, frontmatter: str = "", body: str = "# Body\n") -> Path:
    skill_dir = root / slug
    skill_dir.mkdir(parents=True)
    target = skill_dir / "SKILL.md"
    target.write_text(f"---\n{frontmatter}---\n\n{body}", encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------


class TestCatalog:
    def test_every_technique_has_a_known_tactic(self):
        for tech_id, meta in TECHNIQUES.items():
            assert meta["tactic"] in TACTICS, tech_id
            assert meta["name"]
            assert meta["url"].startswith("https://attack.mitre.org/techniques/")

    def test_technique_ids_are_unique_and_well_formed(self):
        assert len(TECHNIQUES) == len(set(TECHNIQUES))
        for tech_id in TECHNIQUES:
            assert tech_id[0] == "T"
            assert tech_id[1:5].isdigit()
            if "." in tech_id:
                assert len(tech_id.split(".")[1]) == 3

    def test_helpers(self):
        assert technique_url("t1190") == "https://attack.mitre.org/techniques/T1190/"
        assert technique_url("T1059.007") == ("https://attack.mitre.org/techniques/T1059/007/")
        assert technique_url("T9999") == "https://attack.mitre.org/techniques/T9999/"
        assert tactic_name("TA0001") == "Initial Access"
        assert tactic_name("TA9999") == "TA9999"


# ---------------------------------------------------------------------------
# mapping
# ---------------------------------------------------------------------------


class TestMapping:
    def test_every_skill_has_a_reviewed_mapping(self):
        on_disk = {p.name for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file()}
        assert on_disk == set(SKILL_MITRE)

    def test_mapped_ids_exist_in_catalog(self):
        for skill, techs in SKILL_MITRE.items():
            for tech in techs:
                assert tech.upper() in TECHNIQUES, f"{skill} -> {tech}"

    def test_no_duplicates_and_uppercase(self):
        for skill, techs in SKILL_MITRE.items():
            assert len(techs) == len(set(techs)), skill
            assert all(t == t.upper() for t in techs), skill

    def test_process_only_skills_are_empty(self):
        assert get_mitre_for_skill("report-generator") == []
        assert "report-generator" not in mapped_skills()

    def test_frontmatter_matches_mapping(self):
        assert annotation_gaps(SKILLS_DIR) == []


# ---------------------------------------------------------------------------
# annotator
# ---------------------------------------------------------------------------


class TestAnnotator:
    def test_update_text_inserts_key_and_preserves_body(self):
        text = "---\nname: alpha\ndescription: d\n---\n\n# Title\n\nBody\n"
        updated = update_text(text, ["T1190", "T1059"])
        assert "mitre_attack: [T1190, T1059]" in updated
        assert updated.endswith("\n# Title\n\nBody\n")

    def test_update_text_is_idempotent(self):
        text = "---\nname: alpha\ndescription: d\n---\n\nBody\n"
        once = update_text(text, ["T1190"])
        assert update_text(once, ["T1190"]) == once

    def test_update_text_replaces_existing_flow_and_block_forms(self):
        flow = "---\nname: a\ndescription: d\nmitre_attack: [T1000]\n---\nBody\n"
        assert "mitre_attack: [T1190]" in update_text(flow, ["T1190"])
        assert "T1000" not in update_text(flow, ["T1190"])

        block = "---\nname: a\ndescription: d\nmitre_attack:\n  - T1000\n  - T1001\n---\nBody\n"
        updated = update_text(block, ["T1190"])
        assert "mitre_attack: [T1190]" in updated
        assert "T1001" not in updated

    def test_update_text_empty_list(self):
        text = "---\nname: a\ndescription: d\n---\nBody\n"
        assert "mitre_attack: []" in update_text(text, [])

    def test_update_text_requires_frontmatter(self):
        with pytest.raises(ValueError):
            update_text("no frontmatter", ["T1190"])

    def test_current_mitre(self):
        assert current_mitre("---\nmitre_attack: [T1190]\n---\n") == ["T1190"]
        assert current_mitre("---\nmitre_attack: []\n---\n") == []
        assert current_mitre("---\nname: a\n---\n") is None

    def test_annotation_gaps_detects_drift(self, tmp_path):
        _write_skill(tmp_path, "hunt-xss", "mitre_attack: [T1190]\n")
        # hunt-xss is mapped to more than T1190, so only drift is reported for it
        gaps = annotation_gaps(tmp_path)
        assert any(gap.startswith("hunt-xss:") for gap in gaps)

    def test_annotation_gaps_flags_unknown_skill(self, tmp_path):
        _write_skill(tmp_path, "not-a-skill", "name: not-a-skill\n")
        assert annotation_gaps(tmp_path) == ["not-a-skill: no reviewed mapping"]

    def test_annotation_gaps_skips_dirs_without_skill_file(self, tmp_path):
        (tmp_path / "empty").mkdir()
        assert annotation_gaps(tmp_path) == []

    def test_block_form_stops_at_next_key(self):
        text = "---\nmitre_attack:\n  - T1000\ntags: [a]\n---\nBody\n"
        updated = update_text(text, ["T1190"])
        assert "mitre_attack: [T1190]" in updated
        assert "tags: [a]" in updated
        assert "T1000" not in updated

    def test_scalar_form(self):
        text = "---\nmitre_attack: T1190\n---\n"
        assert current_mitre(text) == ["T1190"]

    def test_closing_delimiter_without_newline(self):
        assert current_mitre("---\nname: a\n---") is None
        assert "mitre_attack: [T1190]" in update_text("---\nname: a\n---", ["T1190"])

    def test_unterminated_frontmatter(self):
        assert current_mitre("---\nname: a\n") is None
        with pytest.raises(ValueError):
            update_text("---\nname: a\n", ["T1190"])

    def test_current_mitre_without_frontmatter(self):
        assert current_mitre("# no frontmatter\n") is None


class TestAnnotatorCli:
    @pytest.fixture()
    def mapping(self, monkeypatch):
        import agentx.mitre_annotate as mod

        table = {"hunt-xss": ["T1190"]}
        monkeypatch.setattr(mod, "SKILL_MITRE", table)
        monkeypatch.setattr(mod, "get_mitre_for_skill", lambda name: list(table.get(name, [])))
        return mod

    def test_check_clean(self, mapping, tmp_path, capsys):
        _write_skill(tmp_path, "hunt-xss", "mitre_attack: [T1190]\n")
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path), "--check") == 0
        assert "stale: 0" in capsys.readouterr().out

    def test_apply_then_check(self, mapping, tmp_path):
        target = _write_skill(tmp_path, "hunt-xss", "name: hunt-xss\n")
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path)) == 0
        assert "mitre_attack: [T1190]" in target.read_text(encoding="utf-8")
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path), "--check") == 0

    def test_check_reports_stale(self, mapping, tmp_path, capsys):
        _write_skill(tmp_path, "hunt-xss", "name: hunt-xss\n")
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path), "--check") == 1
        assert "stale:" in capsys.readouterr().out

    def test_unmapped_skill_on_disk(self, mapping, tmp_path, capsys):
        _write_skill(tmp_path, "hunt-xss", "mitre_attack: [T1190]\n")
        _write_skill(tmp_path, "extra", "name: extra\n")
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path)) == 1
        assert "skills without mapping" in capsys.readouterr().err

    def test_mapped_skill_missing_on_disk(self, mapping, tmp_path, capsys):
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path)) == 1
        assert "mapped but missing on disk" in capsys.readouterr().err

    def test_unknown_technique_in_mapping(self, mapping, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(mapping, "SKILL_MITRE", {"hunt-xss": ["T9999"]})
        assert _run_annotator(mapping, "--skills-dir", str(tmp_path)) == 1
        assert "unknown technique" in capsys.readouterr().err


def _run_annotator(module, *argv: str) -> int:
    import sys

    original = sys.argv
    sys.argv = ["annotate_mitre", *argv]
    try:
        return module.main()
    finally:
        sys.argv = original


# ---------------------------------------------------------------------------
# artifacts
# ---------------------------------------------------------------------------


class TestArtifacts:
    def test_navigator_layer_shape(self):
        layer = build_navigator_layer(SKILLS_DIR)
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["attack"]
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert ids == sorted(ids)
        for entry in layer["techniques"]:
            assert entry["techniqueID"] in TECHNIQUES
            assert entry["score"] == len(entry["metadata"][0]["value"].split(", "))
            assert entry["tactic"] == TECHNIQUES[entry["techniqueID"]]["tactic"]

    def test_coverage_markdown_lists_every_mapped_skill(self):
        content = build_coverage_markdown(SKILLS_DIR)
        assert "# MITRE ATT&CK Coverage" in content
        for skill in mapped_skills():
            assert skill in content
        assert "report-generator" in content.split("Unmapped")[1]

    def test_write_and_check_roundtrip(self, tmp_path):
        layer = tmp_path / "mappings" / "layer.json"
        coverage = tmp_path / "ATTACK_COVERAGE.md"
        write_navigator_layer(SKILLS_DIR, layer)
        write_coverage_markdown(SKILLS_DIR, coverage)
        assert check_artifacts(SKILLS_DIR, layer, coverage) == []

        layer.write_text(json.dumps({"techniques": []}), encoding="utf-8")
        problems = check_artifacts(SKILLS_DIR, layer, coverage)
        assert any("stale" in p for p in problems)

    def test_check_reports_missing_files(self, tmp_path):
        problems = check_artifacts(SKILLS_DIR, tmp_path / "nope.json", tmp_path / "nope.md")
        assert len(problems) == 2

    def test_committed_artifacts_are_current(self):
        assert (
            check_artifacts(
                SKILLS_DIR,
                REPO_ROOT / "mappings" / "attack-navigator-layer.json",
                REPO_ROOT / "ATTACK_COVERAGE.md",
            )
            == []
        )


# ---------------------------------------------------------------------------
# lookup index
# ---------------------------------------------------------------------------


class TestAttackIndex:
    @pytest.fixture()
    def index(self, tmp_path):
        _write_skill(tmp_path, "hunt-xss", "mitre_attack: [T1190, T1059.007]\n")
        _write_skill(tmp_path, "hunt-auth", "mitre_attack: [T1078]\n")
        _write_skill(tmp_path, "report", "mitre_attack: []\n")
        return AttackIndex(tmp_path)

    def test_techniques_for_skill(self, index):
        assert index.techniques_for_skill("hunt-xss") == ["T1190", "T1059.007"]
        assert index.techniques_for_skill("missing") == []

    def test_skills_for_technique(self, index):
        assert index.skills_for_technique("t1190") == ["hunt-xss"]
        assert index.skills_for_technique("T9999") == []

    def test_technique_info(self, index):
        info = index.technique("t1078")
        assert info is not None
        assert info.name == "Valid Accounts"
        assert info.tactic_name == "Initial Access"
        assert info.skills == ("hunt-auth",)
        assert index.technique("T9999") is None

    def test_by_tactic(self, index):
        rows = index.by_tactic("TA0001")
        assert {row.id for row in rows} == {"T1190", "T1078"}
        assert index.by_tactic("TA9999") == []

    def test_search(self, index):
        assert [r.id for r in index.search("xss")] == ["T1059.007", "T1190"]
        assert index.search("") == []
        assert index.search("nothing-here") == []

    def test_coverage_and_totals(self, index):
        coverage = index.coverage()
        assert set(coverage) == set(TACTICS)
        assert coverage["TA0001"]["covered"] == 2
        totals = index.totals()
        assert totals == {"skills": 3, "mapped_skills": 2, "techniques": 3}

    def test_repo_index(self):
        repo = get_attack_index(SKILLS_DIR)
        on_disk = sum(1 for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file())
        assert repo.totals()["skills"] == on_disk
        assert repo.totals()["mapped_skills"] >= 100
        assert repo.totals()["mapped_skills"] <= on_disk
        assert repo.techniques_for_skill("hunt-jwt-crypto") == [
            "T1550.001",
            "T1078",
            "T1556",
        ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run(*args: str):
    return CliRunner().invoke(cli.app, list(args))


class TestAttackCli:
    def test_summary(self):
        result = _run("attack")
        assert result.exit_code == 0
        assert "MITRE ATT&CK Coverage" in result.output
        totals = get_attack_index(SKILLS_DIR).totals()
        assert f"{totals['mapped_skills']}/{totals['skills']} skills mapped" in result.output

    def test_technique(self):
        result = _run("attack", "T1190")
        assert result.exit_code == 0
        assert "Exploit Public-Facing Application" in result.output
        assert "hunt-rce" in result.output

    def test_unknown_technique(self):
        result = _run("attack", "T9999")
        assert result.exit_code == 1
        assert "Unknown technique" in result.output

    def test_by_skill(self):
        result = _run("attack", "--skill", "hunt-jwt-crypto")
        assert result.exit_code == 0
        assert "T1550.001" in result.output

    def test_by_skill_unmapped(self):
        result = _run("attack", "--skill", "report-generator")
        assert result.exit_code == 1
        assert "No ATT&CK techniques" in result.output

    def test_by_tactic(self):
        result = _run("attack", "--tactic", "TA0006")
        assert result.exit_code == 0
        assert "Credential Access" in result.output

    def test_unknown_tactic(self):
        result = _run("attack", "--tactic", "TA9999")
        assert result.exit_code == 1

    def test_search(self):
        result = _run("attack", "--search", "jwt")
        assert result.exit_code == 0
        assert "hunt-jwt-crypto" in result.output

    def test_search_no_match(self):
        result = _run("attack", "--search", "zzzz-no-match")
        assert result.exit_code == 1

    def test_skills_info_shows_attack(self, monkeypatch):
        monkeypatch.setattr(
            cli,
            "skill_registry",
            type(
                "R",
                (),
                {
                    "load_skill_configs": lambda self: None,
                    "discover_skills": lambda self: {
                        "hunt-xss": {
                            "category": "hunting",
                            "description": "XSS",
                            "path": "p",
                            "mitre_attack": ["T1059.007"],
                        }
                    },
                    "is_enabled": lambda self, name: True,
                },
            )(),
        )
        result = _run("skills", "info", "hunt-xss")
        assert result.exit_code == 0
        assert "ATT&CK: T1059.007" in result.output


# ---------------------------------------------------------------------------
# QA gate
# ---------------------------------------------------------------------------


class TestQaGate:
    def test_unknown_mitre_id_fails_validate(self, tmp_path, capsys):
        _write_skill(
            tmp_path,
            "alpha",
            "name: alpha\ndescription: " + "x" * 60 + "\ncategory: recon\nmitre_attack: [T9999]\n",
        )
        assert qa_main(["--skills-dir", str(tmp_path), "validate"]) == 1
        assert "unknown MITRE technique" in capsys.readouterr().out

    def test_mappings_command_roundtrip(self, tmp_path):
        _write_skill(tmp_path, "hunt-xss", "mitre_attack: [T1190]\n")
        layer = tmp_path / "layer.json"
        coverage = tmp_path / "coverage.md"
        assert (
            qa_main(
                [
                    "--skills-dir",
                    str(tmp_path),
                    "mappings",
                    "--layer",
                    str(layer),
                    "--coverage",
                    str(coverage),
                ]
            )
            == 0
        )
        assert layer.is_file() and coverage.is_file()
        assert (
            qa_main(
                [
                    "--skills-dir",
                    str(tmp_path),
                    "mappings",
                    "--check",
                    "--layer",
                    str(layer),
                    "--coverage",
                    str(coverage),
                ]
            )
            == 0
        )

    def test_options_after_subcommand(self, tmp_path):
        _write_skill(tmp_path, "alpha", "name: alpha\n")
        assert qa_main(["validate", "--skills-dir", str(tmp_path)]) == 1  # missing fields
        out = qa_main(["index", "--skills-dir", str(tmp_path), "--index", str(tmp_path / "i.json")])
        assert out == 0


# ---------------------------------------------------------------------------
# reporting + planner
# ---------------------------------------------------------------------------


class TestSurfacing:
    def _finding(self) -> Finding:
        return Finding(
            id="f1",
            session_id="s1",
            skill_name="hunt-jwt-crypto",
            title="JWT forgery",
            severity="CRITICAL",
            endpoint="https://target/api",
            description="d",
            impact="i",
            steps_to_reproduce=["step"],
            evidence={"http_response": 'HTTP/1.1 200 OK\\n{"alg":"none"}'},
        )

    def test_markdown_report_has_attack_links(self):
        md = ReportGenerator().generate([self._finding()], fmt="markdown")
        assert "**ATT&CK:**" in md
        assert "https://attack.mitre.org/techniques/T1550/001/" in md

    def test_html_report_has_attack(self):
        html = ReportGenerator().generate([self._finding()], fmt="html")
        assert "ATT&amp;CK:" in html
        assert "T1550.001" in html

    def test_json_report_has_attack(self):
        payload = json.loads(ReportGenerator().generate([self._finding()], fmt="json"))
        assert payload["findings"][0]["mitre_attack"] == [
            "T1550.001",
            "T1078",
            "T1556",
        ]

    def test_report_without_mapping_omits_attack(self):
        finding = self._finding()
        finding.skill_name = "report-generator"
        md = ReportGenerator().generate([finding], fmt="markdown")
        assert "ATT&CK" not in md
