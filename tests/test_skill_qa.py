"""Tests for the ported skill QA harness (``agentx.skills.qa``)."""

from __future__ import annotations

import json
import math
import sys
from collections import Counter
from pathlib import Path

import pytest

from agentx.skills.qa import collisions, frontmatter, index, lint, rules
from agentx.skills.qa.__main__ import _configure_stdout, main

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO_ROOT / "skills"

GOOD_DESC = (
    "Use when testing this skill against an authorized target. Do not use for anything else."
)


def _write_skill(
    root: Path,
    slug: str,
    *,
    description: str = GOOD_DESC,
    name: str | None = None,
    body: str = "Body.\n",
    extra: str = "",
) -> Path:
    skill_dir = root / slug
    skill_dir.mkdir(parents=True, exist_ok=True)
    text = (
        "---\n"
        f"name: {name if name is not None else slug}\n"
        f"description: {json.dumps(description)}\n"
        f"{extra}"
        "---\n\n"
        f"{body}"
    )
    (skill_dir / "SKILL.md").write_text(text, encoding="utf-8")
    return skill_dir


class TestFrontmatter:
    def test_plain_scalar(self):
        assert frontmatter.parse("---\nname: alpha\n---\nbody")["name"] == "alpha"

    def test_folded_scalar(self):
        text = "---\ndescription: >\n  Use when one\n  two.\n---\nbody"
        assert frontmatter.parse(text)["description"] == "Use when one two."

    def test_literal_scalar_keeps_newlines(self):
        text = "---\ndescription: |\n  line one\n  line two\n---\n"
        assert frontmatter.parse(text)["description"] == "line one\nline two"

    def test_single_quoted_multiline(self):
        text = "---\ndescription: 'Use when one\n  two.'\n---\n"
        assert frontmatter.parse(text)["description"] == "Use when one two."

    def test_crlf_and_bom(self):
        text = "\ufeff---\r\nname: alpha\r\n---\r\nbody"
        assert frontmatter.parse(text)["name"] == "alpha"

    def test_comment_only_block_is_empty(self):
        assert frontmatter.parse("---\n# nothing\n---\n") == {}

    def test_missing_block_raises(self):
        with pytest.raises(frontmatter.FrontmatterError, match="no YAML frontmatter"):
            frontmatter.parse("just a body")

    def test_invalid_yaml_raises(self):
        with pytest.raises(frontmatter.FrontmatterError, match="invalid YAML"):
            frontmatter.parse("---\nname: [unclosed\n---\n")

    def test_non_mapping_raises(self):
        with pytest.raises(frontmatter.FrontmatterError, match="must be a mapping"):
            frontmatter.parse("---\n- one\n- two\n---\n")

    def test_non_utf8_raises(self, tmp_path):
        path = tmp_path / "SKILL.md"
        path.write_bytes(b"---\nname: \xff\n---\n")
        with pytest.raises(frontmatter.FrontmatterError, match="not valid UTF-8"):
            frontmatter.load_frontmatter(path)

    def test_description_of_normalizes_whitespace(self):
        assert frontmatter.description_of({"description": "a\n\n  b\tc"}) == "a b c"
        assert frontmatter.description_of({}) == ""

    def test_body_of(self):
        assert frontmatter.body_of("---\nname: a\n---\n\nBody\n") == "\nBody\n"
        assert frontmatter.body_of("no frontmatter") == "no frontmatter"

    def test_iter_skill_dirs_filters(self, tmp_path):
        _write_skill(tmp_path, "alpha")
        _write_skill(tmp_path, "alpha.bak")
        (tmp_path / "not-a-skill").mkdir()
        (tmp_path / "plain-file").write_text("x", encoding="utf-8")
        assert [slug for slug, _ in frontmatter.iter_skill_dirs(tmp_path)] == ["alpha"]

    def test_iter_skill_dirs_missing_root(self, tmp_path):
        assert list(frontmatter.iter_skill_dirs(tmp_path / "missing")) == []

    def test_load_all_reports_errors(self, tmp_path):
        _write_skill(tmp_path, "alpha")
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")
        loaded, errors = frontmatter.load_all(tmp_path)
        assert set(loaded) == {"alpha"}
        assert set(errors) == {"broken"}


class TestRules:
    @pytest.mark.parametrize(
        ("metadata", "needle"),
        [
            ({"description": GOOD_DESC}, "name"),
            ({"name": "Bad_Name", "description": GOOD_DESC}, "kebab"),
            ({"name": "other", "description": GOOD_DESC}, "directory"),
            ({"name": "x" * 65, "description": GOOD_DESC}, "too long"),
            ({"name": "s"}, "description"),
            ({"name": "s", "description": "   "}, "empty"),
            ({"name": "s", "description": "short"}, "too short"),
            ({"name": "s", "description": "x" * 4100}, "too long"),
            ({"name": "s", "description": GOOD_DESC, "category": "nope"}, "category"),
            ({"name": "s", "description": GOOD_DESC, "version": ["1"]}, "version"),
            ({"name": "s", "description": GOOD_DESC, "tags": "x"}, "tags"),
            ({"name": "s", "description": GOOD_DESC, "tags": []}, "tags"),
            ({"name": "s", "description": GOOD_DESC, "tags": [{}]}, "tags"),
            ({"name": "s", "description": GOOD_DESC, "mitre_attack": ["T1"]}, "MITRE"),
            ({"name": "s", "description": GOOD_DESC, "mitre_attack": ["T1059.1"]}, "MITRE"),
            ({"name": "s", "description": GOOD_DESC, "mitre_attack": "T1059"}, "mitre_attack"),
            ({"name": "s", "description": GOOD_DESC, "sources": 5}, "sources"),
        ],
    )
    def test_errors(self, metadata, needle):
        result = rules.validate_skill("s", metadata)
        assert not result.ok
        assert any(needle in error for error in result.errors), result.errors

    def test_valid_metadata(self):
        result = rules.validate_skill(
            "s",
            {
                "name": "s",
                "description": GOOD_DESC,
                "category": "hunting",
                "tags": ["a", "b"],
                "mitre_attack": ["T1059", "T1059.001"],
                "version": "1.0.0",
                "sources": "unit-test",
            },
        )
        assert result.ok, result.errors
        assert result.warnings == []

    def test_warnings_do_not_fail(self):
        result = rules.validate_skill(
            "s",
            {"name": "s", "description": GOOD_DESC + " <script>", "mystery": True},
        )
        assert result.ok
        assert any("unknown" in warning for warning in result.warnings)
        assert any("angle" in warning for warning in result.warnings)


class TestLint:
    def test_clean_skill(self, tmp_path):
        _write_skill(tmp_path, "alpha")
        assert lint.check_skill("alpha", tmp_path / "alpha") == {}

    def test_name_mismatch(self, tmp_path):
        _write_skill(tmp_path, "alpha", name="beta")
        assert "name-matches-folder" in lint.check_skill("alpha", tmp_path / "alpha")

    def test_description_rules(self, tmp_path):
        _write_skill(
            tmp_path,
            "alpha",
            description="no punctuation and no trigger phrases whatsoever here",
        )
        found = lint.check_skill("alpha", tmp_path / "alpha")
        assert "desc-ends-punctuation" in found
        assert "desc-has-use-when" in found
        assert "desc-has-negative-trigger" in found

    def test_max_length(self, tmp_path):
        _write_skill(tmp_path, "alpha", description="Use when testing. " + "x" * 1100 + ".")
        assert "desc-max-length" in lint.check_skill("alpha", tmp_path / "alpha")

    def test_body_max_lines(self, tmp_path):
        _write_skill(tmp_path, "alpha", body="x\n" * 600)
        assert "body-max-lines" in lint.check_skill("alpha", tmp_path / "alpha")

    def test_unparseable(self, tmp_path):
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")
        assert "unparseable-frontmatter" in lint.check_skill("broken", tmp_path / "broken")

    def test_baseline_roundtrip_and_ratchet(self, tmp_path):
        baseline_path = tmp_path / "baseline.json"
        _write_skill(tmp_path, "alpha", description="short")
        violations = lint.collect(tmp_path)
        written = lint.write_baseline(violations, baseline_path)
        assert lint.load_baseline(baseline_path) == written
        assert json.loads(baseline_path.read_text(encoding="utf-8"))["_total_grandfathered"] > 0

        new, grandfathered, stale = lint.compare(violations, lint.load_baseline(baseline_path))
        assert new == []
        assert grandfathered > 0
        assert stale == []

        _write_skill(tmp_path, "alpha")  # fixed
        new, _, stale = lint.compare(lint.collect(tmp_path), lint.load_baseline(baseline_path))
        assert new == []
        assert stale

        _write_skill(tmp_path, "beta", description="short")
        new, _, _ = lint.compare(lint.collect(tmp_path), lint.load_baseline(baseline_path))
        assert new

    def test_missing_baseline_is_empty(self, tmp_path):
        assert lint.load_baseline(tmp_path / "missing.json") == {}


class TestCollisions:
    def test_tokenize_drops_stopwords(self):
        assert collisions.tokenize("Use the security skill when detecting alpha") == Counter(
            {"alpha": 1}
        )

    def test_strip_disambiguation(self):
        text = "Core text. Do not use for X - use other-skill."
        assert collisions.strip_disambiguation(text).strip() == "Core text."

    def test_build_vectors_normalizes(self):
        vectors = collisions.build_vectors(
            {"a-b": "alpha bravo charlie delta", "z": "uniform victor whiskey xray"}
        )
        norm = math.sqrt(sum(weight * weight for weight in vectors["a-b"].values()))
        assert norm == pytest.approx(1.0)

    def test_score_pairs_identical(self):
        description = "alpha bravo charlie delta echo"
        vectors = collisions.build_vectors(
            {"a-b": description, "a-c": description, "z": "uniform victor whiskey xray"}
        )
        pairs = collisions.score_pairs(vectors, 0.5)
        assert len(pairs) == 1
        assert pairs[0][1:] == ("a-b", "a-c")

    def test_score_pairs_distinct(self):
        vectors = collisions.build_vectors({"x": "alpha bravo charlie", "y": "delta echo foxtrot"})
        assert collisions.score_pairs(vectors, 0.1) == []

    def test_score_pairs_skips_background_terms(self, monkeypatch):
        monkeypatch.setattr(collisions, "MAX_DOCS_PER_TERM", 1)
        vectors = {"a": {"shared": 1.0}, "b": {"shared": 1.0}, "c": {"other": 1.0}}
        assert collisions.score_pairs(vectors, 0.1) == []

    def test_load_allowlist_forms(self, tmp_path):
        dict_form = tmp_path / "dict.json"
        dict_form.write_text(
            json.dumps({"reviewed_distinct": [{"pair": ["b", "a"], "reason": "why"}]}),
            encoding="utf-8",
        )
        assert collisions.load_allowlist(dict_form) == {("a", "b"): "why"}

        list_form = tmp_path / "list.json"
        list_form.write_text(json.dumps([["d", "c"]]), encoding="utf-8")
        assert collisions.load_allowlist(list_form) == {("c", "d"): ""}

        assert collisions.load_allowlist(tmp_path / "missing.json") == {}

    def test_run_with_allowlist_and_parse_error(self, tmp_path):
        description = "Use when testing alpha bravo charlie delta echo."
        _write_skill(tmp_path, "a-b", description=description)
        _write_skill(tmp_path, "a-c", description=description)
        _write_skill(tmp_path, "z", description="uniform victor whiskey xray")
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")

        unreviewed, reviewed = collisions.run(tmp_path, 0.3, tmp_path / "none.json")
        assert len(unreviewed) == 1
        assert reviewed == []

        allow = tmp_path / "allow.json"
        allow.write_text(
            json.dumps({"reviewed_distinct": [{"pair": ["a-b", "a-c"], "reason": "distinct"}]}),
            encoding="utf-8",
        )
        unreviewed, reviewed = collisions.run(tmp_path, 0.3, allow)
        assert unreviewed == []
        assert reviewed[0][3] == "distinct"


class TestIndex:
    def test_build_write_check(self, tmp_path):
        _write_skill(
            tmp_path,
            "alpha",
            extra="category: hunting\ntags:\n  - one\nmitre_attack:\n  - T1059\n",
        )
        payload = index.build_index(tmp_path)
        assert payload["schema_version"] == index.SCHEMA_VERSION
        assert payload["total_skills"] == 1
        entry = payload["skills"][0]
        assert entry["name"] == "alpha"
        assert entry["category"] == "hunting"
        assert entry["path"] == f"{tmp_path.name}/alpha"
        assert entry["tags"] == ["one"]
        assert entry["mitre_attack"] == ["T1059"]
        assert entry["body_lines"] >= 1

        target = tmp_path / "index.json"
        document = index.write_index(tmp_path, target)
        assert document["total_skills"] == 1
        ok, _ = index.check_index(tmp_path, target)
        assert ok

        _write_skill(tmp_path, "beta")
        ok, message = index.check_index(tmp_path, target)
        assert not ok
        assert "stale" in message

        ok, message = index.check_index(tmp_path, tmp_path / "missing.json")
        assert not ok
        assert "does not exist" in message

    def test_unknown_category_is_null(self, tmp_path):
        _write_skill(tmp_path, "alpha", extra="category: made-up\n")
        assert index.build_index(tmp_path)["skills"][0]["category"] is None


class TestCli:
    def test_validate_ok(self, tmp_path, capsys):
        _write_skill(tmp_path, "alpha")
        assert main(["--skills-dir", str(tmp_path), "validate"]) == 0
        assert "0 errors" in capsys.readouterr().out

    def test_validate_error(self, tmp_path):
        _write_skill(tmp_path, "alpha", name="beta")
        assert main(["--skills-dir", str(tmp_path), "validate"]) == 1

    def test_lint_baseline_flow(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        _write_skill(tmp_path, "alpha", description="short")
        assert (
            main(
                [
                    "--skills-dir",
                    str(tmp_path),
                    "lint",
                    "--baseline",
                    str(baseline),
                    "--update-baseline",
                ]
            )
            == 0
        )
        assert baseline.is_file()
        assert main(["--skills-dir", str(tmp_path), "lint", "--baseline", str(baseline)]) == 0
        _write_skill(tmp_path, "beta", description="short")
        assert main(["--skills-dir", str(tmp_path), "lint", "--baseline", str(baseline)]) == 1

    def test_collisions_gate(self, tmp_path, capsys):
        description = "Use when testing alpha bravo charlie delta echo."
        _write_skill(tmp_path, "a-b", description=description)
        _write_skill(tmp_path, "a-c", description=description)
        _write_skill(tmp_path, "z", description="uniform victor whiskey xray")
        allow = tmp_path / "allow.json"
        base = ["--skills-dir", str(tmp_path), "collisions", "--threshold", "0.3"]
        assert main([*base, "--allowlist", str(allow)]) == 1
        assert main([*base, "--allowlist", str(allow), "--max-unreviewed", "1"]) == 0
        assert main([*base, "--allowlist", str(allow), "--json"]) == 1

        allow.write_text(
            json.dumps({"reviewed_distinct": [{"pair": ["a-b", "a-c"], "reason": "distinct"}]}),
            encoding="utf-8",
        )
        capsys.readouterr()
        assert main([*base, "--allowlist", str(allow)]) == 0
        assert "reviewed" in capsys.readouterr().out

    def test_index_cli(self, tmp_path):
        _write_skill(tmp_path, "alpha")
        target = tmp_path / "index.json"
        assert main(["--skills-dir", str(tmp_path), "index", "--index", str(target)]) == 0
        assert (
            main(["--skills-dir", str(tmp_path), "index", "--index", str(target), "--check"]) == 0
        )
        missing = tmp_path / "missing.json"
        assert (
            main(["--skills-dir", str(tmp_path), "index", "--index", str(missing), "--check"]) == 1
        )

    def test_all_cli(self, tmp_path):
        _write_skill(tmp_path, "alpha")
        target = tmp_path / "index.json"
        layer = tmp_path / "mappings" / "attack-navigator-layer.json"
        coverage = tmp_path / "ATTACK_COVERAGE.md"
        main(["--skills-dir", str(tmp_path), "index", "--index", str(target)])
        main(
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
        assert (
            main(
                [
                    "--skills-dir",
                    str(tmp_path),
                    "all",
                    "--baseline",
                    str(tmp_path / "baseline.json"),
                    "--allowlist",
                    str(tmp_path / "allow.json"),
                    "--threshold",
                    "0.3",
                    "--index",
                    str(target),
                    "--layer",
                    str(layer),
                    "--coverage",
                    str(coverage),
                ]
            )
            == 0
        )

    def test_validate_reports_parse_errors_and_warnings(self, tmp_path, capsys):
        (tmp_path / "broken").mkdir()
        (tmp_path / "broken" / "SKILL.md").write_text("no frontmatter", encoding="utf-8")
        _write_skill(tmp_path, "alpha", extra="mystery: true\n")
        assert main(["--skills-dir", str(tmp_path), "validate"]) == 1
        out = capsys.readouterr().out
        assert "ERROR  broken" in out
        assert "WARN   alpha" in out

    def test_lint_reports_stale(self, tmp_path, capsys):
        baseline = tmp_path / "baseline.json"
        _write_skill(tmp_path, "alpha", description="short")
        main(
            [
                "--skills-dir",
                str(tmp_path),
                "lint",
                "--baseline",
                str(baseline),
                "--update-baseline",
            ]
        )
        _write_skill(tmp_path, "alpha")
        capsys.readouterr()
        assert main(["--skills-dir", str(tmp_path), "lint", "--baseline", str(baseline)]) == 0
        assert "STALE" in capsys.readouterr().out

    def test_configure_stdout_tolerates_missing_and_errors(self, monkeypatch):
        class Exploding:
            def reconfigure(self, **kwargs):
                raise ValueError

        monkeypatch.setattr(sys, "stdout", object())
        monkeypatch.setattr(sys, "stderr", Exploding())
        _configure_stdout()


class TestRealSkills:
    def test_parse_and_validate(self):
        loaded, errors = frontmatter.load_all(SKILLS_DIR)
        assert errors == {}
        assert len(loaded) >= 70
        for slug, metadata in loaded.items():
            result = rules.validate_skill(slug, metadata)
            assert result.ok, (slug, result.errors)

    def test_no_new_lint_failures(self):
        baseline = lint.load_baseline(REPO_ROOT / ".qa" / "lint-baseline.json")
        new, grandfathered, stale = lint.compare(lint.collect(SKILLS_DIR), baseline)
        assert new == []
        assert grandfathered > 0
        assert stale == []

    def test_no_unreviewed_collisions(self):
        unreviewed, _ = collisions.run(
            SKILLS_DIR, 0.30, REPO_ROOT / ".qa" / "collision-allowlist.json"
        )
        assert unreviewed == []

    def test_index_is_current(self):
        ok, message = index.check_index(SKILLS_DIR, SKILLS_DIR / "index.json")
        assert ok, message
