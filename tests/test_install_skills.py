"""Tests for ``agentx.skills.install`` — the no-API-key host-agent path."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentx.skills.install import (
    Target,
    detect_targets,
    find_target,
    install,
    install_all,
    known_targets,
    post_install_hint,
    skill_dirs,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _make_skill(root: Path, slug: str, body: str = "Body.\n") -> Path:
    skill_dir = root / slug
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {slug}\ndescription: Use when testing {slug}.\n---\n\n{body}",
        encoding="utf-8",
    )
    return skill_dir


def _make_source(root: Path, slugs: tuple[str, ...] = ("alpha", "beta")) -> Path:
    source = root / "skills"
    source.mkdir(parents=True, exist_ok=True)
    for slug in slugs:
        _make_skill(source, slug)
    return source


def _target(path: Path, key: str = "custom") -> Target:
    return Target(key=key, label=f"Custom ({path.name})", path=path, probe=None)


class TestTargets:
    def test_known_targets_include_every_agent(self, tmp_path: Path):
        keys = {t.key for t in known_targets(home=tmp_path)}
        assert {"universal", "claude", "opencode", "gemini", "copilot", "cursor"} <= keys

    def test_universal_is_always_detected(self, tmp_path: Path):
        universal = find_target("universal", home=tmp_path)
        assert universal.probe is None
        assert universal.detected() is True

    def test_undetected_agent_is_excluded(self, tmp_path: Path):
        assert [t.key for t in detect_targets(home=tmp_path)] == ["universal"]

    def test_probe_dir_enables_detection(self, tmp_path: Path):
        (tmp_path / ".claude").mkdir()
        keys = {t.key for t in detect_targets(home=tmp_path)}
        assert "claude" in keys

    def test_project_targets_are_scoped_to_project(self, tmp_path: Path):
        project = tmp_path / "repo"
        keys = {t.key for t in known_targets(home=tmp_path, project=project)}
        assert "project-opencode" in keys
        target = find_target("project-opencode", home=tmp_path, project=project)
        assert target.path == project / ".opencode" / "skills"

    def test_project_targets_absent_by_default(self, tmp_path: Path):
        assert "project" not in {t.key for t in known_targets(home=tmp_path)}

    def test_unknown_key_lists_known_keys(self, tmp_path: Path):
        with pytest.raises(KeyError, match="unknown target"):
            find_target("nope", home=tmp_path)


class TestSkillDirs:
    def test_returns_only_dirs_with_skill_md(self, tmp_path: Path):
        source = _make_source(tmp_path)
        (source / "no-skill-md").mkdir()
        assert [p.name for p in skill_dirs(source)] == ["alpha", "beta"]

    def test_missing_source_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            skill_dirs(tmp_path / "absent")


class TestInstall:
    def test_copies_every_skill(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        report = install(source, _target(dest))
        assert report.created == ["alpha", "beta"]
        assert report.updated == []
        assert report.ok is True
        assert (dest / "alpha" / "SKILL.md").is_file()

    def test_copies_nested_references(self, tmp_path: Path):
        source = _make_source(tmp_path, ("alpha",))
        refs = source / "alpha" / "references"
        refs.mkdir()
        (refs / "01-deep.md").write_text("deep\n", encoding="utf-8")
        dest = tmp_path / "dest"
        install(source, _target(dest))
        assert (dest / "alpha" / "references" / "01-deep.md").is_file()

    def test_rerun_is_idempotent(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        install(source, _target(dest))
        report = install(source, _target(dest))
        assert report.created == []
        assert report.updated == ["alpha", "beta"]

    def test_force_false_keeps_existing(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        _make_skill(dest, "alpha", body="local edit\n")
        report = install(source, _target(dest), force=False)
        assert report.kept == ["alpha"]
        assert report.created == ["beta"]
        assert "local edit" in (dest / "alpha" / "SKILL.md").read_text(encoding="utf-8")

    def test_force_true_overwrites(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        _make_skill(dest, "alpha", body="local edit\n")
        install(source, _target(dest))
        assert "local edit" not in (dest / "alpha" / "SKILL.md").read_text(encoding="utf-8")

    def test_only_limits_the_set(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        report = install(source, _target(dest), only={"beta"})
        assert report.created == ["beta"]
        assert not (dest / "alpha").exists()

    def test_dry_run_writes_nothing(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        report = install(source, _target(dest), dry_run=True)
        assert report.created == ["alpha", "beta"]
        assert not dest.exists()

    def test_dry_run_marks_existing_as_updated(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        _make_skill(dest, "alpha")
        report = install(source, _target(dest), dry_run=True)
        assert report.updated == ["alpha"]
        assert report.created == ["beta"]

    def test_refuses_destination_inside_source(self, tmp_path: Path):
        source = _make_source(tmp_path)
        with pytest.raises(ValueError, match="refusing to install into the source tree"):
            install(source, _target(source / "nested"))

    def test_refuses_source_itself(self, tmp_path: Path):
        source = _make_source(tmp_path)
        with pytest.raises(ValueError, match="refusing to install into the source tree"):
            install(source, _target(source))

    def test_installed_count(self, tmp_path: Path):
        source = _make_source(tmp_path)
        dest = tmp_path / "dest"
        report = install(source, _target(dest))
        assert report.installed == 2


class TestInstallAll:
    def test_installs_into_every_target(self, tmp_path: Path):
        source = _make_source(tmp_path)
        targets = [_target(tmp_path / "one", "one"), _target(tmp_path / "two", "two")]
        reports = install_all(source, targets)
        assert [len(r.created) for r in reports] == [2, 2]
        assert (tmp_path / "one" / "alpha" / "SKILL.md").is_file()
        assert (tmp_path / "two" / "beta" / "SKILL.md").is_file()

    def test_empty_target_list(self, tmp_path: Path):
        source = _make_source(tmp_path)
        assert install_all(source, []) == []


class TestHints:
    @pytest.mark.parametrize(
        "key", ["universal", "claude", "opencode", "gemini", "copilot", "cursor"]
    )
    def test_known_keys_get_a_hint(self, key: str):
        hint = post_install_hint(_target(Path("x"), key), 3)
        assert "3 skills" in hint

    def test_unknown_key_falls_back(self):
        assert "restart" in post_install_hint(_target(Path("x"), "weird"), 1)


class TestScript:
    @staticmethod
    def _load():
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "install_to_agents", SCRIPTS / "install_to_agents.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_list_exits_zero(self, capsys: pytest.CaptureFixture[str]):
        assert self._load().main(["--list"]) == 0
        assert "universal" in capsys.readouterr().out

    def test_dry_run_against_real_skills(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        module = self._load()
        dest = tmp_path / "agent-skills"
        assert module.main(["--target", str(dest), "--dry-run"]) == 0
        assert not dest.exists()
        assert "new:" in capsys.readouterr().out

    def test_real_install_into_temp_dir(self, tmp_path: Path):
        module = self._load()
        dest = tmp_path / "agent-skills"
        assert module.main(["--target", str(dest), "--only", "hunt-xss"]) == 0
        assert (dest / "hunt-xss" / "SKILL.md").is_file()
