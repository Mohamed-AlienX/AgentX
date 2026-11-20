"""Install AgentX skills into a host LLM agent's skill directory.

AgentX skills are plain ``SKILL.md`` playbooks, so any agent that speaks the
Agent Skills standard can use them without an API key: the host agent is the
LLM, AgentX only supplies the instructions. This module finds the skill
directories of the agents installed on the machine and copies the playbooks
into them.

Verified discovery locations (see ``KNOWN_TARGETS``):

* universal  -- ``~/.agents/skills`` is read by Codex, Gemini CLI, Copilot,
  Cursor and OpenCode (compatibility path).
* claude     -- ``~/.claude/skills``
* opencode   -- ``~/.config/opencode/skills``
* gemini     -- ``~/.gemini/skills``
* copilot    -- ``~/.copilot/skills``
* cursor     -- ``~/.cursor/skills``

Nothing is ever deleted: existing skill directories are overwritten in place
with ``dirs_exist_ok`` so a re-run is idempotent.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

UNIVERSAL_KEY = "universal"


@dataclass(frozen=True)
class Target:
    """One install destination for the skill playbooks."""

    key: str
    label: str
    path: Path
    #: Marker directory that proves the agent is installed (``None`` = always).
    probe: Path | None = None
    note: str = ""

    def exists(self) -> bool:
        return self.path.is_dir()

    def detected(self) -> bool:
        return self.probe is None or self.probe.exists()


@dataclass
class InstallReport:
    """Result of one install run against one destination."""

    target: Target
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    @property
    def installed(self) -> int:
        return len(self.created) + len(self.updated)

    @property
    def ok(self) -> bool:
        return not self.failed


def known_targets(home: Path | None = None, project: Path | None = None) -> list[Target]:
    """Return every supported destination, detected or not.

    ``project`` adds project-scoped targets rooted at that directory; pass
    ``None`` to list only user-level locations.
    """
    home = Path.home() if home is None else home
    targets = [
        Target(
            key=UNIVERSAL_KEY,
            label="Any agent (shared standard location)",
            path=home / ".agents" / "skills",
            probe=None,
            note="read by Codex, Gemini CLI, Copilot, Cursor and OpenCode",
        ),
        Target(
            key="claude",
            label="Claude Code",
            path=home / ".claude" / "skills",
            probe=home / ".claude",
        ),
        Target(
            key="opencode",
            label="OpenCode",
            path=home / ".config" / "opencode" / "skills",
            probe=home / ".config" / "opencode",
        ),
        Target(
            key="gemini",
            label="Gemini CLI",
            path=home / ".gemini" / "skills",
            probe=home / ".gemini",
        ),
        Target(
            key="copilot",
            label="GitHub Copilot CLI",
            path=home / ".copilot" / "skills",
            probe=home / ".copilot",
        ),
        Target(
            key="cursor",
            label="Cursor",
            path=home / ".cursor" / "skills",
            probe=home / ".cursor",
        ),
    ]
    if project is not None:
        project = Path(project)
        targets.extend(
            [
                Target(
                    key="project",
                    label="Any agent (project scope)",
                    path=project / ".agents" / "skills",
                    probe=None,
                    note="committed with the repository",
                ),
                Target(
                    key="project-claude",
                    label="Claude Code (project)",
                    path=project / ".claude" / "skills",
                    probe=None,
                ),
                Target(
                    key="project-opencode",
                    label="OpenCode (project)",
                    path=project / ".opencode" / "skills",
                    probe=None,
                ),
                Target(
                    key="project-gemini",
                    label="Gemini CLI (project)",
                    path=project / ".gemini" / "skills",
                    probe=None,
                ),
                Target(
                    key="project-copilot",
                    label="Copilot (project)",
                    path=project / ".github" / "skills",
                    probe=None,
                ),
                Target(
                    key="project-cursor",
                    label="Cursor (project)",
                    path=project / ".cursor" / "skills",
                    probe=None,
                ),
            ]
        )
    return targets


def detect_targets(home: Path | None = None, project: Path | None = None) -> list[Target]:
    """Return the destinations whose agent is actually installed."""
    return [t for t in known_targets(home, project) if t.detected()]


def find_target(key: str, home: Path | None = None, project: Path | None = None) -> Target:
    """Look up a known destination by key."""
    for target in known_targets(home, project):
        if target.key == key:
            return target
    known = ", ".join(t.key for t in known_targets(home, project))
    raise KeyError(f"unknown target {key!r}; known: {known}")


def skill_dirs(skills_dir: Path) -> list[Path]:
    """Return skill directories (those containing ``SKILL.md``), sorted by name."""
    root = Path(skills_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"skills directory not found: {root}")
    return sorted(
        (p for p in root.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()),
        key=lambda p: p.name,
    )


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def install(
    skills_dir: Path,
    target: Target,
    *,
    only: set[str] | None = None,
    force: bool = True,
    dry_run: bool = False,
) -> InstallReport:
    """Copy every skill into ``target.path``.

    ``force=False`` keeps skill directories that already exist. Returns a
    report instead of raising so one bad skill cannot abort the whole run.
    """
    source = Path(skills_dir)
    if _is_inside(target.path, source):
        raise ValueError(f"refusing to install into the source tree: {target.path}")

    report = InstallReport(target=target)
    for skill in skill_dirs(source):
        if only and skill.name not in only:
            continue
        destination = target.path / skill.name
        existed = destination.exists()
        if existed and not force:
            report.kept.append(skill.name)
            continue
        if dry_run:
            (report.updated if existed else report.created).append(skill.name)
            continue
        try:
            target.path.mkdir(parents=True, exist_ok=True)
            shutil.copytree(skill, destination, dirs_exist_ok=True)
            if not (destination / "SKILL.md").is_file():
                raise OSError("SKILL.md missing after copy")
        except OSError as exc:  # pragma: no cover - filesystem specific
            report.failed.append((skill.name, str(exc)))
            continue
        (report.updated if existed else report.created).append(skill.name)
    return report


def install_all(
    skills_dir: Path,
    targets: list[Target],
    *,
    only: set[str] | None = None,
    force: bool = True,
    dry_run: bool = False,
) -> list[InstallReport]:
    """Install into every target; the first failure does not stop the rest."""
    return [
        install(skills_dir, target, only=only, force=force, dry_run=dry_run)
        for target in targets
    ]


def post_install_hint(target: Target, count: int) -> str:
    """Return a one-line, agent-specific activation hint."""
    hints = {
        "universal": "restart the agent and run its skills list (e.g. /skills, $skills).",
        "claude": "run /skills in Claude Code to confirm discovery.",
        "opencode": "skills load automatically; use @<skill-id> or the skill tool.",
        "gemini": "run `/skills list` in Gemini CLI to confirm discovery.",
        "copilot": "run `gh skill list` or ask Copilot which skills are available.",
        "cursor": "open Customize -> Skills in Cursor to confirm discovery.",
    }
    hint = hints.get(target.key, "restart the agent so it rescans its skills directory.")
    return f"{count} skills in {target.path} -- {hint}"
