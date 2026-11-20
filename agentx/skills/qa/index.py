"""Generate a machine-readable index of every installed skill.

The agent, the planner and external tooling (docs, editors, dashboards) all
need the same list: name, description, category, provenance. Deriving it on the
fly means each consumer parses 70 YAML files differently; a generated index is
one artifact with one contract, and ``--check`` keeps it honest in CI.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agentx.skills.qa.frontmatter import body_of, description_of, iter_skill_dirs, load_frontmatter
from agentx.skills.qa.rules import ALLOWED_CATEGORIES

SCHEMA_VERSION = 1
DEFAULT_INDEX = "skills/index.json"

_ENTRY_FIELDS = (
    "name",
    "description",
    "category",
    "sources",
    "version",
    "tags",
    "mitre_attack",
    "triggers",
    "report_count",
)


def _entry(slug: str, skill_dir: Path, root_name: str) -> dict:
    frontmatter = load_frontmatter(skill_dir / "SKILL.md")
    category = frontmatter.get("category")
    entry: dict = {
        "name": str(frontmatter.get("name") or slug),
        "description": description_of(frontmatter),
        "category": str(category) if category in ALLOWED_CATEGORIES else None,
        "path": f"{root_name}/{slug}",
        "body_lines": len(
            body_of((skill_dir / "SKILL.md").read_text(encoding="utf-8")).splitlines()
        ),
    }
    for field in _ENTRY_FIELDS:
        if field in frontmatter and field not in entry:
            entry[field] = frontmatter[field]
    return entry


def build_index(skills_dir: str | Path = "skills") -> dict:
    """Build the index payload (without a timestamp)."""
    skills_dir = Path(skills_dir)
    root_name = skills_dir.resolve().name
    entries = [
        _entry(slug, skill_dir, root_name) for slug, skill_dir in iter_skill_dirs(skills_dir)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "total_skills": len(entries),
        "skills": entries,
    }


def write_index(
    skills_dir: str | Path = "skills",
    path: str | Path | None = None,
) -> dict:
    """Write the index to ``skills/index.json`` (or ``path``). Returns payload."""
    payload = build_index(skills_dir)
    target = Path(path) if path is not None else Path(skills_dir) / "index.json"
    document = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), **payload}
    target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return document


def check_index(
    skills_dir: str | Path = "skills",
    path: str | Path | None = None,
) -> tuple[bool, str]:
    """Return ``(is_current, message)`` comparing the on-disk index to reality."""
    target = Path(path) if path is not None else Path(skills_dir) / "index.json"
    if not target.is_file():
        return False, f"{target} does not exist (run: python -m agentx.skills.qa index)"

    on_disk = json.loads(target.read_text(encoding="utf-8"))
    expected = build_index(skills_dir)
    for key in ("schema_version", "total_skills", "skills"):
        if on_disk.get(key) != expected[key]:
            return False, (f"{target} is stale on {key!r} (run: python -m agentx.skills.qa index)")
    return True, f"{target} is current ({expected['total_skills']} skills)"
