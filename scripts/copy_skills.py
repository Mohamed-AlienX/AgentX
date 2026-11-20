"""Copy the core skill set into the AgentX skills directory.

Source default: ~/.claude/skills
Destination default: <project>/skills

Usage:
    python scripts/copy_skills.py [--source DIR] [--dest DIR] [--all]
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# Allow running from the repo without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentx.config import settings  # noqa: E402

DEFAULT_SOURCE = Path.home() / ".claude" / "skills"


def copy_skill(skill_dir: Path, dest_root: Path) -> str:
    """Copy a single skill directory. Returns status string."""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return "skip:no-skill-md"

    dest = dest_root / skill_dir.name
    dest.mkdir(parents=True, exist_ok=True)

    # Copy the whole skill directory (SKILL.md + referenced assets)
    for item in skill_dir.iterdir():
        target = dest / item.name
        if item.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)

    return "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy AgentX skills.")
    parser.add_argument(
        "--source", type=Path, default=DEFAULT_SOURCE, help="Source skills directory."
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=None,
        help="Destination skills directory (defaults to settings.skills_dir).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Copy every skill in the source, not just the configured set.",
    )
    args = parser.parse_args()

    source = args.source
    dest_root = args.dest or settings.skills_dir

    if not source.exists():
        print(f"Source directory not found: {source}")
        return 1

    dest_root.mkdir(parents=True, exist_ok=True)
    print(f"Source:      {source}")
    print(f"Destination: {dest_root}")

    if args.all:
        targets = [d.name for d in source.iterdir() if d.is_dir()]
    else:
        targets = list(settings.default_skills)

    ok, skipped, missing = 0, 0, 0
    for name in targets:
        skill_dir = source / name
        if not skill_dir.exists():
            print(f"  [missing] {name}")
            missing += 1
            continue
        status = copy_skill(skill_dir, dest_root)
        if status == "ok":
            print(f"  [ok]      {name}")
            ok += 1
        else:
            print(f"  [{status}] {name}")
            skipped += 1

    print(f"\nCopied: {ok}  Skipped: {skipped}  Missing: {missing}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
