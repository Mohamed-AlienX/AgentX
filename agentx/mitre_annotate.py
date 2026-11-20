"""Read/write ``mitre_attack`` frontmatter from the reviewed skill mapping.

Idempotent: touches only the ``mitre_attack`` key, leaving the rest of the
frontmatter and body byte-for-byte unchanged.

Library functions are used by tests and the ``scripts/annotate_mitre.py``
wrapper (``--check`` fails CI when a skill drifts from the mapping).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentx.mitre import TECHNIQUES
from agentx.mitre_mapping import SKILL_MITRE, get_mitre_for_skill

KEY = "mitre_attack"


def _format_line(techs: list[str]) -> str:
    if not techs:
        return f"{KEY}: []"
    return f"{KEY}: [{', '.join(techs)}]"


def _split_frontmatter(text: str) -> tuple[list[str], list[str]] | None:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            return lines[1:idx], lines[idx:]
    return None


def _strip_key(front: list[str]) -> list[str]:
    out: list[str] = []
    skipping_block = False
    for line in front:
        stripped = line.strip()
        if stripped.startswith(f"{KEY}:"):
            skipping_block = not stripped.endswith(("]", "[]"))
            continue
        if skipping_block:
            if stripped.startswith("- ") or not stripped:
                continue
            skipping_block = False
        out.append(line)
    return out


def update_text(text: str, techs: list[str]) -> str:
    if text.startswith("\ufeff"):
        text = text[1:]
    parts = _split_frontmatter(text)
    if parts is None:
        raise ValueError("missing YAML frontmatter")
    front, rest = parts
    front = _strip_key(front)
    if front and not front[-1].endswith("\n"):
        front[-1] += "\n"
    front.append(_format_line(techs) + "\n")
    if rest and not rest[0].endswith("\n"):
        rest[0] += "\n"
    return "---\n" + "".join(front) + "".join(rest)


def current_mitre(text: str) -> list[str] | None:
    if text.startswith("\ufeff"):
        text = text[1:]
    parts = _split_frontmatter(text)
    if parts is None:
        return None
    front = parts[0]
    for line in front:
        stripped = line.strip()
        if stripped.startswith(f"{KEY}:"):
            raw = stripped.split(":", 1)[1].strip()
            if raw in ("", "[]"):
                return []
            if raw.startswith("[") and raw.endswith("]"):
                inner = raw[1:-1].strip()
                return [t.strip().strip("\"'") for t in inner.split(",") if t.strip()]
            return [raw.strip("\"'")]
    return None


def annotation_gaps(skills_dir: Path) -> list[str]:
    gaps: list[str] = []
    for skill_dir in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            continue
        name = skill_dir.name
        if name not in SKILL_MITRE:
            gaps.append(f"{name}: no reviewed mapping")
            continue
        expected = get_mitre_for_skill(name)
        actual = current_mitre(skill_file.read_text(encoding="utf-8-sig"))
        if actual != expected:
            gaps.append(f"{name}: frontmatter {actual} != mapping {expected}")
    return gaps


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skills-dir", default="skills")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    skills_dir = Path(args.skills_dir)
    unknown = sorted({t for techs in SKILL_MITRE.values() for t in techs} - set(TECHNIQUES))
    if unknown:
        print(f"unknown technique IDs in mapping: {unknown}", file=sys.stderr)
        return 1

    changed = 0
    missing = sorted(
        p.name
        for p in skills_dir.iterdir()
        if p.is_dir() and (p / "SKILL.md").exists() and p.name not in SKILL_MITRE
    )
    if missing:
        print(f"skills without mapping: {missing}", file=sys.stderr)
        return 1

    for name in sorted(SKILL_MITRE):
        skill_file = skills_dir / name / "SKILL.md"
        if not skill_file.exists():
            print(f"mapped but missing on disk: {name}", file=sys.stderr)
            return 1
        text = skill_file.read_text(encoding="utf-8-sig")
        expected = get_mitre_for_skill(name)
        desired = update_text(text, expected)
        if desired != text:
            changed += 1
            if args.check:
                print(f"stale: {skill_file}")
            else:
                skill_file.write_text(desired, encoding="utf-8", newline="")

    if args.check and changed:
        return 1
    print(f"{'stale' if args.check else 'updated'}: {changed} skill file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
