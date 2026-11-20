"""Install AgentX skills into a host LLM agent's skill directory.

AgentX skills are plain ``SKILL.md`` playbooks, so any agent that speaks the
Agent Skills standard can use them with no API key: the host agent is the LLM.

Usage:
    python scripts/install_to_agents.py --list
    python scripts/install_to_agents.py --dry-run
    python scripts/install_to_agents.py --all
    python scripts/install_to_agents.py --target claude --target opencode
    python scripts/install_to_agents.py --target C:/some/agent/skills
    python scripts/install_to_agents.py --project
    python scripts/install_to_agents.py --only hunt-xss,hunt-ssrf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from the repo without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentx.skills.install import (  # noqa: E402
    Target,
    detect_targets,
    find_target,
    install,
    known_targets,
    post_install_hint,
)

DEFAULT_SKILLS = Path(__file__).resolve().parent.parent / "skills"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy AgentX skill playbooks into a host LLM agent's skills directory.",
    )
    parser.add_argument(
        "--skills-dir",
        default=str(DEFAULT_SKILLS),
        help="source skills directory (default: <repo>/skills)",
    )
    parser.add_argument(
        "--target",
        action="append",
        metavar="KEY_OR_PATH",
        help="target key (claude, opencode, gemini, copilot, cursor, universal) "
        "or a directory path. Repeatable.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="install into every known location, not only detected ones",
    )
    parser.add_argument(
        "--project",
        action="store_true",
        help="include project-scoped locations under the current directory",
    )
    parser.add_argument(
        "--only",
        default="",
        help="comma-separated skill slugs to install (default: all)",
    )
    parser.add_argument("--dry-run", action="store_true", help="show what would happen")
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep existing skill directories instead of overwriting them",
    )
    parser.add_argument("--list", action="store_true", help="list known and detected locations")
    return parser.parse_args(argv)


def resolve_targets(args: argparse.Namespace) -> list[Target]:
    project = Path.cwd() if args.project else None
    if args.target:
        chosen = []
        for value in args.target:
            try:
                chosen.append(find_target(value, project=project))
            except KeyError:
                path = Path(value).expanduser()
                chosen.append(
                    Target(key="custom", label=f"Custom ({path.name})", path=path, probe=None)
                )
        return chosen
    if args.all:
        return known_targets(project=project)
    return detect_targets(project=project)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    project = Path.cwd() if args.project else None

    if args.list:
        print(f"{'KEY':<18} {'DETECTED':<9} AGENT / PATH")
        for item in known_targets(project=project):
            flag = "yes" if item.detected() else "no"
            print(f"{item.key:<18} {flag:<9} {item.label}")
            print(f"{'':<28}{item.path}")
        return 0

    targets = resolve_targets(args)
    if not targets:
        print("No agent skill directory detected. Use --list, --target PATH or --all.")
        return 1

    skills_dir = Path(args.skills_dir).expanduser()
    if not skills_dir.is_dir():
        print(f"skills directory not found: {skills_dir}")
        return 1

    only = {name.strip() for name in args.only.split(",") if name.strip()} or None
    failures = 0
    for target in targets:
        report = install(skills_dir, target, only=only, force=not args.keep, dry_run=args.dry_run)
        prefix = "[dry-run] " if args.dry_run else ""
        print(f"{prefix}{target.label} -> {target.path}")
        print(
            f"  new: {len(report.created)}  updated: {len(report.updated)}  "
            f"kept: {len(report.kept)}  failed: {len(report.failed)}"
        )
        for slug, error in report.failed:
            print(f"  FAILED {slug}: {error}")
        failures += len(report.failed)
        if not args.dry_run and report.installed:
            print(f"  {post_install_hint(target, report.installed)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
