"""Command-line entry point for the skill QA harness.

Usage::

    python -m agentx.skills.qa validate
    python -m agentx.skills.qa lint [--update-baseline]
    python -m agentx.skills.qa collisions [--threshold 0.3] [--max-unreviewed 0]
    python -m agentx.skills.qa index [--check]
    python -m agentx.skills.qa mappings [--check]
    python -m agentx.skills.qa all

Exit code 0 means pass, 1 means the gate failed.
"""

from __future__ import annotations

import argparse
import json
import sys

from agentx.mitre import TECHNIQUES
from agentx.mitre_navigator import (
    check_artifacts,
    write_coverage_markdown,
    write_navigator_layer,
)
from agentx.skills.qa.collisions import DEFAULT_ALLOWLIST, DEFAULT_THRESHOLD, run
from agentx.skills.qa.frontmatter import load_all
from agentx.skills.qa.index import DEFAULT_INDEX, check_index, write_index
from agentx.skills.qa.lint import (
    DEFAULT_BASELINE,
    collect,
    compare,
    load_baseline,
    write_baseline,
)
from agentx.skills.qa.rules import validate_skill

DEFAULT_LAYER = "mappings/attack-navigator-layer.json"
DEFAULT_COVERAGE = "ATTACK_COVERAGE.md"


def _configure_stdout() -> None:
    """Avoid ``UnicodeEncodeError`` on Windows' cp1252 console."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def _cmd_validate(args: argparse.Namespace) -> int:
    loaded, parse_errors = load_all(args.skills_dir)
    error_count = 0
    warning_count = 0
    for slug, message in sorted(parse_errors.items()):
        print(f"ERROR  {slug}: {message}")
        error_count += 1
    for slug, frontmatter in sorted(loaded.items()):
        result = validate_skill(slug, frontmatter)
        for message in result.errors:
            print(f"ERROR  {slug}: {message}")
            error_count += 1
        for message in result.warnings:
            print(f"WARN   {slug}: {message}")
            warning_count += 1
        for tech_id in frontmatter.get("mitre_attack") or []:
            if str(tech_id).upper() not in TECHNIQUES:
                print(f"ERROR  {slug}: unknown MITRE technique {tech_id}")
                error_count += 1
    total = len(loaded) + len(parse_errors)
    print(f"\nvalidate: {total} skills, {error_count} errors, {warning_count} warnings")
    return 0 if error_count == 0 else 1


def _cmd_lint(args: argparse.Namespace) -> int:
    violations = collect(args.skills_dir)
    if args.update_baseline:
        baseline = write_baseline(violations, args.baseline)
        total = sum(len(slugs) for slugs in baseline.values())
        print(f"lint: baseline rewritten at {args.baseline} ({total} grandfathered)")
        return 0

    new_failures, grandfathered, stale = compare(violations, load_baseline(args.baseline))
    for slug, rule, message in new_failures:
        print(f"FAIL   {slug}: {rule}: {message}")
    for rule, slug in sorted(stale):
        print(f"STALE  {slug}: {rule} now passes -- drop it from the baseline")
    print(
        f"\nlint: {len(new_failures)} new failures, "
        f"{grandfathered} grandfathered, {len(stale)} stale"
    )
    return 0 if not new_failures else 1


def _cmd_collisions(args: argparse.Namespace) -> int:
    unreviewed, reviewed = run(args.skills_dir, args.threshold, args.allowlist)
    if args.json:
        payload = {
            "threshold": args.threshold,
            "unreviewed": [
                {"score": round(score, 3), "a": left, "b": right}
                for score, left, right in unreviewed
            ],
            "reviewed": [
                {"score": round(score, 3), "a": left, "b": right, "reason": reason}
                for score, left, right, reason in reviewed
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        for score, left, right in unreviewed:
            print(f"NEW    {score:.2f}  {left}  <->  {right}")
        for score, left, right, reason in reviewed:
            print(f"OK     {score:.2f}  {left}  <->  {right}  ({reason or 'reviewed distinct'})")
        print(
            f"\ncollisions: {len(unreviewed)} unreviewed, {len(reviewed)} reviewed "
            f"(threshold {args.threshold:.2f})"
        )
    return 0 if len(unreviewed) <= args.max_unreviewed else 1


def _cmd_index(args: argparse.Namespace) -> int:
    if args.check:
        current, message = check_index(args.skills_dir, args.index)
        print(("OK    " if current else "STALE ") + message)
        return 0 if current else 1
    document = write_index(args.skills_dir, args.index)
    print(f"index: wrote {args.index} ({document['total_skills']} skills)")
    return 0


def _cmd_mappings(args: argparse.Namespace) -> int:
    if args.check:
        problems = check_artifacts(args.skills_dir, args.layer, args.coverage)
        for problem in problems:
            print(f"STALE  {problem}")
        print(f"\nmappings: {len(problems)} problem(s)")
        return 0 if not problems else 1

    layer = write_navigator_layer(args.skills_dir, args.layer)
    write_coverage_markdown(args.skills_dir, args.coverage)
    print(
        f"mappings: wrote {args.layer} ({len(layer['techniques'])} techniques) "
        f"and {args.coverage}"
    )
    return 0


def _cmd_all(args: argparse.Namespace) -> int:
    codes = []
    print("== validate ==")
    codes.append(_cmd_validate(args))
    print("\n== lint ==")
    args.update_baseline = False
    codes.append(_cmd_lint(args))
    print("\n== collisions ==")
    codes.append(_cmd_collisions(args))
    print("\n== index ==")
    args.check = True
    codes.append(_cmd_index(args))
    print("\n== mappings ==")
    codes.append(_cmd_mappings(args))
    return max(codes)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agentx.skills.qa",
        description="Validate, lint, de-collide and index AgentX skills.",
    )
    parser.add_argument("--skills-dir", default="skills", help="skills directory")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--skills-dir",
        default=argparse.SUPPRESS,
        help="skills directory (accepted after the subcommand too)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser(
        "validate", parents=[common], help="structural frontmatter validation"
    )
    validate.set_defaults(func=_cmd_validate)

    lint = sub.add_parser(
        "lint", parents=[common], help="description lint with a shrinking baseline"
    )
    lint.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    lint.add_argument(
        "--update-baseline",
        action="store_true",
        help="rewrite the baseline from current failures (pay down debt only)",
    )
    lint.set_defaults(func=_cmd_lint)

    collisions = sub.add_parser(
        "collisions", parents=[common], help="TF-IDF description overlap"
    )
    collisions.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    collisions.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST))
    collisions.add_argument("--max-unreviewed", type=int, default=0)
    collisions.add_argument("--json", action="store_true")
    collisions.set_defaults(func=_cmd_collisions)

    index = sub.add_parser(
        "index", parents=[common], help="generate skills/index.json"
    )
    index.add_argument("--check", action="store_true", help="verify the index is current")
    index.add_argument("--index", default=DEFAULT_INDEX)
    index.set_defaults(func=_cmd_index)

    mappings = sub.add_parser(
        "mappings",
        parents=[common],
        help="generate MITRE ATT&CK Navigator layer + coverage doc",
    )
    mappings.add_argument("--check", action="store_true", help="verify artifacts are current")
    mappings.add_argument("--layer", default=DEFAULT_LAYER)
    mappings.add_argument("--coverage", default=DEFAULT_COVERAGE)
    mappings.set_defaults(func=_cmd_mappings)

    everything = sub.add_parser(
        "all",
        parents=[common],
        help="validate + lint + collisions + index + mappings --check",
    )
    everything.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    everything.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST))
    everything.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    everything.add_argument("--max-unreviewed", type=int, default=0)
    everything.add_argument("--index", default=DEFAULT_INDEX)
    everything.add_argument("--layer", default=DEFAULT_LAYER)
    everything.add_argument("--coverage", default=DEFAULT_COVERAGE)
    everything.add_argument("--json", action="store_true")
    everything.set_defaults(func=_cmd_all)
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdout()
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
