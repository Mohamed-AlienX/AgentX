"""Lint ``SKILL.md`` descriptions for the qualities that drive skill routing.

The description is the only signal the router sees at discovery time, so it
must say what the skill does, when to fire it, and when *not* to fire it. Two
skills whose descriptions overlap without a negative trigger get misrouted.

Grandfathering
--------------
Known pre-existing failures live in a baseline file so the gate can go green
today while debt is paid down. The baseline may only shrink: a NEW failure is
an error, and a baselined skill that starts passing is reported as stale.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agentx.skills.qa.frontmatter import (
    FrontmatterError,
    description_of,
    iter_skill_dirs,
    load_frontmatter,
)

DESCRIPTION_MAX_CHARS = 1024
BODY_MAX_LINES = 500
SENTENCE_ENDINGS = ".!?)\"'"

# "Use when ...", "Use this skill when ...", "Use for ..."
USE_WHEN_RE = re.compile(
    r"\buse\s+(?:this\s+)?(?:skill\s+)?(?:when|whenever|for|during|after|before)\b",
    re.IGNORECASE,
)

# "Do not use for X", "Don't use when Y", "Not for Z"
NEGATIVE_TRIGGER_RE = re.compile(
    r"\b(?:do\s+not\s+use|don'?t\s+use|not\s+for\b|avoid\s+(?:this\s+)?(?:skill\s+)?for)\b",
    re.IGNORECASE,
)

RULES = (
    "name-matches-folder",
    "desc-max-length",
    "desc-ends-punctuation",
    "desc-has-use-when",
    "desc-has-negative-trigger",
    "body-max-lines",
)

DEFAULT_BASELINE = Path(".qa/lint-baseline.json")

_BASELINE_COMMENT = (
    "Pre-existing lint failures, grandfathered so the gate blocks NEW debt only. "
    "This file may only shrink. Never add a slug by hand -- fix the skill, then "
    "run: python -m agentx.skills.qa lint --update-baseline"
)


def check_skill(slug: str, skill_dir: str | Path) -> dict[str, str]:
    """Return ``{rule_id: message}`` for every lint rule the skill violates."""
    skill_md = Path(skill_dir) / "SKILL.md"
    violations: dict[str, str] = {}

    try:
        frontmatter = load_frontmatter(skill_md)
    except FrontmatterError as exc:
        return {"unparseable-frontmatter": str(exc)}

    name = str(frontmatter.get("name", "") or "")
    if name != slug:
        violations["name-matches-folder"] = f"name {name!r} != folder {slug!r}"

    description = description_of(frontmatter)
    if len(description) > DESCRIPTION_MAX_CHARS:
        violations["desc-max-length"] = f"{len(description)} chars, max {DESCRIPTION_MAX_CHARS}"
    if description and description[-1] not in SENTENCE_ENDINGS:
        violations["desc-ends-punctuation"] = f"ends with {description[-40:]!r}"
    if not USE_WHEN_RE.search(description):
        violations["desc-has-use-when"] = "no trigger clause (add 'Use when ...')"
    if not NEGATIVE_TRIGGER_RE.search(description):
        violations["desc-has-negative-trigger"] = (
            "no negative trigger (add 'Do not use for X - use <other-skill>.')"
        )

    line_count = len(skill_md.read_text(encoding="utf-8").splitlines())
    if line_count > BODY_MAX_LINES:
        violations["body-max-lines"] = f"{line_count} lines, max {BODY_MAX_LINES}"

    return violations


def collect(skills_dir: str | Path = "skills") -> dict[str, dict[str, str]]:
    """Lint every skill; return only the skills that have violations."""
    found: dict[str, dict[str, str]] = {}
    for slug, skill_dir in iter_skill_dirs(skills_dir):
        violations = check_skill(slug, skill_dir)
        if violations:
            found[slug] = violations
    return found


def load_baseline(path: str | Path = DEFAULT_BASELINE) -> dict[str, list[str]]:
    """Load the lint baseline; return ``{}`` when the file does not exist."""
    baseline_path = Path(path)
    if not baseline_path.is_file():
        return {}
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    return {rule: list(slugs) for rule, slugs in data.items() if not rule.startswith("_")}


def write_baseline(
    violations: dict[str, dict[str, str]],
    path: str | Path = DEFAULT_BASELINE,
) -> dict[str, list[str]]:
    """Rewrite the baseline from the current violations."""
    baseline = {
        rule: sorted(slug for slug, found in violations.items() if rule in found) for rule in RULES
    }
    baseline = {rule: slugs for rule, slugs in baseline.items() if slugs}
    payload = {
        "_comment": _BASELINE_COMMENT,
        "_total_grandfathered": sum(len(slugs) for slugs in baseline.values()),
        **baseline,
    }
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return baseline


def compare(
    violations: dict[str, dict[str, str]],
    baseline: dict[str, list[str]],
) -> tuple[list[tuple[str, str, str]], int, list[tuple[str, str]]]:
    """Split violations into ``(new_failures, grandfathered_count, stale)``."""
    new_failures: list[tuple[str, str, str]] = []
    grandfathered = 0
    for slug, rule_map in sorted(violations.items()):
        for rule, message in sorted(rule_map.items()):
            if slug in baseline.get(rule, []):
                grandfathered += 1
            else:
                new_failures.append((slug, rule, message))

    stale = [
        (rule, slug)
        for rule, slugs in baseline.items()
        for slug in slugs
        if rule not in violations.get(slug, {})
    ]
    return new_failures, grandfathered, stale
