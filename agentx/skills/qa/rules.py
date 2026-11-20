"""Structural validation rules for ``SKILL.md`` metadata.

Validation answers "is this metadata well-formed?" (fatal errors) and surfaces
advisory warnings. Description *quality* is handled separately by
:mod:`agentx.skills.qa.lint` so it can be ratcheted with a shrinking baseline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Canonical category set. Mirrors ``SkillRegistry._infer_priority`` keys so a
# skill that names its own category always maps to a known priority bucket.
ALLOWED_CATEGORIES = frozenset(
    {
        "recon",
        "hunting",
        "validation",
        "reporting",
        "resources",
        "methodology",
        "post-exploitation",
        "infrastructure",
        "general",
    }
)

# Fields that AgentX itself consumes or recognises. Unknown keys are permitted
# (they are inert metadata) but reported as warnings.
KNOWN_FIELDS = frozenset(
    {
        "name",
        "description",
        "category",
        "sources",
        "version",
        "license",
        "tags",
        "triggers",
        "mitre_attack",
        "allowed_tools",
        "priority",
        "requires_target",
        "required_tools",
        "required_providers",
        "report_count",
    }
)

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

DESC_MIN_CHARS = 50
DESC_HARD_MAX_CHARS = 4096


@dataclass
class ValidationResult:
    """Outcome of validating one skill's frontmatter."""

    slug: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _as_str_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, (str, int, float)) for item in value):
        return None
    return [str(item) for item in value]


def validate_skill(slug: str, frontmatter: dict) -> ValidationResult:
    """Validate one skill's parsed frontmatter. Never raises."""
    result = ValidationResult(slug=slug)
    errors = result.errors
    warnings = result.warnings

    name = frontmatter.get("name")
    if not name:
        errors.append("missing required field: name")
    else:
        name = str(name)
        if not NAME_RE.match(name):
            errors.append(f"name is not lowercase-kebab-case: {name!r}")
        if len(name) > 64:
            errors.append(f"name too long ({len(name)} chars, max 64)")
        if name != slug:
            errors.append(f"name {name!r} != directory {slug!r}")

    if "description" not in frontmatter:
        errors.append("missing required field: description")
    else:
        description = str(frontmatter.get("description") or "")
        if not description.strip():
            errors.append("description is empty")
        elif len(description) < DESC_MIN_CHARS:
            errors.append(f"description too short ({len(description)} chars, min {DESC_MIN_CHARS})")
        elif len(description) > DESC_HARD_MAX_CHARS:
            errors.append(
                f"description too long ({len(description)} chars, max {DESC_HARD_MAX_CHARS})"
            )

    category = frontmatter.get("category")
    if category is not None and str(category) not in ALLOWED_CATEGORIES:
        errors.append(
            f"unknown category {category!r}; allowed: {', '.join(sorted(ALLOWED_CATEGORIES))}"
        )

    version = frontmatter.get("version")
    if version is not None and not isinstance(version, (str, int, float)):
        errors.append(f"version must be a string, got {type(version).__name__}")

    tags = frontmatter.get("tags")
    if tags is not None:
        parsed_tags = _as_str_list(tags)
        if parsed_tags is None:
            errors.append("tags must be a list")
        elif len(parsed_tags) < 1:
            errors.append("tags must contain at least one entry")

    mitre = frontmatter.get("mitre_attack")
    if mitre is not None:
        parsed_mitre = _as_str_list(mitre)
        if parsed_mitre is None:
            errors.append("mitre_attack must be a list of technique IDs")
        else:
            invalid = [t for t in parsed_mitre if not MITRE_RE.match(t.upper())]
            if invalid:
                errors.append(f"invalid MITRE ATT&CK technique ID(s): {invalid}")

    source = frontmatter.get("sources")
    if source is not None and not isinstance(source, str):
        errors.append(f"sources must be a string, got {type(source).__name__}")

    for key in frontmatter:
        if key not in KNOWN_FIELDS:
            warnings.append(f"unknown frontmatter field: {key}")

    for key, value in frontmatter.items():
        if isinstance(value, str) and ("<" in value or ">" in value):
            warnings.append(f"value for {key!r} contains angle brackets (possible injection)")
            break

    return result
