"""Skill quality-assurance tooling for AgentX.

Adapted from the Anthropic-Cybersecurity-Skills repository's ``tools/``
directory. The reusable ideas ported here are:

* one PyYAML-backed frontmatter parser (never a regex parser),
* structural validation of ``SKILL.md`` metadata,
* description linting with a shrinking baseline (new debt fails, old debt is
  grandfathered),
* TF-IDF collision detection over skill descriptions, and
* a generated machine-readable skill index.

The 818-skill content itself was intentionally not imported.
"""

from __future__ import annotations

from agentx.skills.qa.collisions import (
    DEFAULT_THRESHOLD,
    build_vectors,
    load_allowlist,
    run,
    score_pairs,
    strip_disambiguation,
    tokenize,
)
from agentx.skills.qa.frontmatter import (
    FrontmatterError,
    body_of,
    description_of,
    extract_block,
    iter_skill_dirs,
    load_all,
    load_frontmatter,
    parse,
)
from agentx.skills.qa.index import build_index, check_index, write_index
from agentx.skills.qa.lint import (
    RULES,
    check_skill,
    collect,
    compare,
    load_baseline,
    write_baseline,
)
from agentx.skills.qa.rules import ALLOWED_CATEGORIES, ValidationResult, validate_skill

__all__ = [
    "ALLOWED_CATEGORIES",
    "DEFAULT_THRESHOLD",
    "FrontmatterError",
    "RULES",
    "ValidationResult",
    "body_of",
    "build_index",
    "build_vectors",
    "check_index",
    "check_skill",
    "collect",
    "compare",
    "description_of",
    "extract_block",
    "iter_skill_dirs",
    "load_allowlist",
    "load_all",
    "load_baseline",
    "load_frontmatter",
    "parse",
    "run",
    "score_pairs",
    "strip_disambiguation",
    "tokenize",
    "validate_skill",
    "write_baseline",
    "write_index",
]
