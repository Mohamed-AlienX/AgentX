"""Single source of truth for reading ``SKILL.md`` YAML frontmatter.

Every QA tool must read frontmatter through this module. The upstream repo
learned this the hard way: three hand-rolled "YAML-ish" parsers each handled a
different subset of scalar styles and silently truncated multi-line
descriptions. PyYAML handles plain, single-quoted, folded (``>-``) and literal
(``|``) scalars, escapes and CRLF/BOM prefixes correctly.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import yaml

# Frontmatter is the block between the opening ``---`` and the next ``---`` that
# sits alone on its own line. Tolerates CRLF and a leading UTF-8 BOM.
_FRONTMATTER_RE = re.compile(r"\A\ufeff?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)

BACKUP_SUFFIX = ".bak"


class FrontmatterError(ValueError):
    """Raised when a ``SKILL.md`` has missing or unparseable frontmatter."""


def extract_block(text: str) -> str:
    """Return the raw YAML frontmatter block from a ``SKILL.md``'s text."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        raise FrontmatterError("no YAML frontmatter block (file must start with '---')")
    return match.group(1)


def parse(text: str) -> dict:
    """Parse a ``SKILL.md``'s full text into a frontmatter dict."""
    try:
        data = yaml.safe_load(extract_block(text))
    except yaml.YAMLError as exc:
        raise FrontmatterError(f"invalid YAML in frontmatter: {exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise FrontmatterError(f"frontmatter must be a mapping, got {type(data).__name__}")
    return data


def load_frontmatter(path: str | Path) -> dict:
    """Read one ``SKILL.md`` and return its frontmatter as a dict."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise FrontmatterError(f"not valid UTF-8: {exc}") from exc
    return parse(text)


def description_of(frontmatter: dict) -> str:
    """Return the description as a single normalized line.

    YAML preserves the newlines of a literal (``|``) scalar and folds a folded
    (``>``) one; collapsing whitespace here gives every style the same shape,
    which is what the index and the linters want to compare.
    """
    return " ".join(str(frontmatter.get("description", "")).split())


def body_of(text: str) -> str:
    """Return everything after the frontmatter block (the Markdown body)."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return text
    return text[match.end() :]


def iter_skill_dirs(skills_dir: str | Path = "skills") -> Iterator[tuple[str, Path]]:
    """Yield ``(slug, skill_dir)`` for every real skill, in sorted order.

    Skips ``*.bak`` backup directories and any directory lacking a ``SKILL.md``.
    """
    root = Path(skills_dir)
    if not root.is_dir():
        return
    for skill_dir in sorted(root.iterdir()):
        if skill_dir.name.endswith(BACKUP_SUFFIX):
            continue
        if not skill_dir.is_dir():
            continue
        if not (skill_dir / "SKILL.md").is_file():
            continue
        yield skill_dir.name, skill_dir


def load_all(
    skills_dir: str | Path = "skills",
) -> tuple[dict[str, dict], dict[str, str]]:
    """Load frontmatter for every skill.

    Returns ``(frontmatter_by_slug, errors_by_slug)``. Callers decide whether a
    parse failure is fatal; nothing is silently dropped.
    """
    loaded: dict[str, dict] = {}
    errors: dict[str, str] = {}
    for slug, skill_dir in iter_skill_dirs(skills_dir):
        try:
            loaded[slug] = load_frontmatter(skill_dir / "SKILL.md")
        except FrontmatterError as exc:
            errors[slug] = str(exc)
    return loaded, errors
