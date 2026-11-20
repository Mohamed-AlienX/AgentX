"""Detect skills whose descriptions are so similar they get misrouted.

Pure-standard-library TF-IDF cosine similarity. An agent picks a skill from its
description alone; when two descriptions are near-duplicates the router cannot
reliably choose and misroutes ("skill collision").

Three details make the score mean something:

* Stopwords are dropped -- every description says "use when ... security", so
  those words carry no discriminating signal.
* The slug tokens are added -- ``hunt-idor`` and ``hunt-rce`` differ mainly by
  their names, which the prose alone may not mention.
* Disambiguation sentences are stripped -- a correct negative trigger names the
  sibling skill, and scoring that text would *raise* similarity, punishing the
  very fix the linter asks for.

A high score is not automatically a defect. Genuinely distinct near-twins go in
the allowlist with a reason, which doubles as the wording their negative
triggers should use.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from itertools import combinations
from pathlib import Path

from agentx.skills.qa.frontmatter import description_of, load_all

DEFAULT_THRESHOLD = 0.45
DEFAULT_ALLOWLIST = Path(".qa/collision-allowlist.json")

# Words too common in this corpus to carry signal.
STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "for",
        "in",
        "on",
        "with",
        "using",
        "use",
        "uses",
        "used",
        "when",
        "this",
        "that",
        "is",
        "are",
        "be",
        "by",
        "from",
        "as",
        "it",
        "its",
        "into",
        "via",
        "at",
        "not",
        "skill",
        "security",
        "detect",
        "detects",
        "detecting",
        "analyze",
        "analyzes",
        "analyzing",
        "perform",
        "performs",
        "performing",
        "implement",
        "implements",
        "implementing",
    }
)

# A term appearing in more than this many skills is domain-wide background:
# skipped when pairing, which also keeps scoring near-linear.
MAX_DOCS_PER_TERM = 60

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_DISAMBIGUATION_RE = re.compile(
    r"\b(?:do\s+not\s+use|don'?t\s+use|avoid\s+(?:this\s+)?(?:skill\s+)?for)\b.*",
    re.IGNORECASE | re.DOTALL,
)
_KEYWORDS_LABEL_RE = re.compile(r"\bkeywords\s*:", re.IGNORECASE)


def strip_disambiguation(text: str) -> str:
    """Drop negative-trigger sentences and the literal ``Keywords:`` label."""
    return _KEYWORDS_LABEL_RE.sub(" ", _DISAMBIGUATION_RE.sub("", text))


def tokenize(text: str) -> Counter[str]:
    """Lowercase alphanumeric tokens minus stopwords and 1-2 char noise."""
    return Counter(
        word for word in _TOKEN_RE.findall(text.lower()) if word not in STOPWORDS and len(word) > 2
    )


def build_vectors(descriptions: dict[str, str]) -> dict[str, dict[str, float]]:
    """L2-normalized TF-IDF vectors, keyed by slug, from ``{slug: description}``."""
    documents: dict[str, Counter[str]] = {}
    for slug, description in descriptions.items():
        text = f"{strip_disambiguation(description)} {slug.replace('-', ' ')}"
        documents[slug] = tokenize(text)

    document_frequency: Counter[str] = Counter()
    for counts in documents.values():
        document_frequency.update(counts.keys())

    total = max(len(documents), 1)
    vectors: dict[str, dict[str, float]] = {}
    for slug, counts in documents.items():
        weights = {
            term: (1 + math.log(freq)) * math.log(total / document_frequency[term])
            for term, freq in counts.items()
        }
        norm = math.sqrt(sum(weight * weight for weight in weights.values())) or 1.0
        vectors[slug] = {term: weight / norm for term, weight in weights.items()}
    return vectors


def score_pairs(
    vectors: dict[str, dict[str, float]],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[tuple[float, str, str]]:
    """Return ``(score, slug_a, slug_b)`` at/above ``threshold``, best first."""
    postings: dict[str, list[str]] = {}
    for slug, vector in vectors.items():
        for term in vector:
            postings.setdefault(term, []).append(slug)

    similarities: dict[tuple[str, str], float] = {}
    for term, slugs in postings.items():
        if len(slugs) > MAX_DOCS_PER_TERM:
            continue
        weights = {slug: vectors[slug][term] for slug in slugs}
        for left, right in combinations(sorted(slugs), 2):
            key = (left, right)
            similarities[key] = similarities.get(key, 0.0) + weights[left] * weights[right]

    ranked = sorted(((score, *pair) for pair, score in similarities.items()), reverse=True)
    return [item for item in ranked if item[0] >= threshold]


def load_allowlist(path: str | Path = DEFAULT_ALLOWLIST) -> dict[tuple[str, str], str]:
    """Load reviewed-as-distinct pairs as ``{(a, b): reason}``."""
    allowlist_path = Path(path)
    if not allowlist_path.is_file():
        return {}
    data = json.loads(allowlist_path.read_text(encoding="utf-8"))
    entries = data.get("reviewed_distinct", []) if isinstance(data, dict) else data
    reviewed: dict[tuple[str, str], str] = {}
    for entry in entries:
        if isinstance(entry, dict):
            left, right = str(entry["pair"][0]), str(entry["pair"][1])
            reason = str(entry.get("reason", ""))
        else:
            left, right = str(entry[0]), str(entry[1])
            reason = ""
        reviewed[(left, right) if left <= right else (right, left)] = reason
    return reviewed


def run(
    skills_dir: str | Path = "skills",
    threshold: float = DEFAULT_THRESHOLD,
    allowlist_path: str | Path = DEFAULT_ALLOWLIST,
) -> tuple[
    list[tuple[float, str, str]],
    list[tuple[float, str, str, str]],
]:
    """Return ``(unreviewed, reviewed)`` collisions at/above ``threshold``."""
    loaded, parse_errors = load_all(skills_dir)
    descriptions = {
        slug: description_of(frontmatter)
        for slug, frontmatter in loaded.items()
        if slug not in parse_errors
    }
    allowlist = load_allowlist(allowlist_path)

    unreviewed: list[tuple[float, str, str]] = []
    reviewed: list[tuple[float, str, str, str]] = []
    for score, left, right in score_pairs(build_vectors(descriptions), threshold):
        key = (left, right) if left <= right else (right, left)
        if key in allowlist:
            reviewed.append((score, left, right, allowlist[key]))
        else:
            unreviewed.append((score, left, right))
    return unreviewed, reviewed
