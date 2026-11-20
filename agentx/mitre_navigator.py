"""Generate MITRE ATT&CK artifacts for AgentX skills.

Outputs (both derived, never hand-edited):
- ``mappings/attack-navigator-layer.json`` — ATT&CK Navigator layer
- ``ATTACK_COVERAGE.md`` — tactic/technique coverage + per-skill table
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from agentx.mitre import TACTICS, TECHNIQUES, tactic_name, technique_url
from agentx.mitre_mapping import SKILL_MITRE, get_mitre_for_skill

NAVIGATOR_VERSION = "4.9"
LAYER_VERSION = "4.5"
ATTACK_VERSION = "16"


def _existing_skills(skills_dir: Path) -> list[str]:
    return sorted(name for name in SKILL_MITRE if (skills_dir / name / "SKILL.md").exists())


def build_navigator_layer(skills_dir: str | Path = "skills") -> dict:
    """Build an ATT&CK Navigator layer covering all mapped skills."""
    skills_dir = Path(skills_dir)
    tech_to_skills: defaultdict[str, list[str]] = defaultdict(list)

    for skill_name in _existing_skills(skills_dir):
        for tech_id in get_mitre_for_skill(skill_name):
            if tech_id in TECHNIQUES:
                tech_to_skills[tech_id].append(skill_name)

    techniques = []
    for tech_id in sorted(tech_to_skills):
        skills_list = sorted(set(tech_to_skills[tech_id]))
        tech = TECHNIQUES[tech_id]
        techniques.append(
            {
                "techniqueID": tech_id,
                "tactic": tech["tactic"],
                "score": len(skills_list),
                "color": "#0066cc" if len(skills_list) > 1 else "#66b3ff",
                "comment": f"{tech['name']} — {', '.join(skills_list)}",
                "metadata": [{"name": "skills", "value": ", ".join(skills_list)}],
                "enabled": True,
                "showSubtechniques": "." in tech_id,
            }
        )

    return {
        "name": "AgentX Skills - MITRE ATT&CK Coverage",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            "Auto-generated from skills/*/SKILL.md mitre_attack frontmatter "
            "via agentx.mitre_navigator. Do not hand-edit."
        ),
        "filters": {"platforms": ["Linux", "Windows", "macOS", "Cloud"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#66b3ff"], "minValue": 0, "maxValue": 6},
        "legendItems": [
            {"label": "Covered by 1 skill", "color": "#66b3ff"},
            {"label": "Covered by 2+ skills", "color": "#0066cc"},
        ],
        "metadata": [{"name": "source", "value": "AgentX skills registry"}],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def write_navigator_layer(
    skills_dir: str | Path = "skills",
    path: str | Path = "mappings/attack-navigator-layer.json",
) -> dict:
    """Write the Navigator layer and return it."""
    layer = build_navigator_layer(skills_dir)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    return layer


def _skill_category(skills_dir: Path, skill_name: str) -> str:
    """Read category from frontmatter without importing the registry."""
    skill_file = skills_dir / skill_name / "SKILL.md"
    try:
        text = skill_file.read_text(encoding="utf-8")
    except OSError:
        return "-"
    if not text.startswith("---"):
        return "-"
    end = text.find("\n---", 3)
    if end == -1:
        return "-"
    for line in text[3:end].splitlines():
        if line.startswith("category:"):
            return line.split(":", 1)[1].strip().strip("\"'") or "-"
    return "-"


def build_coverage_markdown(skills_dir: str | Path = "skills") -> str:
    """Generate ATTACK_COVERAGE.md content."""
    skills_dir = Path(skills_dir)
    existing = _existing_skills(skills_dir)
    tech_to_skills: defaultdict[str, list[str]] = defaultdict(list)

    for skill_name in existing:
        for tech_id in get_mitre_for_skill(skill_name):
            if tech_id in TECHNIQUES:
                tech_to_skills[tech_id].append(skill_name)

    mapped_count = sum(1 for s in existing if get_mitre_for_skill(s))
    unmapped = [s for s in existing if not get_mitre_for_skill(s)]

    lines = [
        "# MITRE ATT&CK Coverage (AgentX Skills)",
        "",
        f"- Skills total: {len(existing)}",
        f"- Skills mapped to ≥1 technique: {mapped_count}",
        f"- Techniques covered: {len(tech_to_skills)}",
        "- Navigator layer: [mappings/attack-navigator-layer.json]"
        "(mappings/attack-navigator-layer.json)",
        "",
        "> Process-only skills are intentionally unmapped rather than given "
        "invented technique IDs.",
        "",
        "## Coverage by Tactic",
        "",
        "| Tactic | Technique | Name | Skills |",
        "|---|---|---|---|",
    ]

    for tactic_id in TACTICS:
        tactic_techniques = sorted(
            t for t in tech_to_skills if TECHNIQUES[t]["tactic"] == tactic_id
        )
        for tech_id in tactic_techniques:
            name = TECHNIQUES[tech_id]["name"]
            skills_doc = ", ".join(sorted(set(tech_to_skills[tech_id])))
            lines.append(
                f"| [{tactic_name(tactic_id)}]({TACTICS[tactic_id]['url']}) "
                f"| [{tech_id}]({technique_url(tech_id)}) | {name} | {skills_doc} |"
            )

    lines += [
        "",
        "## Per-Skill Mapping",
        "",
        "| Skill | Category | Techniques |",
        "|---|---|---|",
    ]
    for skill_name in existing:
        techs = get_mitre_for_skill(skill_name)
        links = " ".join(f"[{t}]({technique_url(t)})" for t in techs) or "—"
        lines.append(f"| {skill_name} | {_skill_category(skills_dir, skill_name)} | {links} |")

    lines += ["", f"Unmapped (process-only): {', '.join(unmapped) or 'none'}", ""]
    lines.append("*Auto-generated by `agentx.mitre_navigator`. Do not hand-edit.*")
    lines.append("")
    return "\n".join(lines)


def write_coverage_markdown(
    skills_dir: str | Path = "skills",
    path: str | Path = "ATTACK_COVERAGE.md",
) -> str:
    """Write ATTACK_COVERAGE.md and return its content."""
    content = build_coverage_markdown(skills_dir)
    Path(path).write_text(content, encoding="utf-8")
    return content


def check_artifacts(
    skills_dir: str | Path = "skills",
    layer_path: str | Path = "mappings/attack-navigator-layer.json",
    coverage_path: str | Path = "ATTACK_COVERAGE.md",
) -> list[str]:
    """Return drift messages between committed artifacts and fresh output."""
    problems: list[str] = []

    layer_file = Path(layer_path)
    if not layer_file.exists():
        problems.append(f"missing {layer_file}")
    else:
        committed = json.loads(layer_file.read_text(encoding="utf-8"))
        fresh = build_navigator_layer(skills_dir)
        if committed.get("techniques") != fresh.get("techniques"):
            problems.append(f"{layer_file} is stale (techniques differ)")

    coverage_file = Path(coverage_path)
    if not coverage_file.exists():
        problems.append(f"missing {coverage_file}")
    else:
        committed_md = coverage_file.read_text(encoding="utf-8")
        fresh_md = build_coverage_markdown(skills_dir)
        if committed_md != fresh_md:
            problems.append(f"{coverage_file} is stale")

    return problems
