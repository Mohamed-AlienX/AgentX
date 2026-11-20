"""Read-side ATT&CK lookup over skill frontmatter.

Used by the CLI (``agentx attack``), the planner prompt builder and tests.
Reads ``skills/*/SKILL.md`` directly so it never depends on the registry
being initialized.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agentx.mitre import TACTICS, TECHNIQUES, tactic_name, technique_url
from agentx.skills.qa.frontmatter import load_all


@dataclass(frozen=True)
class TechniqueInfo:
    """A technique plus the skills that cover it."""

    id: str
    name: str
    tactic: str
    url: str
    skills: tuple[str, ...] = field(default_factory=tuple)

    @property
    def tactic_name(self) -> str:
        return tactic_name(self.tactic)


class AttackIndex:
    """Query skills by ATT&CK technique, tactic, or text."""

    def __init__(self, skills_dir: str | Path = "skills"):
        self.skills_dir = Path(skills_dir)
        self._by_technique: dict[str, list[str]] = {}
        self._by_skill: dict[str, list[str]] = {}
        self._categories: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        loaded, _ = load_all(self.skills_dir)
        for skill_name, meta in loaded.items():
            techs = [str(t).upper() for t in (meta.get("mitre_attack") or [])]
            techs = list(dict.fromkeys(techs))
            self._by_skill[skill_name] = techs
            self._categories[skill_name] = str(meta.get("category") or "-")
            for tech in techs:
                self._by_technique.setdefault(tech, []).append(skill_name)

    # -- queries ---------------------------------------------------------
    def techniques_for_skill(self, skill: str) -> list[str]:
        return list(self._by_skill.get(skill, []))

    def skills_for_technique(self, technique: str) -> list[str]:
        return sorted(self._by_technique.get(technique.upper(), []))

    def technique(self, technique: str) -> TechniqueInfo | None:
        tech_id = technique.upper()
        skills = tuple(self.skills_for_technique(tech_id))
        meta = TECHNIQUES.get(tech_id)
        if not meta:
            return None
        return TechniqueInfo(
            id=tech_id,
            name=meta["name"],
            tactic=meta["tactic"],
            url=technique_url(tech_id),
            skills=skills,
        )

    def by_tactic(self, tactic_id: str) -> list[TechniqueInfo]:
        tactic_id = tactic_id.upper()
        out: list[TechniqueInfo] = []
        for tech_id in sorted(self._by_technique):
            meta = TECHNIQUES.get(tech_id)
            if meta and meta["tactic"] == tactic_id:
                out.append(self.technique(tech_id))  # type: ignore[arg-type]
        return out

    def search(self, query: str) -> list[TechniqueInfo]:
        """Match technique IDs/names and skill names (case-insensitive)."""
        needle = query.strip().lower()
        if not needle:
            return []
        hits: list[TechniqueInfo] = []
        for tech_id in sorted(self._by_technique):
            info = self.technique(tech_id)
            if info is None:
                continue
            haystack = f"{info.id} {info.name} {info.tactic_name} {info.skills}".lower()
            if needle in haystack:
                hits.append(info)
        return hits

    def coverage(self) -> dict[str, dict[str, int]]:
        """Per-tactic technique counts across the catalog."""
        result: dict[str, dict[str, int]] = {}
        for tactic_id, tactic in TACTICS.items():
            total = sum(1 for t in TECHNIQUES.values() if t["tactic"] == tactic_id)
            covered = sum(
                1 for t in self._by_technique if TECHNIQUES.get(t, {}).get("tactic") == tactic_id
            )
            result[tactic_id] = {
                "name": tactic["name"],
                "covered": covered,
                "catalog": total,
                "skills": sum(
                    len(self._by_technique[t])
                    for t in self._by_technique
                    if TECHNIQUES.get(t, {}).get("tactic") == tactic_id
                ),
            }
        return result

    def totals(self) -> dict[str, int]:
        mapped_skills = sum(1 for techs in self._by_skill.values() if techs)
        return {
            "skills": len(self._by_skill),
            "mapped_skills": mapped_skills,
            "techniques": len(self._by_technique),
        }


def get_attack_index(skills_dir: str | Path | None = None) -> AttackIndex:
    """Build a fresh index (no caching: skill files change during a session)."""
    if skills_dir is None:
        from agentx.config import settings

        skills_dir = settings.skills_dir
    return AttackIndex(skills_dir)
