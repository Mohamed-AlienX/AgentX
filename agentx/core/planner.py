"""Task planner for AgentX - converts user intent into skill execution plans."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from agentx.ai.prompts.orchestrator import ORCHESTRATOR_PROMPT
from agentx.ai.prompts.scope_guard import SCOPE_GUARD_PROMPT
from agentx.ai.router import router
from agentx.core.session import session_manager
from agentx.skills.base import get_skill_class
from agentx.skills.registry import skill_registry


@dataclass
class PlanStep:
    """Single step in an execution plan."""

    skill: str
    description: str
    reason: str
    dependencies: list[str] = field(default_factory=list)
    estimated_time: str = "5-10 min"
    priority: int = 10


@dataclass
class ExecutionPlan:
    """Complete execution plan."""

    analysis: str
    steps: list[PlanStep]
    selected_skills: list[str]
    questions: list[str]
    estimated_time: str
    target: str = ""


class TaskPlanner:
    """Plans multi-step skill execution based on user intent."""

    def __init__(self):
        self._skill_descriptions: dict[str, str] = {}
        self._skill_mitre: dict[str, list[str]] = {}
        self._skill_descriptions = self._load_skill_descriptions()

    def _load_skill_descriptions(self) -> dict[str, str]:
        """Load skill descriptions and ATT&CK tags for planning."""
        descriptions = {}
        for name in skill_registry.get_enabled_skills():
            skill_class = get_skill_class(name)
            if skill_class:
                descriptions[name] = skill_class.description
            else:
                metadata = skill_registry._skill_metadata.get(name, {})
                descriptions[name] = metadata.get("description", "")
            metadata = skill_registry._skill_metadata.get(name, {})
            self._skill_mitre[name] = list(metadata.get("mitre_attack") or [])
        return descriptions

    async def create_plan(
        self,
        user_input: str,
        target: str = "",
        context: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        """Create execution plan from user input."""
        # Get current session context
        session = session_manager.get_session()
        session_context = ""
        if session:
            findings_count = len(session.get_findings())
            session_context = f"""
Current Session: {session.id}
Target: {session.target or target}
Phase: {session.current_phase}
Findings: {findings_count} total
Completed Skills: {", ".join(session.completed_skills) if session.completed_skills else "none"}
Active Skills: {", ".join(session.active_skills) if session.active_skills else "none"}
"""

        # Build skill list for prompt (ATT&CK tags help the model reason about coverage)
        skills_list = "\n".join(
            [
                f"- {name}: {desc}"
                + (
                    f" [ATT&CK: {', '.join(self._skill_mitre.get(name, []))}]"
                    if self._skill_mitre.get(name)
                    else ""
                )
                for name, desc in self._skill_descriptions.items()
            ]
        )

        prompt = f"""
{ORCHESTRATOR_PROMPT}
{SCOPE_GUARD_PROMPT}

## Current Context
{session_context}

## Available Skills
{skills_list}

## User Request
{user_input}

## Additional Context
{json.dumps(context or {}, indent=2)}

Create an execution plan following the output format specified in your instructions.
"""

        response = await router.complete(
            [{"role": "user", "content": prompt}],
            task_type="orchestrator",
        )

        return self._parse_plan(response, target)

    def _parse_plan(self, response: str, target: str) -> ExecutionPlan:
        """Parse orchestrator response into ExecutionPlan."""
        plan = ExecutionPlan(
            analysis="",
            steps=[],
            selected_skills=[],
            questions=[],
            estimated_time="",
            target=target,
        )

        # Parse sections
        sections = {
            "analysis": r"## Analysis\n(.*?)(?=\n## |\Z)",
            "selected_skills": r"## Selected Skills\n(.*?)(?=\n## |\Z)",
            "execution_plan": r"## Execution Plan\n(.*?)(?=\n## |\Z)",
            "questions": r"## Questions for User\n(.*?)(?=\n## |\Z)",
            "estimated_time": r"## Estimated Time\n(.*?)(?=\n## |\Z)",
        }

        for key, pattern in sections.items():
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1).strip()
                if key == "analysis":
                    plan.analysis = content
                elif key == "selected_skills":
                    # Parse skill list
                    for line in content.split("\n"):
                        line = line.strip()
                        if line[:1] in "-*?" or line.startswith("???"):
                            skill_part = re.sub(r"^[\-\*\?\s\u2022\ufeff]+", "", line).strip()
                            if ":" in skill_part:
                                skill_name = skill_part.split(":")[0].strip()
                                plan.selected_skills.append(skill_name)
                elif key == "execution_plan":
                    # Parse numbered steps
                    step_pattern = r"(\d+)\.\s+\[(.*?)\]\s+(.*?)(?=\n\d+\.|\n## |\Z)"
                    for match in re.finditer(step_pattern, content, re.DOTALL):
                        step_num = int(match.group(1))
                        skill_name = match.group(2).strip()
                        description = match.group(3).strip()
                        plan.steps.append(
                            PlanStep(
                                skill=skill_name,
                                description=description,
                                reason=f"Step {step_num}",
                                priority=step_num * 10,
                            )
                        )
                elif key == "questions":
                    for line in content.split("\n"):
                        line = line.strip()
                        if line[:1] in "-*?" or line.startswith("???"):
                            plan.questions.append(
                                re.sub(r"^[\-\*\?\s\u2022\ufeff]+", "", line).strip()
                            )
                elif key == "estimated_time":
                    plan.estimated_time = content

        # If no structured plan found, create a simple one
        if not plan.steps and plan.selected_skills:
            for i, skill in enumerate(plan.selected_skills):
                plan.steps.append(
                    PlanStep(
                        skill=skill,
                        description=f"Execute {skill}",
                        reason="Auto-generated from selected skills",
                        priority=(i + 1) * 10,
                    )
                )

        return plan

    async def suggest_next_skills(
        self,
        current_findings: list[dict[str, Any]],
        completed_skills: list[str],
    ) -> list[str]:
        """Suggest next skills based on findings (A→B signal method)."""
        if not current_findings:
            return []

        # Extract finding types
        finding_types = set()
        for f in current_findings:
            title = f.get("title", "").lower()
            if "idor" in title:
                finding_types.add("idor")
            elif "xss" in title:
                finding_types.add("xss")
            elif "ssrf" in title:
                finding_types.add("ssrf")
            elif "sql" in title or "sqli" in title:
                finding_types.add("sqli")
            elif "auth" in title or "jwt" in title:
                finding_types.add("auth")
            elif "race" in title:
                finding_types.add("race")

        # A→B chain suggestions
        chain_map = {
            "idor": ["hunt-auth-bypass", "hunt-session", "hunt-graphql"],
            "xss": ["hunt-session", "hunt-csrf", "hunt-dom"],
            "ssrf": ["hunt-cloud-misconfig", "hunt-rce"],
            "sqli": ["hunt-rce", "hunt-cloud-misconfig"],
            "auth": ["hunt-session", "hunt-mfa-bypass", "hunt-oauth"],
            "race": ["hunt-business-logic", "hunt-auth-bypass"],
        }

        suggestions = []
        for ftype in finding_types:
            for skill in chain_map.get(ftype, []):
                if skill not in completed_skills and skill_registry.is_enabled(skill):
                    suggestions.append(skill)

        # Add general hunting skills if not done
        core_hunting = ["hunt-xss", "hunt-sqli", "hunt-ssrf", "hunt-idor", "hunt-rce"]
        for skill in core_hunting:
            if skill not in completed_skills and skill_registry.is_enabled(skill):
                suggestions.append(skill)

        # Remove duplicates, keep order
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:5]  # Top 5 suggestions


# Global planner
planner = TaskPlanner()
