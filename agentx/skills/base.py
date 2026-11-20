"""Base classes for AgentX skills."""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from agentx.ai.router import router
from agentx.config import SkillConfig, settings


class SkillResult(BaseModel):
    """Result of a skill execution."""

    skill_name: str
    success: bool
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    next_actions: list[str] = Field(default_factory=list)


class ToolResult(BaseModel):
    """Result of a tool execution."""

    tool: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    parsed_output: Any = None
    duration_ms: int = 0


@dataclass
class SkillContext:
    """Context passed to skills during execution."""

    target: str = ""
    session_id: str = ""
    user_input: str = ""
    previous_findings: list[dict[str, Any]] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)


class BaseSkill(abc.ABC):
    """Abstract base class for all AgentX skills."""

    # Class attributes to be overridden
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    version: ClassVar[str] = "1.0.0"
    category: ClassVar[str] = "general"
    priority: ClassVar[int] = 10
    requires_target: ClassVar[bool] = True
    required_tools: ClassVar[list[str]] = []
    required_providers: ClassVar[list[str]] = []

    def __init__(self, config: SkillConfig | None = None):
        self.config = config or SkillConfig(name=self.name, enabled=True)
        self._context: SkillContext | None = None

    @property
    def context(self) -> SkillContext:
        if self._context is None:
            self._context = SkillContext()
        return self._context

    @context.setter
    def context(self, value: SkillContext) -> None:
        self._context = value

    @abc.abstractmethod
    async def execute(self, context: SkillContext) -> SkillResult:
        """Execute the skill with the given context."""
        pass

    async def initialize(self) -> None:
        """Initialize skill (install tools, load data, etc.)."""
        await self._install_required_tools()

    async def cleanup(self) -> None:
        """Cleanup after skill execution."""
        pass

    async def _install_required_tools(self) -> None:
        """Install required external tools."""
        from agentx.tools.installer import install_tool

        for tool in self.required_tools:
            try:
                await install_tool(tool)
            except Exception:
                # Log but don't fail - tool might already be installed
                pass

    async def call_ai(
        self,
        prompt: str,
        system_prompt: str | None = None,
        task_type: str = "skill",
        **kwargs,
    ) -> str:
        """Call AI with the skill's context."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        return await router.complete(messages, task_type=task_type, **kwargs)

    async def stream_ai(
        self,
        prompt: str,
        system_prompt: str | None = None,
        task_type: str = "skill",
        **kwargs,
    ):
        """Stream AI response."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async for chunk in router.stream_complete(messages, task_type=task_type, **kwargs):
            yield chunk

    def _create_result(
        self,
        response: str,
        context: SkillContext | None = None,
    ) -> SkillResult:
        """Build a SkillResult from a raw AI response.

        Markdown-only skills (no ``skill.py``) use this to turn the model's
        guidance into a structured result.
        """
        text = (response or "").strip()
        return SkillResult(
            skill_name=self.name,
            success=bool(text),
            summary=text[:500],
            metadata={"raw_response": text},
        )

    def load_skill_markdown(self, skill_name: str | None = None) -> str:
        """Load skill markdown documentation."""
        name = skill_name or self.name
        skill_dir = settings.skills_dir / name
        skill_file = skill_dir / "SKILL.md"

        if skill_file.exists():
            return skill_file.read_text(encoding="utf-8")

        # Try builtin skills
        builtin_file = Path(__file__).parent / "builtin" / name / "SKILL.md"
        if builtin_file.exists():
            return builtin_file.read_text(encoding="utf-8")

        return ""

    def extract_payloads(self, content: str, section: str) -> list[str]:
        """Extract payloads from skill markdown."""
        payloads = []
        pattern = rf"## {re.escape(section)}.*?(?=## |\Z)"
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            section_content = match.group(0)
            # Find code blocks
            code_blocks = re.findall(
                r"```(?:bash|sql|python|javascript|xml|json)?\n(.*?)\n```",
                section_content,
                re.DOTALL,
            )
            for block in code_blocks:
                lines = [
                    line.strip()
                    for line in block.split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]
                payloads.extend(lines)
        return payloads

    def extract_tables(self, content: str, section: str) -> list[dict[str, Any]]:
        """Extract markdown tables from skill markdown."""
        tables = []
        pattern = rf"## {re.escape(section)}.*?(?=## |\Z)"
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            section_content = match.group(0)
            # Find markdown tables
            table_pattern = r"\|(.+?)\|\n\|([\-:\|]+)\|\n((?:\|.+?\|\n)+)"
            for table_match in re.finditer(table_pattern, section_content, re.MULTILINE):
                headers = [h.strip() for h in table_match.group(1).split("|") if h.strip()]
                rows_content = table_match.group(3).strip().split("\n")
                for row in rows_content:
                    cells = [c.strip() for c in row.split("|") if c.strip()]
                    if len(cells) == len(headers):
                        tables.append(dict(zip(headers, cells, strict=False)))
        return tables

    def create_finding(
        self,
        title: str,
        severity: str,
        endpoint: str,
        description: str,
        impact: str,
        steps_to_reproduce: list[str],
        evidence: dict[str, Any] | None = None,
        cvss_score: float | None = None,
        references: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a standardized finding object."""
        return {
            "title": title,
            "severity": severity.upper(),
            "endpoint": endpoint,
            "description": description,
            "impact": impact,
            "steps_to_reproduce": steps_to_reproduce,
            "evidence": evidence or {},
            "cvss_score": cvss_score,
            "references": references or [],
            "skill": self.name,
            "validated": False,
        }

    def validate_finding(self, finding: dict[str, Any]) -> bool:
        """Run basic validation on a finding (7-Question Gate lite)."""
        # This is a lightweight check; full validation uses triage-validation skill
        required_fields = ["title", "severity", "endpoint", "impact", "steps_to_reproduce"]
        for field_name in required_fields:
            if not finding.get(field_name):
                return False

        # Check for theoretical language
        theoretical_phrases = [
            "could potentially",
            "may allow",
            "might enable",
            "theoretically",
            "in theory",
            "possible to",
            "hypothetically",
        ]
        text = f"{finding.get('description', '')} {finding.get('impact', '')}".lower()
        for phrase in theoretical_phrases:
            if phrase in text:
                return False

        return True


class ReconSkill(BaseSkill):
    """Base class for reconnaissance skills."""

    category: ClassVar[str] = "recon"

    async def discover_assets(self, target: str) -> list[dict[str, Any]]:
        """Discover assets for target. Override in subclasses."""
        return []


class HuntingSkill(BaseSkill):
    """Base class for vulnerability hunting skills."""

    category: ClassVar[str] = "hunting"

    async def hunt(self, target: str, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Hunt for vulnerabilities. Override in subclasses."""
        return []


class ValidationSkill(BaseSkill):
    """Base class for validation skills."""

    category: ClassVar[str] = "validation"

    async def validate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate findings. Override in subclasses."""
        return []


class ReportingSkill(BaseSkill):
    """Base class for reporting skills."""

    category: ClassVar[str] = "reporting"

    async def generate_report(
        self, findings: list[dict[str, Any]], format: str = "markdown"
    ) -> str:
        """Generate report. Override in subclasses."""
        return ""


# Skill registry
SKILL_REGISTRY: dict[str, type[BaseSkill]] = {}


def register_skill(skill_class: type[BaseSkill]) -> type[BaseSkill]:
    """Decorator to register a skill class."""
    if not skill_class.name:
        raise ValueError(f"Skill {skill_class.__name__} must have a 'name' attribute")
    SKILL_REGISTRY[skill_class.name] = skill_class
    return skill_class


def get_skill_class(name: str) -> type[BaseSkill] | None:
    """Get skill class by name."""
    return SKILL_REGISTRY.get(name)


def get_all_skills() -> dict[str, type[BaseSkill]]:
    """Get all registered skills."""
    return SKILL_REGISTRY.copy()
