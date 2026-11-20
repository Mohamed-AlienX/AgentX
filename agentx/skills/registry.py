"""Skill Registry - Dynamic loading and management of skills."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import yaml

from agentx.config import SkillConfig, settings
from agentx.skills.base import (
    BaseSkill,
    get_skill_class,
)


class SkillRegistry:
    """Manages skill discovery, loading, and instantiation."""

    def __init__(self):
        self._loaded_skills: dict[str, BaseSkill] = {}
        self._skill_configs: dict[str, SkillConfig] = {}
        self._skill_metadata: dict[str, dict[str, Any]] = {}

    def discover_skills(self) -> dict[str, dict[str, Any]]:
        """Discover all available skills from skills directory and builtin."""
        skills = {}

        # Discover from configured skills directory
        skills_dir = settings.skills_dir
        if skills_dir.exists():
            for skill_dir in skills_dir.iterdir():
                if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
                    metadata = self._parse_skill_metadata(skill_dir)
                    skills[metadata["name"]] = metadata

        # Discover from builtin skills
        builtin_dir = Path(__file__).parent / "builtin"
        if builtin_dir.exists():
            for skill_dir in builtin_dir.iterdir():
                if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
                    metadata = self._parse_skill_metadata(skill_dir)
                    if metadata["name"] not in skills:
                        skills[metadata["name"]] = metadata

        self._skill_metadata = skills
        return skills

    def _parse_skill_metadata(self, skill_dir: Path) -> dict[str, Any]:
        """Parse skill metadata from SKILL.md frontmatter."""
        skill_file = skill_dir / "SKILL.md"
        content = skill_file.read_text(encoding="utf-8")

        # Parse YAML frontmatter
        metadata = {
            "name": skill_dir.name,
            "path": str(skill_dir),
            "description": "",
            "version": "1.0.0",
            "category": self._infer_category(skill_dir.name),
            "priority": 10,
            "requires_target": True,
            "required_tools": [],
            "required_providers": [],
        }

        explicit_priority = False
        if content.startswith("---"):
            try:
                end_idx = content.index("---", 3)
                frontmatter = content[3:end_idx].strip()
                parsed = yaml.safe_load(frontmatter)
                if parsed:
                    metadata.update(parsed)
                    # Re-infer category if frontmatter did not specify one
                    if not parsed.get("category"):
                        metadata["category"] = self._infer_category(skill_dir.name)
                    explicit_priority = parsed.get("priority") is not None
            except (ValueError, yaml.YAMLError):
                pass

        # Infer priority from category unless the frontmatter set one explicitly
        if not explicit_priority:
            metadata["priority"] = self._infer_priority(metadata.get("category", "general"))

        return metadata

    @staticmethod
    def _infer_category(name: str) -> str:
        """Infer a skill's category from its name."""
        n = name.lower()
        if n.startswith("hunt-"):
            return "hunting"
        if any(k in n for k in ("recon", "osint", "enum", "subdomain", "web2")):
            return "recon"
        if any(k in n for k in ("triage", "validation", "validate")):
            return "validation"
        if any(k in n for k in ("report", "writing", "evidence", "hygiene")):
            return "reporting"
        if n in ("security-arsenal", "payload", "wordlist"):
            return "resources"
        if any(k in n for k in ("methodology", "mindset", "workflow", "bug-bounty", "dispatch")):
            return "methodology"
        if any(
            k in n
            for k in (
                "ad-attacker",
                "privesc",
                "lateral",
                "c2-",
                "persistence",
                "evasion",
                "container",
                "data-exfil",
                "exploit-chainer",
            )
        ):
            return "post-exploitation"
        if any(
            k in n
            for k in (
                "network-",
                "wireless",
                "mobile",
                "traffic-",
                "social-engineer",
                "phishing",
            )
        ):
            return "infrastructure"
        return "general"

    @staticmethod
    def _infer_priority(category: str) -> int:
        """Assign a default priority by category."""
        return {
            "recon": 1,
            "methodology": 2,
            "hunting": 5,
            "post-exploitation": 7,
            "infrastructure": 7,
            "validation": 8,
            "reporting": 9,
            "resources": 6,
            "general": 10,
        }.get(category, 10)

    def load_skill_configs(self) -> None:
        """Load skill configurations from settings."""
        for skill_config in settings.skills:
            self._skill_configs[skill_config.name] = skill_config

        # Add default skills if not configured
        for skill_name in settings.default_skills:
            if skill_name not in self._skill_configs:
                self._skill_configs[skill_name] = SkillConfig(
                    name=skill_name,
                    enabled=True,
                    priority=10,
                )

    def get_skill_config(self, name: str) -> SkillConfig:
        """Get skill configuration."""
        return self._skill_configs.get(name, SkillConfig(name=name, enabled=True))

    def is_enabled(self, name: str) -> bool:
        """Check if skill is enabled."""
        config = self.get_skill_config(name)
        return config.enabled

    def get_enabled_skills(self) -> list[str]:
        """Get list of enabled skill names."""
        return [name for name, config in self._skill_configs.items() if config.enabled]

    def get_skills_by_category(self, category: str) -> list[str]:
        """Get enabled skills by category."""
        enabled = self.get_enabled_skills()
        result = []
        for name in enabled:
            metadata = self._skill_metadata.get(name, {})
            if metadata.get("category") == category:
                result.append(name)
        return sorted(result, key=lambda n: self.get_skill_config(n).priority)

    async def load_skill(self, name: str) -> BaseSkill | None:
        """Load and instantiate a skill by name."""
        if name in self._loaded_skills:
            return self._loaded_skills[name]

        if not self.is_enabled(name):
            return None

        # Try to get registered class first
        skill_class = get_skill_class(name)
        if skill_class:
            config = self.get_skill_config(name)
            skill = skill_class(config)
            await skill.initialize()
            self._loaded_skills[name] = skill
            return skill

        # Try to load from builtin module
        try:
            skill = await self._load_builtin_skill(name)
            if skill:
                self._loaded_skills[name] = skill
                return skill
        except Exception:
            pass

        # Try to load from external skill directory
        try:
            skill = await self._load_external_skill(name)
            if skill:
                self._loaded_skills[name] = skill
                return skill
        except Exception:
            pass

        return None

    async def _load_builtin_skill(self, name: str) -> BaseSkill | None:
        """Load a builtin skill from agentx.skills.builtin."""
        module_path = f"agentx.skills.builtin.{name}"
        try:
            module = importlib.import_module(module_path)
            # Find skill class in module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseSkill) and attr is not BaseSkill:
                    config = self.get_skill_config(name)
                    skill = attr(config)
                    await skill.initialize()
                    return skill
        except ImportError:
            pass
        return None

    async def _load_external_skill(self, name: str) -> BaseSkill | None:
        """Load an external skill from skills directory."""
        metadata = self._skill_metadata.get(name)
        if not metadata:
            return None

        skill_dir = Path(metadata["path"])
        skill_file = skill_dir / "skill.py"

        if not skill_file.exists():
            # Create a dynamic skill from markdown only
            return await self._create_dynamic_skill(name, metadata)

        # Load skill module
        spec = importlib.util.spec_from_file_location(f"skill_{name}", skill_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseSkill) and attr is not BaseSkill:
                    config = self.get_skill_config(name)
                    skill = attr(config)
                    await skill.initialize()
                    return skill

        return None

    async def _create_dynamic_skill(self, name: str, metadata: dict[str, Any]) -> BaseSkill:
        """Create a dynamic skill from markdown documentation only."""
        from agentx.skills.base import HuntingSkill

        _skill_name = name  # avoid class-body self-shadowing (`name = name`)

        class DynamicSkill(HuntingSkill):
            name = _skill_name
            description = metadata.get("description", "")
            version = metadata.get("version", "1.0.0")
            category = metadata.get("category", "hunting")
            priority = metadata.get("priority", 10)
            requires_target = metadata.get("requires_target", True)
            required_tools = metadata.get("required_tools", [])
            required_providers = metadata.get("required_providers", [])

            def __init__(self, config: SkillConfig):
                super().__init__(config)
                self._markdown_content = ""

            async def execute(self, context) -> Any:
                # Load markdown content on first execution
                if not self._markdown_content:
                    skill_dir = Path(metadata["path"])
                    skill_file = skill_dir / "SKILL.md"
                    if skill_file.exists():
                        self._markdown_content = skill_file.read_text(encoding="utf-8")

                # Use AI to analyze and execute based on markdown
                prompt = f"""
Skill: {self.name}
Description: {self.description}

Markdown Documentation:
{self._markdown_content[:8000]}

Current Context:
- Target: {context.target}
- User Input: {context.user_input}
- Previous Findings: {len(context.previous_findings)} findings

Based on this skill's methodology, what should be the next actions?
Provide a structured plan with specific tool commands to run.
"""

                response = await self.call_ai(prompt, task_type="skill")
                return self._create_result(response, context)

        config = self.get_skill_config(name)
        skill = DynamicSkill(config)
        await skill.initialize()
        return skill

    async def execute_skill(self, name: str, context: Any) -> Any:
        """Execute a skill by name with context."""
        skill = await self.load_skill(name)
        if not skill:
            from agentx.skills.base import SkillResult

            return SkillResult(
                skill_name=name,
                success=False,
                errors=[f"Skill '{name}' not found or not enabled"],
            )

        skill.context = context
        try:
            result = await skill.execute(context)
            return result
        except Exception as e:
            from agentx.skills.base import SkillResult

            return SkillResult(
                skill_name=name,
                success=False,
                errors=[f"Skill execution failed: {str(e)}"],
            )

    async def execute_skill_chain(
        self,
        skill_names: list[str],
        context: Any,
    ) -> list[Any]:
        """Execute a chain of skills sequentially."""
        results = []
        current_context = context

        for skill_name in skill_names:
            result = await self.execute_skill(skill_name, current_context)
            results.append(result)

            # Update context with findings for next skill
            if result.findings:
                current_context.previous_findings.extend(result.findings)
                current_context.state[f"{skill_name}_findings"] = result.findings

        return results

    async def cleanup_all(self) -> None:
        """Cleanup all loaded skills."""
        for skill in self._loaded_skills.values():
            try:
                await skill.cleanup()
            except Exception:
                pass
        self._loaded_skills.clear()


# Global registry instance
skill_registry = SkillRegistry()
