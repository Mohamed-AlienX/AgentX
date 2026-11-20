"""Skill executor for AgentX - runs skills and manages execution flow."""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any

from agentx.config import settings
from agentx.core.planner import ExecutionPlan, PlanStep
from agentx.core.session import HuntSession, session_manager
from agentx.core.triage import triage_findings
from agentx.skills.base import SkillContext, SkillResult
from agentx.skills.registry import skill_registry


@dataclass
class ExecutionResult:
    """Result of plan execution."""

    plan: ExecutionPlan
    step_results: list[SkillResult] = field(default_factory=list)
    success: bool = True
    errors: list[str] = field(default_factory=list)
    total_findings: int = 0
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    validation_summary: str = ""


class SkillExecutor:
    """Executes skills according to plan."""

    def __init__(self):
        self._running = False
        self._current_step: PlanStep | None = None

    async def execute_plan(self, plan: ExecutionPlan) -> ExecutionResult:
        """Execute a full plan."""
        self._running = True
        result = ExecutionResult(plan=plan)
        session = session_manager.get_session()

        if not session:
            result.success = False
            result.errors.append("No active session")
            return result

        # Update session phase
        session_manager.update_phase("hunting")

        for step in plan.steps:
            if not self._running:
                result.errors.append("Execution stopped by user")
                break

            self._current_step = step
            session_manager.add_active_skill(step.skill)

            try:
                step_result = await self._execute_step(step, session.context)
                result.step_results.append(step_result)

                if step_result.success:
                    session_manager.complete_skill(step.skill)
                    if step_result.findings:
                        result.total_findings += len(step_result.findings)
                        result.new_findings.extend(step_result.findings)
                        # Add findings to session
                        for finding in step_result.findings:
                            from agentx.core.memory import Finding

                            finding_obj = Finding(
                                id=f"finding_{len(session.get_findings()) + 1}",
                                session_id=session.id,
                                skill_name=step.skill,
                                title=finding.get("title", ""),
                                severity=finding.get("severity", "MEDIUM"),
                                endpoint=finding.get("endpoint", ""),
                                description=finding.get("description", ""),
                                impact=finding.get("impact", ""),
                                steps_to_reproduce=finding.get("steps_to_reproduce", []),
                                evidence=finding.get("evidence", {}),
                                cvss_score=finding.get("cvss_score"),
                            )
                            session_manager.add_finding(finding_obj)
                else:
                    result.errors.extend(step_result.errors)
                    # Continue with next step unless critical

            except Exception as e:
                error_msg = f"Step {step.skill} failed: {str(e)}"
                result.errors.append(error_msg)
                traceback.print_exc()
                result.success = False

        if settings.auto_triage:
            await self._run_post_hunt_triage(result, session)
        else:
            session_manager.update_phase("validation" if result.new_findings else "hunting")

        self._running = False
        return result

    async def _run_post_hunt_triage(
        self,
        result: ExecutionResult,
        session: HuntSession,
    ) -> None:
        """Automated post-hunt stage: triage every untriaged finding.

        Runs the local 7-Question Gate over the session findings, persists the
        outcome, and records a summary so reports show what was validated.
        """
        findings = [f for f in session.get_findings() if not f.validation_notes]
        if not findings:
            session_manager.update_phase("hunting")
            return

        session_manager.update_phase("validation")
        passed, total = triage_findings(findings)
        result.validation_summary = (
            f"Triage: {passed}/{total} finding(s) passed the automated gate."
        )
        session_manager.complete_skill("triage-validation")

    async def _execute_step(self, step: PlanStep, context: SkillContext) -> SkillResult:
        """Execute a single plan step."""
        # Check if skill is enabled
        if not skill_registry.is_enabled(step.skill):
            return SkillResult(
                skill_name=step.skill,
                success=False,
                errors=[f"Skill '{step.skill}' is not enabled"],
            )

        # Execute skill
        try:
            result = await skill_registry.execute_skill(step.skill, context)
            return result
        except Exception as e:
            return SkillResult(
                skill_name=step.skill,
                success=False,
                errors=[f"Execution error: {str(e)}"],
            )

    async def execute_single_skill(
        self,
        skill_name: str,
        context: SkillContext | None = None,
    ) -> SkillResult:
        """Execute a single skill directly."""
        session = session_manager.get_session()
        if not session:
            return SkillResult(
                skill_name=skill_name,
                success=False,
                errors=["No active session"],
            )

        skill_context = context or session.context
        session_manager.add_active_skill(skill_name)

        try:
            result = await skill_registry.execute_skill(skill_name, skill_context)
            if result.success:
                session_manager.complete_skill(skill_name)
            return result
        except Exception as e:
            return SkillResult(
                skill_name=skill_name,
                success=False,
                errors=[f"Execution error: {str(e)}"],
            )
        finally:
            if skill_name in session.active_skills:
                session.active_skills.remove(skill_name)

    async def execute_skill_chain(
        self,
        skill_names: list[str],
        context: SkillContext | None = None,
    ) -> list[SkillResult]:
        """Execute a chain of skills."""
        session = session_manager.get_session()
        if not session:
            return [SkillResult(skill_name="chain", success=False, errors=["No active session"])]

        skill_context = context or session.context
        return await skill_registry.execute_skill_chain(skill_names, skill_context)

    def stop(self) -> None:
        """Stop current execution."""
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_step(self) -> PlanStep | None:
        return self._current_step


# Global executor
executor = SkillExecutor()
