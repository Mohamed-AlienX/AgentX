"""Skill executor for AgentX - runs skills and manages execution flow."""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Any

from agentx.config import settings
from agentx.core.handoff import FallbackHandoff
from agentx.core.intelligence import AttackVector, HandoffEnvelope, from_handoff
from agentx.core.planner import ExecutionPlan, PlanStep
from agentx.core.proof import ProofGate
from agentx.core.scope_control import ScopeDecision, ScopeGuard
from agentx.core.service_scoring import rank_attack_vectors
from agentx.core.session import HuntSession, session_manager
from agentx.core.trace import AuditTrace
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
    fallback_handoffs: list[FallbackHandoff] = field(default_factory=list)
    plan_only: bool = False
    aborted: bool = False
    abort_reason: str = ""


class SkillExecutor:
    """Executes skills according to plan."""

    def __init__(self):
        self._running = False
        self._current_step: PlanStep | None = None
        self._aborted = False
        self._abort_reason = ""

    async def execute_plan(
        self,
        plan: ExecutionPlan,
        *,
        plan_only: bool = False,
        scope_guard: ScopeGuard | None = None,
        proof_gate: ProofGate | None = None,
        trace: AuditTrace | None = None,
        handoff: HandoffEnvelope | dict[str, Any] | None = None,
        attack_vectors: list[AttackVector] | None = None,
    ) -> ExecutionResult:
        """Execute a full plan."""
        self._running = True
        self._aborted = False
        self._abort_reason = ""
        result = ExecutionResult(plan=plan, plan_only=plan_only)
        session = session_manager.get_session()

        if not session:
            result.success = False
            result.errors.append("No active session")
            self._running = False
            return result

        envelope = self._coerce_handoff(handoff)
        ordered_vectors = self._ordered_vectors(envelope, attack_vectors)
        steps = self._steps_for_execution(plan, ordered_vectors)

        self._trace(
            trace,
            phase="plan",
            prompt=plan.analysis or "execute plan",
            tool_call={
                "name": "execute_plan",
                "args": {"plan_only": plan_only, "steps": len(steps)},
            },
            decision_rationale="plan_only requested" if plan_only else "executing plan",
            target=session.target,
        )

        if plan_only:
            self._running = False
            return result

        session_manager.update_phase("hunting")
        preflight = self._preflight(
            session.target,
            action=f"execute_plan:{plan.target or session.target}",
            scope_guard=scope_guard,
            trace=trace,
            phase="preflight",
        )
        if not preflight.allowed:
            self._mark_aborted(result, preflight.reason)
            self._running = False
            return result

        for index, step in enumerate(steps):
            if not self._running:
                if self._aborted:
                    self._mark_aborted(result, self._abort_reason or "aborted")
                else:
                    result.errors.append("Execution stopped by user")
                break

            self._current_step = step
            session_manager.add_active_skill(step.skill)
            vector = self._vector_for_step(step, ordered_vectors, index)
            next_vector = self._next_vector(ordered_vectors, index)
            step_started = time.monotonic()

            try:
                step_preflight = self._preflight(
                    session.target,
                    action=f"skill:{step.skill}",
                    scope_guard=scope_guard,
                    trace=trace,
                    phase="preflight",
                )
                if not step_preflight.allowed:
                    failure = step_preflight.reason
                    step_result = SkillResult(
                        skill_name=step.skill, success=False, errors=[failure]
                    )
                    result.step_results.append(step_result)
                    result.errors.append(failure)
                    result.success = False
                    self._record_fallback(
                        result,
                        vector=vector,
                        next_vector=next_vector,
                        failure_reason=failure,
                        duration=time.monotonic() - step_started,
                        session=session,
                        trace=trace,
                    )
                    if step_preflight.category == "abort":
                        self._mark_aborted(result, failure)
                        break
                    continue

                self._trace(
                    trace,
                    phase="tool_call",
                    prompt=step.description or step.skill,
                    tool_call={"name": step.skill, "args": {"target": session.target}},
                    decision_rationale=step.reason or "execute planned step",
                    target=session.target,
                )

                step_result = await self._execute_step(step, session.context)
                result.step_results.append(step_result)

                proof_ok, proof_reason = self._proof_check(step_result, proof_gate)
                if step_result.success and not proof_ok:
                    step_result.success = False
                    step_result.findings = []
                    step_result.errors.append(proof_reason)

                if step_result.success:
                    session_manager.complete_skill(step.skill)
                    if step_result.findings:
                        result.total_findings += len(step_result.findings)
                        result.new_findings.extend(step_result.findings)
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
                    self._trace(
                        trace,
                        phase="observation",
                        prompt=step.skill,
                        tool_call={"name": step.skill, "result": "success"},
                        decision_rationale=step_result.summary or "step succeeded",
                        target=session.target,
                    )
                else:
                    failure = "; ".join(step_result.errors) or proof_reason or "step failed"
                    result.errors.extend(step_result.errors)
                    self._record_fallback(
                        result,
                        vector=vector,
                        next_vector=next_vector,
                        failure_reason=failure,
                        duration=time.monotonic() - step_started,
                        session=session,
                        trace=trace,
                    )
                    self._trace(
                        trace,
                        phase="decision",
                        prompt=step.skill,
                        tool_call={"name": step.skill, "result": "failed"},
                        decision_rationale=failure,
                        target=session.target,
                    )

            except Exception as e:
                error_msg = f"Step {step.skill} failed: {str(e)}"
                result.errors.append(error_msg)
                result.success = False
                traceback.print_exc()
                self._record_fallback(
                    result,
                    vector=vector,
                    next_vector=next_vector,
                    failure_reason=error_msg,
                    duration=time.monotonic() - step_started,
                    session=session,
                    trace=trace,
                )

        if settings.auto_triage:
            await self._run_post_hunt_triage(result, session, proof_gate=proof_gate, trace=trace)
        else:
            session_manager.update_phase("validation" if result.new_findings else "hunting")

        self._running = False
        self._current_step = None
        return result

    async def _run_post_hunt_triage(
        self,
        result: ExecutionResult,
        session: HuntSession,
        *,
        proof_gate: ProofGate | None = None,
        trace: AuditTrace | None = None,
    ) -> None:
        """Automated post-hunt stage: triage every untriaged finding."""
        findings = [f for f in session.get_findings() if not f.validation_notes]
        if not findings:
            session_manager.update_phase("hunting")
            return

        session_manager.update_phase("validation")
        gate = proof_gate or ProofGate()
        for finding in findings:
            proof = gate.evaluate(finding)
            if not proof.accepted:
                finding.validated = False
                finding.validation_notes = proof.reason
                from agentx.core.memory import memory

                memory.update_finding(finding)
                self._trace(
                    trace,
                    phase="triage",
                    prompt=finding.title,
                    tool_call={"name": "proof_gate", "result": "rejected"},
                    decision_rationale=proof.reason,
                    target=session.target,
                )

        remaining = [f for f in findings if not f.validation_notes]
        passed, total = triage_findings(remaining)
        rejected = len(findings) - len(remaining)
        result.validation_summary = (
            f"Triage: {passed}/{total} finding(s) passed the automated gate"
            + (f"; {rejected} rejected by proof gate." if rejected else ".")
        )
        session_manager.complete_skill("triage-validation")

    async def _execute_step(self, step: PlanStep, context: SkillContext) -> SkillResult:
        """Execute a single plan step."""
        if not skill_registry.is_enabled(step.skill):
            return SkillResult(
                skill_name=step.skill,
                success=False,
                errors=[f"Skill '{step.skill}' is not enabled"],
            )

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
        *,
        scope_guard: ScopeGuard | None = None,
        proof_gate: ProofGate | None = None,
        trace: AuditTrace | None = None,
    ) -> SkillResult:
        """Execute a single skill directly."""
        session = session_manager.get_session()
        if not session:
            return SkillResult(
                skill_name=skill_name,
                success=False,
                errors=["No active session"],
            )

        preflight = self._preflight(
            session.target,
            action=f"skill:{skill_name}",
            scope_guard=scope_guard,
            trace=trace,
            phase="preflight",
        )
        if not preflight.allowed:
            return SkillResult(skill_name=skill_name, success=False, errors=[preflight.reason])

        skill_context = context or session.context
        session_manager.add_active_skill(skill_name)

        try:
            self._trace(
                trace,
                phase="tool_call",
                prompt=skill_name,
                tool_call={"name": skill_name, "args": {"target": session.target}},
                decision_rationale="execute single skill",
                target=session.target,
            )
            result = await skill_registry.execute_skill(skill_name, skill_context)
            proof_ok, proof_reason = self._proof_check(result, proof_gate)
            if result.success and not proof_ok:
                result.success = False
                result.findings = []
                result.errors.append(proof_reason)
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

    def abort(self, reason: str = "aborted") -> None:
        """Trip kill-switch and stop current execution."""
        self._aborted = True
        self._abort_reason = reason or "aborted"
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_step(self) -> PlanStep | None:
        return self._current_step

    @staticmethod
    def _coerce_handoff(
        handoff: HandoffEnvelope | dict[str, Any] | None,
    ) -> HandoffEnvelope | None:
        if handoff is None:
            return None
        if isinstance(handoff, HandoffEnvelope):
            return handoff
        if isinstance(handoff, dict):
            return from_handoff(handoff)
        return None

    @staticmethod
    def _ordered_vectors(
        envelope: HandoffEnvelope | None,
        attack_vectors: list[AttackVector] | None,
    ) -> list[AttackVector]:
        if attack_vectors is not None:
            return rank_attack_vectors(
                type(
                    "BI",
                    (),
                    {
                        "discovered_services": [],
                        "target_intelligence": type("TI", (), {"profile": {}})(),
                        "vulnerabilities": [],
                        "attack_vectors": list(attack_vectors),
                    },
                )()
            )
        if envelope is None:
            return []
        return rank_attack_vectors(envelope.brain_intelligence)

    @staticmethod
    def _steps_for_execution(
        plan: ExecutionPlan, ordered_vectors: list[AttackVector]
    ) -> list[PlanStep]:
        if not ordered_vectors:
            return list(plan.steps)
        vector_order = {vector.id: idx for idx, vector in enumerate(ordered_vectors) if vector.id}
        if not vector_order:
            return list(plan.steps)

        annotated: list[tuple[int, int, PlanStep]] = []
        for index, step in enumerate(plan.steps):
            rank = vector_order.get(step.skill)
            if rank is None:
                rank = vector_order.get(getattr(step, "vector_id", ""), len(vector_order) + index)
            annotated.append((rank, index, step))
        annotated.sort(key=lambda item: (item[0], item[1]))
        return [step for _, _, step in annotated]

    @staticmethod
    def _vector_for_step(
        step: PlanStep, ordered_vectors: list[AttackVector], index: int
    ) -> AttackVector | None:
        if not ordered_vectors:
            return None
        for vector in ordered_vectors:
            if vector.id and vector.id == step.skill:
                return vector
            if vector.id and vector.id == getattr(step, "vector_id", ""):
                return vector
        if index < len(ordered_vectors):
            return ordered_vectors[index]
        return None

    @staticmethod
    def _next_vector(ordered_vectors: list[AttackVector], index: int) -> AttackVector | None:
        if index + 1 < len(ordered_vectors):
            return ordered_vectors[index + 1]
        return None

    def _preflight(
        self,
        target: str,
        *,
        action: str,
        scope_guard: ScopeGuard | None,
        trace: AuditTrace | None,
        phase: str,
    ) -> ScopeDecision:
        if self._aborted:
            decision = ScopeDecision(False, self._abort_reason or "aborted", "abort")
        elif scope_guard is None:
            decision = ScopeDecision(True)
        else:
            decision = scope_guard.preflight(target, action=action)
        if not decision.allowed:
            self._trace(
                trace,
                phase=phase,
                prompt=action,
                tool_call={"name": "scope_guard", "result": decision.category},
                decision_rationale=decision.reason,
                target=target,
            )
        return decision

    def _proof_check(self, result: SkillResult, proof_gate: ProofGate | None) -> tuple[bool, str]:
        if not result.success:
            return True, ""
        if not result.findings:
            return True, ""
        gate = proof_gate or ProofGate()
        for finding in result.findings:
            proof = gate.evaluate(finding)
            if not proof.accepted:
                return False, proof.reason
        return True, ""

    def _record_fallback(
        self,
        result: ExecutionResult,
        *,
        vector: AttackVector | None,
        next_vector: AttackVector | None,
        failure_reason: str,
        duration: float,
        session: HuntSession,
        trace: AuditTrace | None,
    ) -> None:
        service = ""
        port = None
        if vector is not None:
            service = str(vector.target_service.get("service", "")) if vector.target_service else ""
            port = vector.target_port
        handoff = FallbackHandoff(
            attempted_vector_id=(
                vector.id
                if vector and vector.id
                else (self._current_step.skill if self._current_step else "unknown")
            ),
            attempted_cve=vector.cve_id if vector else None,
            failure_reason=failure_reason,
            service=service,
            port=port,
            duration_seconds=round(max(duration, 0.0), 3),
            next_vector_id=next_vector.id if next_vector else None,
        )
        result.fallback_handoffs.append(handoff)
        self._trace(
            trace,
            phase="fallback",
            prompt=handoff.attempted_vector_id,
            tool_call={"name": "fallback_handoff", "result": handoff.next_vector_id or "none"},
            decision_rationale=failure_reason,
            target=session.target,
        )

    @staticmethod
    def _trace(
        trace: AuditTrace | None,
        *,
        phase: str,
        prompt: str,
        tool_call: dict[str, Any],
        decision_rationale: str,
        target: str,
    ) -> None:
        if trace is None:
            return
        trace.append(
            phase=phase,
            prompt=prompt,
            tool_call=tool_call,
            decision_rationale=decision_rationale,
            target=target,
        )

    def _mark_aborted(self, result: ExecutionResult, reason: str) -> None:
        result.aborted = True
        result.abort_reason = reason
        result.success = False
        if reason not in result.errors:
            result.errors.append(reason)


# Global executor
executor = SkillExecutor()
