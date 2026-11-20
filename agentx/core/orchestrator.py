"""AgentX Orchestrator - the brain that ties planning, execution and chat together."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentx.ai.prompts.orchestrator import ORCHESTRATOR_PROMPT
from agentx.ai.prompts.scope_guard import SCOPE_GUARD_PROMPT
from agentx.ai.router import router
from agentx.core.executor import ExecutionResult, executor
from agentx.core.planner import ExecutionPlan, planner
from agentx.core.session import HuntSession, session_manager
from agentx.mcp import mcp_manager
from agentx.skills.registry import skill_registry


@dataclass
class OrchestratorResponse:
    """Response from the orchestrator."""

    text: str
    plan: ExecutionPlan | None = None
    result: ExecutionResult | None = None
    kind: str = "chat"  # chat, plan, execution, info, error
    findings: list[dict[str, Any]] = field(default_factory=list)
    tool_traces: list[Any] = field(default_factory=list)


class Orchestrator:
    """Main orchestrator for AgentX."""

    def __init__(self, auto_execute: bool = False):
        self.auto_execute = auto_execute
        self._initialized = False
        self._pending_plan: ExecutionPlan | None = None

    async def initialize(self) -> None:
        """Initialize orchestrator and discover skills."""
        if self._initialized:
            return
        skill_registry.load_skill_configs()
        skill_registry.discover_skills()
        self._initialized = True

    async def handle_message(
        self,
        user_input: str,
        target: str | None = None,
        auto_execute: bool | None = None,
    ) -> OrchestratorResponse:
        """Handle a user message end-to-end."""
        await self.initialize()

        session = session_manager.get_session()
        if not session:
            session = session_manager.create_session(target or "")

        # Update target if provided
        if target:
            session.target = target
            session.context.target = target
        elif not session.target:
            detected = self._detect_target(user_input)
            if detected:
                session.target = detected
                session.context.target = detected

        # Record user message
        session_manager.add_conversation("user", user_input)

        # Handle pending-plan confirmation
        if self._pending_plan is not None and self._is_confirmation(user_input):
            plan = self._pending_plan
            self._pending_plan = None
            text = self._execution_start(plan)
            result = await executor.execute_plan(plan)
            text += "\n" + self._format_result(result)
            resp = OrchestratorResponse(
                text=text,
                plan=plan,
                result=result,
                kind="execution",
                findings=result.new_findings,
            )
            session_manager.add_conversation("assistant", resp.text, {"kind": resp.kind})
            return resp

        # Route the intent
        intent = self._classify_intent(user_input, session)

        if intent == "status":
            resp = await self._status_response(session)
        elif intent == "plan" or intent == "hunt":
            resp = await self._plan_and_maybe_execute(user_input, session, auto_execute)
        elif intent == "question":
            resp = await self._chat(user_input, session)
        else:
            resp = await self._chat(user_input, session)

        # Record assistant response
        session_manager.add_conversation("assistant", resp.text, {"kind": resp.kind})
        return resp

    def _classify_intent(self, user_input: str, session: HuntSession) -> str:
        """Classify user intent."""
        text = user_input.lower().strip()

        # Status requests
        if (
            re.search(r"\b(status|progress|findings|الوضع|الحالة|النتائج|إيه اللي)\b", text)
            and len(text) < 40
        ):
            return "status"

        # Explicit planning/hunting verbs
        hunt_keywords = [
            "hunt",
            "scan",
            "test",
            "recon",
            "enumerate",
            "fuzz",
            "probe",
            "find",
            "exploit",
            "check for",
            "look for",
            "اختبر",
            "افحص",
            "هجوم",
            "اكتشف",
            "ابحث",
            "حلل الموقع",
            "اختبر الموقع",
        ]
        if any(kw in text for kw in hunt_keywords):
            return "hunt"

        # Plan keywords
        plan_keywords = ["plan", "methodology", "approach", "خطة", "خطه", "منهجية"]
        if any(kw in text for kw in plan_keywords):
            return "plan"

        # Question keywords
        if text.endswith("?") or text.startswith(
            ("how", "what", "why", "when", "where", "which", "can ", "does ")
        ):
            return "question"
        if "?" in text and len(text) < 200:
            return "question"

        return "chat"

    def _is_confirmation(self, text: str) -> bool:
        """Check if a message confirms a pending plan."""
        t = text.strip().lower()
        return t in {
            "go",
            "run",
            "execute",
            "start",
            "yes",
            "y",
            "ok",
            "okay",
            "do it",
            "confirm",
            "proceed",
            "نفذ",
            "شغل",
            "ابدأ",
            "تمام",
            "ايوه",
            "نعم",
        }

    def _detect_target(self, text: str) -> str:
        """Attempt to detect a target URL/domain in the text."""
        url_match = re.search(r"https?://[^\s\"'<>]+", text)
        if url_match:
            return url_match.group(0)

        domain_match = re.search(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s\"'<>]*)?",
            text,
            re.IGNORECASE,
        )
        if domain_match and not domain_match.group(0).endswith((".md", ".py", ".txt")):
            return domain_match.group(0)
        return ""

    async def _plan_and_maybe_execute(
        self,
        user_input: str,
        session: HuntSession,
        auto_execute: bool | None,
    ) -> OrchestratorResponse:
        """Create a plan and optionally execute it."""
        if not session.target:
            return OrchestratorResponse(
                text=(
                    "I need a target to build a plan. Please provide a URL or domain "
                    "(e.g. `example.com`), or use `/target <url>`."
                ),
                kind="info",
            )

        session.context.user_input = user_input
        try:
            plan = await planner.create_plan(user_input, session.target)
        except Exception as exc:
            return OrchestratorResponse(
                text=(
                    "I couldn't reach an AI provider to build a plan.\n\n"
                    f"`{exc}`\n\n"
                    "Configure a provider in `config/default.yaml` (set `enabled: true` and an "
                    "API key), then restart AgentX."
                ),
                kind="error",
            )

        if not plan.steps:
            # No actionable steps; fall back to chat with plan analysis
            text = plan.analysis or "I couldn't derive an execution plan from that request."
            if plan.questions:
                text += "\n\nQuestions:\n" + "\n".join(f"- {q}" for q in plan.questions)
            return OrchestratorResponse(text=text, plan=plan, kind="plan")

        # Present the plan
        text = self._format_plan(plan)

        should_execute = auto_execute if auto_execute is not None else self.auto_execute
        if not should_execute:
            self._pending_plan = plan
            text += "\n\n_Reply `go` / `execute` to run this plan, or refine your request._"
            return OrchestratorResponse(text=text, plan=plan, kind="plan")

        # Execute
        text += "\n\n" + self._execution_start(plan)
        result = await executor.execute_plan(plan)
        text += "\n" + self._format_result(result)

        findings = result.new_findings
        return OrchestratorResponse(
            text=text, plan=plan, result=result, kind="execution", findings=findings
        )

    async def _chat(self, user_input: str, session: HuntSession) -> OrchestratorResponse:
        """Handle a conversational message (via MCP tools when connected)."""
        if mcp_manager.is_connected:
            from agentx.core.agent_loop import run_agent_loop

            loop = await run_agent_loop(user_input, session)
            resp = OrchestratorResponse(text=loop.text, kind="chat")
            resp.tool_traces = loop.traces
            return resp

        history = session_manager.get_conversation_history(limit=20)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": ORCHESTRATOR_PROMPT + "\n" + SCOPE_GUARD_PROMPT}
        ]

        for entry in history[-10:]:
            if entry.role in ("user", "assistant"):
                messages.append({"role": entry.role, "content": entry.content})

        context_note = (
            f"\n\n[Session context] target={session.target or 'unset'}, "
            f"phase={session.current_phase}, "
            f"findings={len(session.get_findings())}, "
            f"completed_skills={session.completed_skills}"
        )
        messages.append({"role": "user", "content": user_input + context_note})

        try:
            response = await router.complete(messages, task_type="orchestrator")
        except Exception as e:
            return OrchestratorResponse(
                text=f"AI request failed: {e}",
                kind="error",
            )

        return OrchestratorResponse(text=response, kind="chat")

    async def _status_response(self, session: HuntSession) -> OrchestratorResponse:
        """Build a status response."""
        findings = session.get_findings()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        lines = [
            f"Session: {session.id}",
            f"Target: {session.target or '(unset)'}",
            f"Phase: {session.current_phase}",
            f"Findings: {len(findings)} total",
        ]
        if by_sev:
            lines.append("  By severity: " + ", ".join(f"{k}={v}" for k, v in by_sev.items()))
        lines.append(
            "Completed skills: "
            + (", ".join(session.completed_skills) if session.completed_skills else "none")
        )
        lines.append(
            "Active skills: "
            + (", ".join(session.active_skills) if session.active_skills else "none")
        )

        # Suggest next skills
        suggestions: list[str] = []
        try:
            finding_dicts = [{"title": f.title} for f in findings]
            suggestions = await planner.suggest_next_skills(finding_dicts, session.completed_skills)
        except Exception:
            suggestions = []

        if suggestions:
            lines.append("Suggested next: " + ", ".join(suggestions))

        return OrchestratorResponse(text="\n".join(lines), kind="info")

    def _format_plan(self, plan: ExecutionPlan) -> str:
        """Format a plan for display."""
        out = ["# Execution Plan"]
        if plan.analysis:
            out.append(f"\n{plan.analysis}")
        if plan.selected_skills:
            out.append("\n## Skills")
            out.append(", ".join(plan.selected_skills))
        if plan.steps:
            out.append("\n## Steps")
            for i, step in enumerate(plan.steps, 1):
                out.append(f"{i}. [{step.skill}] {step.description}")
        if plan.questions:
            out.append("\n## Questions")
            for q in plan.questions:
                out.append(f"- {q}")
        if plan.estimated_time:
            out.append(f"\nEstimated time: {plan.estimated_time}")
        return "\n".join(out)

    def _execution_start(self, plan: ExecutionPlan) -> str:
        return f"Executing {len(plan.steps)} step(s)... [auto-execute]"

    def _format_result(self, result: ExecutionResult) -> str:
        """Format execution result."""
        lines = ["## Execution Result"]
        lines.append(f"Success: {result.success}")
        lines.append(f"Steps run: {len(result.step_results)}")
        lines.append(f"Findings: {result.total_findings}")
        if result.validation_summary:
            lines.append(result.validation_summary)
        if result.errors:
            lines.append("Errors:")
            for e in result.errors:
                lines.append(f"- {e}")
        for step_result in result.step_results:
            status = "OK" if step_result.success else "FAIL"
            lines.append(f"\n[{status}] {step_result.skill_name}: {step_result.summary}")
        return "\n".join(lines)


# Global orchestrator
orchestrator = Orchestrator()
