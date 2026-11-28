"""Cross-session handoff report generator and executor fallback records.

Generates a markdown handoff so a new session can resume an engagement
without re-reading raw history. Adapted from pentest-ai-agents `handoff.sh` (MIT).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from agentx.core.memory import memory

if TYPE_CHECKING:
    from agentx.core.session import HuntSession

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class FallbackHandoff:
    """Deterministic record for advancing past a failed vector."""

    attempted_vector_id: str
    attempted_cve: str | None
    failure_reason: str
    service: str
    port: int | None
    duration_seconds: float
    next_vector_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _mask_secret(secret: str) -> str:
    """Mask a credential secret for the handoff report."""
    if not secret:
        return "(empty)"
    if len(secret) <= 4:
        return "*" * len(secret)
    return secret[:2] + "*" * (len(secret) - 2)


def generate_handoff(session: HuntSession) -> str:
    """Build a markdown handoff report for the given session."""
    findings = session.get_findings()
    credentials = memory.get_credentials_by_session(session.id)
    chains = memory.get_chains_by_session(session.id)

    lines: list[str] = [
        f"# Handoff — session {session.id}",
        "",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- Target: {session.target or '(unset)'}",
        f"- Phase: {session.current_phase}",
        f"- Completed skills: {', '.join(session.completed_skills) or 'none'}",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("_No findings recorded yet._")
    else:
        by_sev: dict[str, list[Any]] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            by_sev.setdefault(f.severity.lower(), []).append(f)
        for sev in _SEVERITY_ORDER + tuple(k for k in by_sev if k not in _SEVERITY_ORDER):
            for f in by_sev.get(sev, []):
                mark = "[x]" if f.validated else "[ ]"
                lines.append(
                    f"- {mark} **{f.severity.upper()}** {f.title} — `{f.endpoint}`"
                    f" (skill: {f.skill_name})"
                )

    lines += ["", "## Credentials", ""]
    if not credentials:
        lines.append("_No credentials captured._")
    else:
        for c in credentials:
            who = c.username or "(user)"
            where = f" @ {c.host}" if c.host else ""
            lines.append(
                f"- {who}{where} — type={c.cred_type or '?'}"
                f", secret=`{_mask_secret(c.secret)}`"
                + (f", source={c.source}" if c.source else "")
            )
        lines.append("")
        lines.append(
            "> Secrets are masked in this report. Re-read the findings DB for full values."
        )

    lines += ["", "## Attack Chains", ""]
    if not chains:
        lines.append("_No attack chains defined._")
    else:
        for ch in chains:
            lines.append(
                f"- **{ch.name}** — status={ch.status}, score={ch.score},"
                f" steps={len(ch.steps)}" + (f", MITRE={', '.join(ch.mitre)}" if ch.mitre else "")
            )

    lines += ["", "## Suggested Next Steps", ""]
    unvalidated = [f for f in findings if not f.validated]
    if unvalidated:
        lines.append(f"- Validate {len(unvalidated)} unvalidated finding(s) (`/validate`).")
    if not session.target:
        lines.append("- Declare the target (`/target <url|domain>`).")
    lines.append("- Review findings above, then continue with the next planned skill.")
    lines.append("")
    return "\n".join(lines)


__all__ = ["FallbackHandoff", "generate_handoff"]
