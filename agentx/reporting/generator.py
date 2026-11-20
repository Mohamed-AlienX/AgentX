"""Report generator - renders findings into deliverable formats."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agentx.config import settings
from agentx.core.memory import Finding
from agentx.mitre import technique_url
from agentx.mitre_mapping import get_mitre_for_skill

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_EMOJI = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}


class ReportGenerator:
    """Generates reports from findings."""

    def __init__(self, templates_dir: Path | None = None):
        self.templates_dir = templates_dir or settings.report_templates_dir

    def generate(
        self,
        findings: list[Finding],
        target: str = "",
        session_id: str = "",
        fmt: str = "markdown",
        title: str | None = None,
    ) -> str:
        """Generate a report in the requested format."""
        fmt = fmt.lower()
        if fmt == "json":
            return self._to_json(findings, target, session_id)
        elif fmt == "html":
            return self._to_html(findings, target, session_id, title)
        else:
            return self._to_markdown(findings, target, session_id, title)

    def save(
        self,
        findings: list[Finding],
        target: str = "",
        session_id: str = "",
        fmt: str = "markdown",
        output_path: Path | None = None,
    ) -> Path:
        """Generate and save a report to disk."""
        content = self.generate(findings, target, session_id, fmt)

        if output_path is None:
            ext = {"markdown": "md", "html": "html", "json": "json"}.get(fmt, "md")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            reports_dir = settings.data_dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = reports_dir / f"report_{session_id or 'session'}_{stamp}.{ext}"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _sorted(self, findings: list[Finding]) -> list[Finding]:
        def key(f: Finding) -> int:
            try:
                return SEVERITY_ORDER.index(f.severity.upper())
            except ValueError:
                return len(SEVERITY_ORDER)

        return sorted(findings, key=key)

    def _to_json(self, findings: list[Finding], target: str, session_id: str) -> str:
        data = {
            "target": target,
            "session_id": session_id,
            "generated_at": datetime.now().isoformat(),
            "summary": self._summary(findings),
            "findings": [self._finding_to_dict(f) for f in self._sorted(findings)],
        }
        return json.dumps(data, indent=2, default=str)

    def _to_markdown(
        self,
        findings: list[Finding],
        target: str,
        session_id: str,
        title: str | None,
    ) -> str:
        title = title or f"Security Assessment Report - {target or 'Target'}"
        lines = [
            f"# {title}",
            "",
            f"**Target:** {target or 'N/A'}  ",
            f"**Session:** {session_id or 'N/A'}  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Total Findings:** {len(findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        summary = self._summary(findings)
        for sev in SEVERITY_ORDER:
            lines.append(f"| {sev} | {summary.get(sev, 0)} |")

        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for i, f in enumerate(self._sorted(findings), 1):
            lines.append(f"### {i}. [{f.severity}] {f.title}")
            lines.append("")
            lines.append(f"- **Endpoint:** `{f.endpoint}`")
            lines.append(f"- **Skill:** {f.skill_name}")
            techniques = get_mitre_for_skill(f.skill_name)
            if techniques:
                links = ", ".join(f"[{t}]({technique_url(t)})" for t in techniques)
                lines.append(f"- **ATT&CK:** {links}")
            if f.cvss_score is not None:
                lines.append(f"- **CVSS:** {f.cvss_score}")
            lines.append(f"- **Validated:** {'Yes' if f.validated else 'No'}")
            lines.append("")
            lines.append("**Description**")
            lines.append("")
            lines.append(f.description or "_No description provided._")
            lines.append("")
            lines.append("**Impact**")
            lines.append("")
            lines.append(f.impact or "_No impact provided._")
            lines.append("")
            lines.append("**Steps to Reproduce**")
            lines.append("")
            for step_num, step in enumerate(f.steps_to_reproduce, 1):
                lines.append(f"{step_num}. {step}")
            if not f.steps_to_reproduce:
                lines.append("_None provided._")
            lines.append("")
            if f.evidence:
                lines.append("**Evidence**")
                lines.append("")
                lines.append("```")
                lines.append(json.dumps(f.evidence, indent=2, default=str)[:4000])
                lines.append("```")
                lines.append("")

        return "\n".join(lines)

    def _to_html(
        self,
        findings: list[Finding],
        target: str,
        session_id: str,
        title: str | None,
    ) -> str:
        title = title or f"Security Assessment Report - {target or 'Target'}"
        summary = self._summary(findings)

        rows = "\n".join(
            f"<tr><td>{sev}</td><td>{summary.get(sev, 0)}</td></tr>" for sev in SEVERITY_ORDER
        )

        finding_blocks = []
        for i, f in enumerate(self._sorted(findings), 1):
            steps = "".join(f"<li>{s}</li>" for s in f.steps_to_reproduce)
            techniques = get_mitre_for_skill(f.skill_name)
            attack_line = (
                f"<p><strong>ATT&amp;CK:</strong> {', '.join(techniques)}</p>" if techniques else ""
            )
            finding_blocks.append(f"""
            <div class="finding">
              <h3>{i}. <span class="sev-{f.severity.lower()}">{f.severity}</span> {f.title}</h3>
              <p><strong>Endpoint:</strong> <code>{f.endpoint}</code></p>
              <p><strong>Skill:</strong> {f.skill_name}</p>
              {attack_line}
              <h4>Description</h4><p>{f.description}</p>
              <h4>Impact</h4><p>{f.impact}</p>
              <h4>Steps to Reproduce</h4><ol>{steps}</ol>
            </div>""")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px; color: #1a1a1a; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 8px; }}
  table {{ border-collapse: collapse; margin: 12px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 12px; }}
  .finding {{ border: 1px solid #ddd; border-radius: 6px; padding: 16px; margin: 16px 0; }}
  .sev-critical {{ color: #b00020; font-weight: bold; }}
  .sev-high {{ color: #d35400; font-weight: bold; }}
  .sev-medium {{ color: #b8860b; font-weight: bold; }}
  .sev-low {{ color: #2e7d32; font-weight: bold; }}
  .sev-info {{ color: #555; font-weight: bold; }}
  code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p><strong>Target:</strong> {target or "N/A"}<br>
<strong>Session:</strong> {session_id or "N/A"}<br>
<strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<h2>Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>{rows}</table>
<h2>Findings</h2>
{"".join(finding_blocks) if finding_blocks else "<p>No findings.</p>"}
</body>
</html>"""

    def _summary(self, findings: list[Finding]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in findings:
            sev = f.severity.upper()
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def _finding_to_dict(self, f: Finding) -> dict[str, Any]:
        return {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "description": f.description,
            "impact": f.impact,
            "steps_to_reproduce": f.steps_to_reproduce,
            "evidence": f.evidence,
            "cvss_score": f.cvss_score,
            "validated": f.validated,
            "validation_notes": f.validation_notes,
            "skill": f.skill_name,
            "mitre_attack": get_mitre_for_skill(f.skill_name),
            "timestamp": f.timestamp.isoformat(),
        }


report_generator = ReportGenerator()
