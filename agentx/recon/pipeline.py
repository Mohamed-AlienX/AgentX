"""Recon pipeline - orchestrates reconnaissance tools and skills."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentx.tools.installer import get_installer
from agentx.tools.wrapper import tool_wrapper


@dataclass
class ReconResult:
    """Result of a reconnaissance stage."""

    stage: str
    success: bool
    data: Any = None
    error: str = ""
    count: int = 0


class ReconPipeline:
    """Runs a staged reconnaissance pipeline against a target."""

    def __init__(self):
        self.installer = get_installer()

    async def run(
        self,
        target: str,
        stages: list[str] | None = None,
    ) -> list[ReconResult]:
        """Run recon stages against the target."""
        stages = stages or ["subdomains", "http_probe", "urls", "fingerprint"]
        results: list[ReconResult] = []

        for stage in stages:
            handler = getattr(self, f"_stage_{stage}", None)
            if not handler:
                results.append(ReconResult(stage=stage, success=False, error="unknown stage"))
                continue
            try:
                result = await handler(target)
            except Exception as e:
                result = ReconResult(stage=stage, success=False, error=str(e))
            results.append(result)

        return results

    async def _stage_subdomains(self, target: str) -> ReconResult:
        """Enumerate subdomains with subfinder."""
        if not self.installer.is_installed("subfinder"):
            return ReconResult("subdomains", False, error="subfinder not installed")

        domain = self._extract_domain(target)
        result = await tool_wrapper.run("subfinder", ["-d", domain, "-silent"], parse=True)
        subs = result.parsed_output or []
        return ReconResult(
            "subdomains",
            result.success,
            data=subs,
            count=len(subs),
            error=result.stderr if not result.success else "",
        )

    async def _stage_http_probe(self, target: str) -> ReconResult:
        """Probe live HTTP services with httpx."""
        if not self.installer.is_installed("httpx"):
            return ReconResult("http_probe", False, error="httpx not installed")

        host = self._extract_domain(target)
        result = await tool_wrapper.run(
            "httpx",
            ["-u", host, "-silent", "-json", "-title", "-tech-detect", "-status-code"],
            parse=True,
        )
        data = result.parsed_output or []
        return ReconResult(
            "http_probe",
            result.success,
            data=data,
            count=len(data),
            error=result.stderr if not result.success else "",
        )

    async def _stage_urls(self, target: str) -> ReconResult:
        """Gather known URLs via gau/waybackurls."""
        tool = (
            "gau"
            if self.installer.is_installed("gau")
            else ("waybackurls" if self.installer.is_installed("waybackurls") else None)
        )
        if not tool:
            return ReconResult("urls", False, error="gau/waybackurls not installed")

        domain = self._extract_domain(target)
        result = await tool_wrapper.run(tool, [domain], parse=True)
        urls = result.parsed_output or []
        return ReconResult(
            "urls",
            result.success,
            data=urls[:5000],
            count=len(urls),
            error=result.stderr if not result.success else "",
        )

    async def _stage_fingerprint(self, target: str) -> ReconResult:
        """Fingerprint the target technologies."""
        url = target if target.startswith("http") else f"https://{target}"
        if not self.installer.is_installed("httpx"):
            return ReconResult("fingerprint", False, error="httpx not installed")

        result = await tool_wrapper.run(
            "httpx",
            ["-u", url, "-silent", "-json", "-tech-detect", "-web-server", "-title"],
            parse=True,
        )
        data = result.parsed_output or []
        return ReconResult(
            "fingerprint",
            result.success,
            data=data,
            count=len(data),
            error=result.stderr if not result.success else "",
        )

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Strip scheme/path to get the bare domain."""
        t = target.strip()
        if "://" in t:
            t = t.split("://", 1)[1]
        t = t.split("/", 1)[0]
        t = t.split(":", 1)[0]
        return t

    def available_stages(self) -> list[str]:
        return ["subdomains", "http_probe", "urls", "fingerprint"]


# Global pipeline
recon_pipeline = ReconPipeline()
