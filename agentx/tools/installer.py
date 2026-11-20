"""Tool installer - detects and installs external security tools."""

from __future__ import annotations

import asyncio
import shutil
import sys
from dataclasses import dataclass, field

from agentx.config import settings


@dataclass
class ToolSpec:
    """Specification for an external tool."""

    name: str
    binary: str
    description: str = ""
    install_method: str = "go"  # go, pip, apt, cargo, manual, git
    install_target: str = ""  # module/package/repo
    pip_package: str = ""
    go_package: str = ""
    git_repo: str = ""
    verify_args: list[str] = field(default_factory=lambda: ["--version"])


# Known external tools and how to install them
TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        "subfinder",
        "subfinder",
        "Subdomain enumeration",
        "go",
        go_package="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "httpx": ToolSpec(
        "httpx",
        "httpx",
        "HTTP probing",
        "go",
        go_package="github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
    "katana": ToolSpec(
        "katana",
        "katana",
        "Web crawler",
        "go",
        go_package="github.com/projectdiscovery/katana/cmd/katana@latest",
    ),
    "nuclei": ToolSpec(
        "nuclei",
        "nuclei",
        "Vulnerability scanner",
        "go",
        go_package="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    "ffuf": ToolSpec(
        "ffuf", "ffuf", "Web fuzzer", "go", go_package="github.com/ffuf/ffuf/v2@latest"
    ),
    "dnsx": ToolSpec(
        "dnsx",
        "dnsx",
        "DNS toolkit",
        "go",
        go_package="github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    ),
    "gau": ToolSpec(
        "gau", "gau", "Fetch known URLs", "go", go_package="github.com/lc/gau/v2/cmd/gau@latest"
    ),
    "waybackurls": ToolSpec(
        "waybackurls",
        "waybackurls",
        "Fetch wayback URLs",
        "go",
        go_package="github.com/tomnomnom/waybackurls@latest",
    ),
    "assetfinder": ToolSpec(
        "assetfinder",
        "assetfinder",
        "Find related assets",
        "go",
        go_package="github.com/tomnomnom/assetfinder@latest",
    ),
    "dalfox": ToolSpec(
        "dalfox", "dalfox", "XSS scanner", "go", go_package="github.com/hahwul/dalfox/v2@latest"
    ),
    "nmap": ToolSpec("nmap", "nmap", "Port scanner", "manual"),
    "sqlmap": ToolSpec(
        "sqlmap",
        "sqlmap",
        "SQL injection tool",
        "git",
        git_repo="https://github.com/sqlmapproject/sqlmap.git",
    ),
    "jq": ToolSpec("jq", "jq", "JSON processor", "manual"),
    "trufflehog": ToolSpec(
        "trufflehog",
        "trufflehog",
        "Secret scanner",
        "go",
        go_package="github.com/trufflesecurity/trufflehog/v3@latest",
    ),
    "gf": ToolSpec(
        "gf", "gf", "grep wrapper for patterns", "go", go_package="github.com/tomnomnom/gf@latest"
    ),
    "gitleaks": ToolSpec(
        "gitleaks",
        "gitleaks",
        "Secret scanner",
        "go",
        go_package="github.com/gitleaks/gitleaks/v8@latest",
    ),
    "subzy": ToolSpec(
        "subzy",
        "subzy",
        "Subdomain takeover scanner",
        "go",
        go_package="github.com/PentestPad/subzy@latest",
    ),
    "gobuster": ToolSpec(
        "gobuster",
        "gobuster",
        "Directory/DNS brute forcer",
        "go",
        go_package="github.com/OJ/gobuster/v3@latest",
    ),
    "amass": ToolSpec(
        "amass",
        "amass",
        "Attack surface mapping",
        "go",
        go_package="github.com/owasp-amass/amass/v4/...@master",
    ),
}


class ToolInstaller:
    """Detects and installs external tools."""

    def __init__(self):
        self._installed: dict[str, str] = {}  # name -> path

    def is_installed(self, tool: str) -> bool:
        """Check if a tool is installed and locatable."""
        if tool in self._installed:
            return True
        spec = TOOL_SPECS.get(tool)
        binary = spec.binary if spec else tool
        path = shutil.which(binary)
        if path:
            self._installed[tool] = path
            return True
        return False

    def get_path(self, tool: str) -> str | None:
        """Get the path to a tool binary."""
        if self.is_installed(tool):
            return self._installed.get(tool)
        return None

    async def install_tool(self, tool: str, force: bool = False) -> bool:
        """Install a tool if not already present."""
        if not force and self.is_installed(tool):
            return True

        spec = TOOL_SPECS.get(tool)
        if not spec:
            # Unknown tool - cannot auto-install
            return self.is_installed(tool)

        try:
            if spec.install_method == "go":
                return await self._install_go(spec)
            elif spec.install_method == "pip":
                return await self._install_pip(spec)
            elif spec.install_method == "git":
                return await self._install_git(spec)
            elif spec.install_method == "cargo":
                return await self._install_cargo(spec)
            else:
                # manual installation required
                return False
        except Exception:
            return False

    async def _install_go(self, spec: ToolSpec) -> bool:
        """Install a Go tool."""
        if not shutil.which("go"):
            return False
        target = spec.go_package or spec.name
        proc = await asyncio.create_subprocess_exec(
            "go",
            "install",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0 and self.is_installed(spec.name)

    async def _install_pip(self, spec: ToolSpec) -> bool:
        """Install a pip package."""
        pkg = spec.pip_package or spec.name
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "pip",
            "install",
            pkg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def _install_git(self, spec: ToolSpec) -> bool:
        """Clone a git repo into the tools dir."""
        if not spec.git_repo:
            return False
        dest = settings.tools_dir / spec.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            return True
        proc = await asyncio.create_subprocess_exec(
            "git",
            "clone",
            "--depth",
            "1",
            spec.git_repo,
            str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def _install_cargo(self, spec: ToolSpec) -> bool:
        """Install a Rust/cargo tool."""
        if not shutil.which("cargo"):
            return False
        proc = await asyncio.create_subprocess_exec(
            "cargo",
            "install",
            spec.install_target or spec.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    def check_all(self) -> dict[str, bool]:
        """Check installation status of all known tools."""
        return {name: self.is_installed(name) for name in TOOL_SPECS}

    def missing_tools(self) -> list[str]:
        """List tools that are not installed."""
        return [name for name in TOOL_SPECS if not self.is_installed(name)]

    def install_local_path(self, name: str, path: str) -> None:
        """Register a locally installed tool by explicit path."""
        self._installed[name] = path


# Global installer
_installer = ToolInstaller()


async def install_tool(tool: str, force: bool = False) -> bool:
    """Module-level convenience for installing a tool."""
    return await _installer.install_tool(tool, force=force)


def get_installer() -> ToolInstaller:
    return _installer
