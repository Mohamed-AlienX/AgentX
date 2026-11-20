"""Local tools integration - run user's local scripts and commands."""

from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentx.config import settings
from agentx.skills.base import ToolResult


@dataclass
class LocalTool:
    """A user-defined local tool/script."""

    name: str
    command: str  # template, e.g. "python scan.py --target {target}"
    description: str = ""
    args_schema: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    shell: bool = False


# Registry of local tools
LOCAL_TOOLS: dict[str, LocalTool] = {}


def register_local_tool(tool: LocalTool) -> None:
    """Register a local tool."""
    LOCAL_TOOLS[tool.name] = tool


def load_local_tools(config: dict[str, Any] | None = None) -> dict[str, LocalTool]:
    """Load local tools from settings/config."""
    tools_config = config if config is not None else settings.local_tools
    for name, spec in (tools_config or {}).items():
        if isinstance(spec, dict):
            register_local_tool(
                LocalTool(
                    name=name,
                    command=spec.get("command", ""),
                    description=spec.get("description", ""),
                    args_schema=spec.get("args", {}),
                    cwd=spec.get("cwd", ""),
                    shell=spec.get("shell", False),
                )
            )
    return LOCAL_TOOLS


def discover_scripts(scripts_dir: Path | None = None) -> list[Path]:
    """Discover runnable scripts in the scripts directory."""
    scripts_dir = scripts_dir or settings.scripts_dir
    if not scripts_dir.exists():
        return []

    scripts = []
    for ext in ("*.py", "*.sh", "*.ps1", "*.bat", "*.cmd"):
        scripts.extend(scripts_dir.glob(ext))
    return sorted(scripts)


class LocalToolRunner:
    """Runs user-defined local tools."""

    async def run(
        self,
        name: str,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        """Run a registered local tool by name."""
        tool = LOCAL_TOOLS.get(name)
        if not tool:
            return ToolResult(
                tool=name,
                success=False,
                stderr=f"Local tool '{name}' not registered",
                exit_code=127,
            )

        params = params or {}
        try:
            command = tool.command.format(**params)
        except KeyError as e:
            return ToolResult(
                tool=name,
                success=False,
                stderr=f"Missing parameter for local tool: {e}",
                exit_code=2,
            )

        start = time.time()
        cwd = tool.cwd or None

        try:
            if tool.shell:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                )
                cmd_display = command
            else:
                parts = shlex.split(command)
                proc = await asyncio.create_subprocess_exec(
                    *parts,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                )
                cmd_display = " ".join(parts)
        except OSError as e:
            return ToolResult(
                tool=name,
                success=False,
                stderr=f"Failed to start local tool: {e}",
                exit_code=127,
                duration_ms=int((time.time() - start) * 1000),
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout or settings.tool_timeout,
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                tool=name,
                success=False,
                stderr=f"Local tool timed out after {timeout or settings.tool_timeout}s",
                exit_code=124,
                duration_ms=int((time.time() - start) * 1000),
            )

        return ToolResult(
            tool=name,
            success=proc.returncode == 0,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            exit_code=proc.returncode or 0,
            duration_ms=int((time.time() - start) * 1000),
            parsed_output={"command": cmd_display},
        )

    async def run_script(
        self,
        script_path: str | Path,
        args: list[str] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        """Run an arbitrary local script file."""
        path = Path(script_path)
        if not path.exists():
            return ToolResult(
                tool=str(path),
                success=False,
                stderr=f"Script not found: {path}",
                exit_code=127,
            )

        # Determine interpreter by extension
        ext = path.suffix.lower()
        if ext == ".py":
            cmd = ["python", str(path), *(args or [])]
        elif ext == ".ps1":
            cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(path), *(args or [])]
        elif ext in (".bat", ".cmd"):
            cmd = [str(path), *(args or [])]
        elif ext == ".sh":
            cmd = ["bash", str(path), *(args or [])]
        else:
            cmd = [str(path), *(args or [])]

        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            return ToolResult(
                tool=str(path),
                success=False,
                stderr=f"Failed to start script: {e}",
                exit_code=127,
                duration_ms=int((time.time() - start) * 1000),
            )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout or settings.tool_timeout,
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                tool=str(path),
                success=False,
                stderr="Script timed out",
                exit_code=124,
                duration_ms=int((time.time() - start) * 1000),
            )

        return ToolResult(
            tool=str(path),
            success=proc.returncode == 0,
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            exit_code=proc.returncode or 0,
            duration_ms=int((time.time() - start) * 1000),
        )


# Global local tool runner
local_runner = LocalToolRunner()
