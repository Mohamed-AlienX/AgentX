"""Tool wrapper - safely executes external security tools."""

from __future__ import annotations

import asyncio
import shlex
import time
from typing import Any

from agentx.config import settings
from agentx.skills.base import ToolResult
from agentx.tools.installer import TOOL_SPECS, get_installer


class ToolWrapper:
    """Executes external tools and captures results."""

    def __init__(self, default_timeout: int | None = None):
        self.default_timeout = default_timeout or settings.tool_timeout
        self.installer = get_installer()

    def _resolve_binary(self, tool: str) -> str | None:
        """Resolve the binary path for a tool."""
        if self.installer.is_installed(tool):
            return self.installer.get_path(tool)
        # Try direct which
        import shutil

        spec = TOOL_SPECS.get(tool)
        binary = spec.binary if spec else tool
        return shutil.which(binary)

    async def run(
        self,
        tool: str,
        args: list[str] | str,
        input_data: str | None = None,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        parse: bool = False,
    ) -> ToolResult:
        """Run a tool with the given arguments."""
        start = time.time()

        binary = self._resolve_binary(tool)
        if not binary:
            return ToolResult(
                tool=tool,
                success=False,
                stderr=f"Tool '{tool}' not found. Install it first.",
                exit_code=127,
            )

        if isinstance(args, str):
            arg_list = shlex.split(args)
        else:
            arg_list = list(args)

        cmd = [binary, *arg_list]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )

            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(input_data.encode() if input_data else None),
                    timeout=timeout or self.default_timeout,
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult(
                    tool=tool,
                    success=False,
                    stderr=f"Tool timed out after {timeout or self.default_timeout}s",
                    exit_code=124,
                    duration_ms=int((time.time() - start) * 1000),
                )

            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")

            result = ToolResult(
                tool=tool,
                success=proc.returncode == 0,
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode or 0,
                duration_ms=int((time.time() - start) * 1000),
            )

            if parse:
                result.parsed_output = self._parse_output(tool, stdout)

            return result

        except FileNotFoundError:
            return ToolResult(
                tool=tool,
                success=False,
                stderr=f"Binary for '{tool}' could not be executed",
                exit_code=127,
            )
        except Exception as e:
            return ToolResult(
                tool=tool,
                success=False,
                stderr=f"Execution error: {str(e)}",
                exit_code=1,
                duration_ms=int((time.time() - start) * 1000),
            )

    def _parse_output(self, tool: str, stdout: str) -> Any:
        """Parse tool output into structured data."""
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]

        # JSON output tools
        if tool in ("httpx", "katana", "nuclei", "dnsx"):
            import json

            results = []
            for line in lines:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    results.append({"raw": line})
            return results

        # Line-based output (one item per line)
        if tool in ("subfinder", "assetfinder", "gau", "waybackurls", "ffuf"):
            return lines

        return lines

    async def run_pipeline(
        self,
        steps: list[dict[str, Any]],
        initial_input: str | None = None,
    ) -> list[ToolResult]:
        """Run a pipeline of tools passing output to next."""
        results = []
        pipe_input = initial_input

        for step in steps:
            tool = step["tool"]
            args = step.get("args", [])
            result = await self.run(
                tool,
                args,
                input_data=pipe_input if step.get("stdin", True) else None,
                timeout=step.get("timeout"),
                parse=step.get("parse", False),
            )
            results.append(result)

            if result.success and result.stdout:
                pipe_input = result.stdout

        return results


# Global wrapper
tool_wrapper = ToolWrapper()


async def run_tool(tool: str, args: list[str] | str, **kwargs) -> ToolResult:
    """Convenience function to run a tool."""
    return await tool_wrapper.run(tool, args, **kwargs)
