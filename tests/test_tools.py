"""Hermetic tests for agentx.tools: wrapper, local_tools, installer.

No real external tool is ever executed: subprocess factories and shutil.which
are replaced with recording fakes, and filesystem writes stay in tmp_path.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentx.config import settings
from agentx.tools import installer as installer_mod
from agentx.tools import local_tools as local_mod
from agentx.tools import wrapper as wrapper_mod
from agentx.tools.installer import TOOL_SPECS, ToolInstaller, ToolSpec
from agentx.tools.local_tools import (
    LocalTool,
    LocalToolRunner,
    discover_scripts,
    load_local_tools,
    register_local_tool,
)
from agentx.tools.wrapper import ToolWrapper


class FakeProcess:
    """Stand-in for an asyncio subprocess object."""

    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int | None = 0,
        timeout: bool = False,
        error: BaseException | None = None,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._timeout = timeout
        self._error = error
        self.killed = False
        self.waited = False
        self.sent_input: bytes | None = None

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        self.sent_input = input
        if self._timeout:
            raise TimeoutError()
        if self._error is not None:
            raise self._error
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int | None:
        self.waited = True
        return self.returncode


class FakeSubprocess:
    """Recording replacement for asyncio.create_subprocess_exec/shell."""

    def __init__(self) -> None:
        self.exec_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.shell_calls: list[tuple[str, dict[str, Any]]] = []
        self._queue: list[FakeProcess] = []
        self.error: BaseException | None = None

    def queue(self, proc: FakeProcess) -> FakeProcess:
        self._queue.append(proc)
        return proc

    def _next(self) -> FakeProcess:
        if self._queue:
            return self._queue.pop(0)
        return FakeProcess()

    async def spawn_exec(self, *args: Any, **kwargs: Any) -> FakeProcess:
        self.exec_calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self._next()

    async def spawn_shell(self, command: str, **kwargs: Any) -> FakeProcess:
        self.shell_calls.append((command, kwargs))
        if self.error is not None:
            raise self.error
        return self._next()


@pytest.fixture
def fake_sub(monkeypatch: pytest.MonkeyPatch) -> FakeSubprocess:
    fake = FakeSubprocess()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake.spawn_exec)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", fake.spawn_shell)
    return fake


@pytest.fixture
def fake_which(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    table: dict[str, str | None] = {}
    calls: list[str] = []

    def _which(binary: str, *args: Any, **kwargs: Any) -> str | None:
        calls.append(binary)
        return table.get(binary)

    monkeypatch.setattr(shutil, "which", _which)
    return SimpleNamespace(table=table, calls=calls)


@pytest.fixture
def installer() -> ToolInstaller:
    return ToolInstaller()


@pytest.fixture
def wrapper(monkeypatch: pytest.MonkeyPatch) -> ToolWrapper:
    monkeypatch.setattr(wrapper_mod, "get_installer", lambda: ToolInstaller())
    return ToolWrapper(default_timeout=5)


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> dict[str, LocalTool]:
    tools: dict[str, LocalTool] = {}
    monkeypatch.setattr(local_mod, "LOCAL_TOOLS", tools)
    return tools


# --------------------------------------------------------------------------- #
# installer.py
# --------------------------------------------------------------------------- #


def test_is_installed_caches_which_result(installer: ToolInstaller, fake_which) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    assert installer.is_installed("subfinder") is True
    assert installer._installed["subfinder"] == "C:/bin/subfinder.exe"
    assert installer.is_installed("subfinder") is True
    assert fake_which.calls == ["subfinder"]


def test_is_installed_unknown_tool_uses_tool_name(installer: ToolInstaller, fake_which) -> None:
    fake_which.table["mytool"] = "C:/bin/mytool"
    assert installer.is_installed("mytool") is True
    assert fake_which.calls == ["mytool"]


def test_is_installed_missing_tool(installer: ToolInstaller, fake_which) -> None:
    assert installer.is_installed("nmap") is False
    assert installer._installed == {}
    assert fake_which.calls == ["nmap"]


def test_get_path(installer: ToolInstaller, fake_which) -> None:
    assert installer.get_path("jq") is None
    fake_which.table["jq"] = "C:/bin/jq.exe"
    assert installer.get_path("jq") == "C:/bin/jq.exe"


def test_install_local_path_registers_without_which(installer: ToolInstaller, fake_which) -> None:
    installer.install_local_path("custom", "C:/tools/custom.exe")
    assert installer.is_installed("custom") is True
    assert installer.get_path("custom") == "C:/tools/custom.exe"
    assert fake_which.calls == []


async def test_install_tool_skips_when_present(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    assert await installer.install_tool("subfinder") is True
    assert fake_sub.exec_calls == []


async def test_install_tool_go_success(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["go"] = "C:/go/go.exe"
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    fake_sub.queue(FakeProcess(returncode=0))
    assert await installer.install_tool("subfinder", force=True) is True
    args, kwargs = fake_sub.exec_calls[0]
    assert args == ("go", "install", TOOL_SPECS["subfinder"].go_package)
    assert kwargs["stdout"] == asyncio.subprocess.PIPE
    assert kwargs["stderr"] == asyncio.subprocess.PIPE


async def test_install_tool_go_failure_returncode(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["go"] = "C:/go/go.exe"
    fake_sub.queue(FakeProcess(returncode=1))
    assert await installer.install_tool("nuclei", force=True) is False


async def test_install_go_without_go_binary(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    assert await installer._install_go(TOOL_SPECS["gau"]) is False
    assert fake_sub.exec_calls == []


async def test_install_tool_unknown_tool(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    assert await installer.install_tool("definitely-not-a-tool") is False
    assert fake_sub.exec_calls == []
    assert fake_which.calls == ["definitely-not-a-tool"] * 2


async def test_install_tool_manual_method_returns_false(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    assert await installer.install_tool("nmap", force=True) is False
    assert fake_sub.exec_calls == []


async def test_install_tool_exception_returns_false(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["go"] = "C:/go/go.exe"
    fake_sub.error = RuntimeError("spawn failed")
    assert await installer.install_tool("httpx", force=True) is False


async def test_install_tool_pip_dispatch(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess, monkeypatch
) -> None:
    spec = ToolSpec(name="pipdemo", binary="pipdemo", install_method="pip", pip_package="demo-pkg")
    monkeypatch.setitem(TOOL_SPECS, "pipdemo", spec)
    fake_sub.queue(FakeProcess(returncode=0))
    assert await installer.install_tool("pipdemo", force=True) is True
    args, _kwargs = fake_sub.exec_calls[0]
    assert args == (sys.executable, "-m", "pip", "install", "demo-pkg")


async def test_install_pip_failure(installer: ToolInstaller, fake_sub: FakeSubprocess) -> None:
    spec = ToolSpec(name="pipfail", binary="pipfail", install_method="pip")
    fake_sub.queue(FakeProcess(returncode=1))
    assert await installer._install_pip(spec) is False


async def test_install_tool_cargo_dispatch(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess, monkeypatch
) -> None:
    spec = ToolSpec(
        name="cargodemo", binary="cargodemo", install_method="cargo", install_target="demo-crate"
    )
    monkeypatch.setitem(TOOL_SPECS, "cargodemo", spec)
    fake_which.table["cargo"] = "C:/cargo.exe"
    fake_sub.queue(FakeProcess(returncode=0))
    assert await installer.install_tool("cargodemo", force=True) is True
    args, _kwargs = fake_sub.exec_calls[0]
    assert args == ("cargo", "install", "demo-crate")


async def test_install_cargo_without_binary(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    spec = ToolSpec(name="cargodemo2", binary="x", install_method="cargo")
    assert await installer._install_cargo(spec) is False
    assert fake_sub.exec_calls == []


async def test_install_cargo_failure(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["cargo"] = "C:/cargo.exe"
    fake_sub.queue(FakeProcess(returncode=3))
    spec = ToolSpec(name="cargodemo3", binary="x", install_method="cargo")
    assert await installer._install_cargo(spec) is False


async def test_install_git_requires_repo(
    installer: ToolInstaller, fake_sub: FakeSubprocess
) -> None:
    spec = ToolSpec(name="nogit", binary="nogit", install_method="git", git_repo="")
    assert await installer._install_git(spec) is False
    assert fake_sub.exec_calls == []


async def test_install_git_skips_existing_dest(
    installer: ToolInstaller, fake_sub: FakeSubprocess, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    (tmp_path / "sqlmap").mkdir()
    assert await installer._install_git(TOOL_SPECS["sqlmap"]) is True
    assert fake_sub.exec_calls == []


async def test_install_git_clones_when_absent(
    installer: ToolInstaller, fake_sub: FakeSubprocess, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    fake_sub.queue(FakeProcess(returncode=0))
    spec = TOOL_SPECS["sqlmap"]
    assert await installer._install_git(spec) is True
    args, kwargs = fake_sub.exec_calls[0]
    assert args == ("git", "clone", "--depth", "1", spec.git_repo, str(tmp_path / "sqlmap"))
    assert kwargs["stdout"] == asyncio.subprocess.PIPE


async def test_install_git_clone_failure(
    installer: ToolInstaller, fake_sub: FakeSubprocess, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    fake_sub.queue(FakeProcess(returncode=128))
    assert await installer._install_git(TOOL_SPECS["sqlmap"]) is False


async def test_install_tool_git_dispatch(
    installer: ToolInstaller, fake_which, fake_sub: FakeSubprocess, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "tools_dir", tmp_path)
    fake_sub.queue(FakeProcess(returncode=0))
    assert await installer.install_tool("sqlmap") is True
    args, _kwargs = fake_sub.exec_calls[0]
    assert args == (
        "git",
        "clone",
        "--depth",
        "1",
        TOOL_SPECS["sqlmap"].git_repo,
        str(tmp_path / "sqlmap"),
    )


def test_check_all_and_missing_tools(installer: ToolInstaller, fake_which) -> None:
    fake_which.table["nmap"] = "C:/nmap.exe"
    fake_which.table["jq"] = "C:/jq.exe"
    status = installer.check_all()
    assert set(status) == set(TOOL_SPECS)
    assert status["nmap"] is True
    assert status["jq"] is True
    assert status["subfinder"] is False
    missing = installer.missing_tools()
    assert "nmap" not in missing
    assert "jq" not in missing
    assert "subfinder" in missing
    assert len(missing) == len(TOOL_SPECS) - 2


async def test_module_level_helpers(fake_which, monkeypatch) -> None:
    fresh = ToolInstaller()
    monkeypatch.setattr(installer_mod, "_installer", fresh)
    assert installer_mod.get_installer() is fresh

    fake_which.table["nmap"] = "C:/nmap.exe"
    assert await installer_mod.install_tool("nmap") is True
    assert fresh._installed["nmap"] == "C:/nmap.exe"

    fake_which.table.clear()
    assert await installer_mod.install_tool("nmap", force=True) is False


# --------------------------------------------------------------------------- #
# wrapper.py
# --------------------------------------------------------------------------- #


def test_wrapper_timeout_defaults(wrapper: ToolWrapper) -> None:
    assert wrapper.default_timeout == 5
    fallback = ToolWrapper(default_timeout=0)
    assert fallback.default_timeout == settings.tool_timeout
    assert isinstance(wrapper.installer, ToolInstaller)


def test_resolve_binary_prefers_installer_cache(wrapper: ToolWrapper, fake_which) -> None:
    wrapper.installer.install_local_path("subfinder", "C:/tools/subfinder.exe")
    assert wrapper._resolve_binary("subfinder") == "C:/tools/subfinder.exe"
    assert fake_which.calls == []


def test_resolve_binary_falls_back_to_spec_binary(wrapper: ToolWrapper, fake_which) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    assert wrapper._resolve_binary("subfinder") == "C:/bin/subfinder.exe"
    assert fake_which.calls == ["subfinder"]


def test_resolve_binary_unknown_tool_uses_tool_name(wrapper: ToolWrapper, fake_which) -> None:
    fake_which.table["mytool"] = "C:/bin/mytool"
    assert wrapper._resolve_binary("mytool") == "C:/bin/mytool"
    assert fake_which.calls == ["mytool"]


def test_resolve_binary_missing_returns_none(wrapper: ToolWrapper, fake_which) -> None:
    assert wrapper._resolve_binary("nmap") is None


async def test_run_tool_not_found(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    result = await wrapper.run("nmap", "-sV")
    assert result.success is False
    assert result.exit_code == 127
    assert "not found" in result.stderr
    assert fake_sub.exec_calls == []


async def test_run_success_parses_string_args(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["nmap"] = "C:/bin/nmap.exe"
    fake_sub.queue(FakeProcess(stdout=b"Nmap scan report\n", returncode=0))
    result = await wrapper.run("nmap", "-sV -O example.com")
    args, kwargs = fake_sub.exec_calls[0]
    assert args == ("C:/bin/nmap.exe", "-sV", "-O", "example.com")
    assert kwargs["stdin"] is None
    assert kwargs["cwd"] is None
    assert kwargs["env"] is None
    assert kwargs["stdout"] == asyncio.subprocess.PIPE
    assert kwargs["stderr"] == asyncio.subprocess.PIPE
    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "Nmap scan report\n"
    assert result.duration_ms >= 0


async def test_run_passes_input_cwd_env(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["assetfinder"] = "C:/bin/assetfinder.exe"
    proc = fake_sub.queue(FakeProcess(stdout=b"a.com\n", returncode=0))
    result = await wrapper.run(
        "assetfinder",
        ["--all"],
        input_data="example.com",
        cwd="C:/work",
        env={"X": "1"},
    )
    args, kwargs = fake_sub.exec_calls[0]
    assert args == ("C:/bin/assetfinder.exe", "--all")
    assert kwargs["stdin"] == asyncio.subprocess.PIPE
    assert kwargs["cwd"] == "C:/work"
    assert kwargs["env"] == {"X": "1"}
    assert proc.sent_input == b"example.com"
    assert result.success is True


async def test_run_nonzero_returncode(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["ffuf"] = "C:/bin/ffuf.exe"
    fake_sub.queue(FakeProcess(stderr=b"boom", returncode=2))
    result = await wrapper.run("ffuf", ["-u", "x"])
    assert result.success is False
    assert result.exit_code == 2
    assert result.stderr == "boom"


async def test_run_none_returncode_maps_to_zero(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["gau"] = "C:/bin/gau.exe"
    fake_sub.queue(FakeProcess(stdout=b"x", returncode=None))
    result = await wrapper.run("gau", [])
    assert result.exit_code == 0
    assert result.success is False


async def test_run_timeout_explicit(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["httpx"] = "C:/bin/httpx.exe"
    proc = fake_sub.queue(FakeProcess(timeout=True))
    result = await wrapper.run("httpx", ["-u", "x"], timeout=3)
    assert result.exit_code == 124
    assert result.success is False
    assert "timed out after 3s" in result.stderr
    assert proc.killed is True
    assert proc.waited is True
    assert result.duration_ms >= 0


async def test_run_timeout_uses_default(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["httpx"] = "C:/bin/httpx.exe"
    fake_sub.queue(FakeProcess(timeout=True))
    result = await wrapper.run("httpx", ["-u", "x"])
    assert "timed out after 5s" in result.stderr


async def test_run_binary_not_executable(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["nmap"] = "C:/bin/nmap.exe"
    fake_sub.error = FileNotFoundError("missing")
    result = await wrapper.run("nmap", "-sV")
    assert result.success is False
    assert result.exit_code == 127
    assert "could not be executed" in result.stderr


async def test_run_execution_error(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["nmap"] = "C:/bin/nmap.exe"
    fake_sub.error = RuntimeError("spawn blew up")
    result = await wrapper.run("nmap", "-sV")
    assert result.success is False
    assert result.exit_code == 1
    assert "Execution error: spawn blew up" in result.stderr
    assert result.duration_ms >= 0


async def test_run_parse_json_output(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["httpx"] = "C:/bin/httpx.exe"
    stdout = b'{"url": "https://a.com", "status_code": 200}\nnot-json\n\n{"url": "https://b.com"}\n'
    fake_sub.queue(FakeProcess(stdout=stdout))
    result = await wrapper.run("httpx", ["-u", "x"], parse=True)
    assert result.parsed_output == [
        {"url": "https://a.com", "status_code": 200},
        {"raw": "not-json"},
        {"url": "https://b.com"},
    ]


async def test_run_parse_line_output(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    fake_sub.queue(FakeProcess(stdout=b"a.com\n\nb.com\n"))
    result = await wrapper.run("subfinder", ["-d", "x"], parse=True)
    assert result.parsed_output == ["a.com", "b.com"]


def test_parse_output_default_tool(wrapper: ToolWrapper) -> None:
    assert wrapper._parse_output("nmap", "22/tcp open\n\n80/tcp open\n") == [
        "22/tcp open",
        "80/tcp open",
    ]


async def test_pipeline_chains_stdout_to_next_stdin(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    fake_which.table["httpx"] = "C:/bin/httpx.exe"
    first = fake_sub.queue(FakeProcess(stdout=b"a.com\nb.com\n", returncode=0))
    second = fake_sub.queue(FakeProcess(stdout=b'{"url": "a.com"}\n', returncode=0))
    results = await wrapper.run_pipeline(
        [
            {"tool": "subfinder", "args": ["-d", "x"]},
            {"tool": "httpx", "args": [], "parse": True},
        ]
    )
    assert len(results) == 2
    assert first.sent_input is None
    assert second.sent_input == b"a.com\nb.com\n"
    assert all(r.success for r in results)
    assert results[1].parsed_output == [{"url": "a.com"}]


async def test_pipeline_failed_step_does_not_propagate_stdin(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    fake_which.table["httpx"] = "C:/bin/httpx.exe"
    fake_sub.queue(FakeProcess(stdout=b"a.com\n", returncode=1))
    second = fake_sub.queue(FakeProcess(returncode=0))
    results = await wrapper.run_pipeline([{"tool": "subfinder"}, {"tool": "httpx"}])
    assert results[0].success is False
    assert second.sent_input is None


async def test_pipeline_stdin_false_skips_chaining(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["subfinder"] = "C:/bin/subfinder.exe"
    fake_which.table["httpx"] = "C:/bin/httpx.exe"
    fake_sub.queue(FakeProcess(stdout=b"a.com\n"))
    second = fake_sub.queue(FakeProcess())
    results = await wrapper.run_pipeline([{"tool": "subfinder"}, {"tool": "httpx", "stdin": False}])
    assert results[0].success is True
    assert second.sent_input is None


async def test_pipeline_step_timeout(
    wrapper: ToolWrapper, fake_which, fake_sub: FakeSubprocess
) -> None:
    fake_which.table["nmap"] = "C:/bin/nmap.exe"
    fake_sub.queue(FakeProcess(timeout=True))
    results = await wrapper.run_pipeline([{"tool": "nmap", "timeout": 2}])
    assert results[0].exit_code == 124
    assert "timed out after 2s" in results[0].stderr


async def test_run_tool_convenience(monkeypatch, fake_which, fake_sub: FakeSubprocess) -> None:
    monkeypatch.setattr(wrapper_mod, "get_installer", lambda: ToolInstaller())
    monkeypatch.setattr(wrapper_mod, "tool_wrapper", ToolWrapper(default_timeout=5))
    fake_which.table["jq"] = "C:/bin/jq.exe"
    fake_sub.queue(FakeProcess(stdout=b'{"a": 1}\n'))
    result = await wrapper_mod.run_tool("jq", ["--version"])
    assert result.success is True
    assert result.stdout == '{"a": 1}\n'
    args, _kwargs = fake_sub.exec_calls[0]
    assert args == ("C:/bin/jq.exe", "--version")


# --------------------------------------------------------------------------- #
# local_tools.py
# --------------------------------------------------------------------------- #


def test_register_local_tool(registry: dict[str, LocalTool]) -> None:
    tool = LocalTool(name="scan", command="scan.py {target}", description="d")
    register_local_tool(tool)
    assert registry["scan"] is tool


def test_load_local_tools_from_config(registry: dict[str, LocalTool]) -> None:
    config = {
        "nmap-scan": {
            "command": "nmap {target}",
            "description": "scan",
            "args": {"target": "str"},
            "cwd": "/w",
            "shell": True,
        },
        "bad-spec": "not-a-dict",
    }
    loaded = load_local_tools(config)
    assert loaded is registry
    tool = registry["nmap-scan"]
    assert tool.command == "nmap {target}"
    assert tool.description == "scan"
    assert tool.args_schema == {"target": "str"}
    assert tool.cwd == "/w"
    assert tool.shell is True
    assert "bad-spec" not in registry


def test_load_local_tools_minimal_spec(registry: dict[str, LocalTool]) -> None:
    load_local_tools({"minimal": {"command": "echo hi"}})
    tool = registry["minimal"]
    assert tool.description == ""
    assert tool.args_schema == {}
    assert tool.cwd == ""
    assert tool.shell is False


def test_load_local_tools_uses_settings(registry: dict[str, LocalTool], monkeypatch) -> None:
    monkeypatch.setattr(settings, "local_tools", {"from-settings": {"command": "ls"}})
    loaded = load_local_tools()
    assert "from-settings" in loaded


def test_load_local_tools_empty_config_does_not_fall_back(
    registry: dict[str, LocalTool], monkeypatch
) -> None:
    monkeypatch.setattr(settings, "local_tools", {"fallback": {"command": "ls"}})
    load_local_tools({})
    assert "fallback" not in registry


def test_discover_scripts_missing_dir(tmp_path: Path) -> None:
    assert discover_scripts(tmp_path / "nope") == []


def test_discover_scripts_finds_supported_extensions(tmp_path: Path) -> None:
    for name in ("b.sh", "a.py", "c.ps1", "d.bat", "e.cmd", "notes.txt"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "hidden.py").write_text("x", encoding="utf-8")
    found = discover_scripts(tmp_path)
    assert [p.name for p in found] == ["a.py", "b.sh", "c.ps1", "d.bat", "e.cmd"]


def test_discover_scripts_uses_settings_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "scripts_dir", tmp_path)
    (tmp_path / "run.py").write_text("x", encoding="utf-8")
    assert [p.name for p in discover_scripts()] == ["run.py"]


async def test_run_unregistered_tool(fake_sub: FakeSubprocess, registry) -> None:
    result = await LocalToolRunner().run("ghost")
    assert result.exit_code == 127
    assert result.success is False
    assert "not registered" in result.stderr
    assert fake_sub.exec_calls == []
    assert fake_sub.shell_calls == []


async def test_run_missing_format_parameter(registry, fake_sub: FakeSubprocess) -> None:
    register_local_tool(LocalTool(name="scan", command="scan.py --target {target}"))
    result = await LocalToolRunner().run("scan", params={})
    assert result.exit_code == 2
    assert result.success is False
    assert "Missing parameter" in result.stderr
    assert "target" in result.stderr


async def test_run_shell_command(registry, fake_sub: FakeSubprocess) -> None:
    tool = LocalTool(name="sh", command="echo {msg} done", shell=True, cwd="C:/work")
    register_local_tool(tool)
    fake_sub.queue(FakeProcess(stdout=b"hi\n", returncode=0))
    result = await LocalToolRunner().run("sh", {"msg": "hi"})
    assert len(fake_sub.shell_calls) == 1
    command, kwargs = fake_sub.shell_calls[0]
    assert command == "echo hi done"
    assert kwargs["cwd"] == "C:/work"
    assert kwargs["stdout"] == asyncio.subprocess.PIPE
    assert kwargs["stderr"] == asyncio.subprocess.PIPE
    assert result.success is True
    assert result.stdout == "hi\n"
    assert result.parsed_output == {"command": "echo hi done"}
    assert result.duration_ms >= 0


async def test_run_exec_command(registry, fake_sub: FakeSubprocess) -> None:
    register_local_tool(LocalTool(name="py", command="python scan.py --target {target}"))
    fake_sub.queue(FakeProcess(stdout=b"done\n", stderr=b"warn\n", returncode=0))
    result = await LocalToolRunner().run("py", {"target": "example.com"})
    args, kwargs = fake_sub.exec_calls[0]
    assert args == ("python", "scan.py", "--target", "example.com")
    assert kwargs["cwd"] is None
    assert fake_sub.shell_calls == []
    assert result.success is True
    assert result.stdout == "done\n"
    assert result.stderr == "warn\n"
    assert result.parsed_output == {"command": "python scan.py --target example.com"}


async def test_run_failure_returncode(registry, fake_sub: FakeSubprocess) -> None:
    register_local_tool(LocalTool(name="fail", command="boom"))
    fake_sub.queue(FakeProcess(stderr=b"bad", returncode=7))
    result = await LocalToolRunner().run("fail")
    assert result.success is False
    assert result.exit_code == 7
    assert result.stderr == "bad"


async def test_run_timeout(registry, fake_sub: FakeSubprocess) -> None:
    register_local_tool(LocalTool(name="slow", command="sleep 99"))
    proc = fake_sub.queue(FakeProcess(timeout=True))
    result = await LocalToolRunner().run("slow", timeout=4)
    assert result.exit_code == 124
    assert result.success is False
    assert "timed out after 4s" in result.stderr
    assert proc.killed is True
    assert proc.waited is True


async def test_local_run_timeout_uses_default(
    registry, fake_sub: FakeSubprocess, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "tool_timeout", 55)
    register_local_tool(LocalTool(name="slow2", command="sleep 99"))
    fake_sub.queue(FakeProcess(timeout=True))
    result = await LocalToolRunner().run("slow2")
    assert result.exit_code == 124
    assert "timed out after 55s" in result.stderr


async def test_run_spawn_error_returns_tool_result(registry, fake_sub: FakeSubprocess) -> None:
    register_local_tool(LocalTool(name="missing", command="no-such-binary"))
    fake_sub.error = FileNotFoundError("no-such-binary")
    result = await LocalToolRunner().run("missing")
    assert result.success is False
    assert result.exit_code == 127
    assert "Failed to start local tool" in result.stderr


async def test_run_script_missing(tmp_path: Path, fake_sub: FakeSubprocess) -> None:
    result = await LocalToolRunner().run_script(tmp_path / "ghost.py")
    assert result.exit_code == 127
    assert result.success is False
    assert "Script not found" in result.stderr
    assert fake_sub.exec_calls == []


async def test_run_script_spawn_error_returns_tool_result(
    tmp_path: Path, fake_sub: FakeSubprocess
) -> None:
    script = tmp_path / "run.py"
    script.write_text("print(1)", encoding="utf-8")
    fake_sub.error = FileNotFoundError("python")
    result = await LocalToolRunner().run_script(script)
    assert result.success is False
    assert result.exit_code == 127
    assert "Failed to start script" in result.stderr


@pytest.mark.parametrize(
    ("filename", "cmd_template"),
    [
        ("run.py", ["python", "{path}", "--flag"]),
        ("run.ps1", ["powershell", "-ExecutionPolicy", "Bypass", "-File", "{path}", "--flag"]),
        ("run.bat", ["{path}", "--flag"]),
        ("run.cmd", ["{path}", "--flag"]),
        ("run.sh", ["bash", "{path}", "--flag"]),
        ("run.txt", ["{path}", "--flag"]),
    ],
)
async def test_run_script_interpreter_dispatch(
    tmp_path: Path, fake_sub: FakeSubprocess, filename: str, cmd_template: list[str]
) -> None:
    path = tmp_path / filename
    path.write_text("rem", encoding="utf-8")
    fake_sub.queue(FakeProcess(stdout=b"ok", returncode=0))
    result = await LocalToolRunner().run_script(path, args=["--flag"])
    args, _kwargs = fake_sub.exec_calls[0]
    expected = tuple(str(path) if tok == "{path}" else tok for tok in cmd_template)
    assert args == expected
    assert result.success is True
    assert result.stdout == "ok"
    assert result.duration_ms >= 0


async def test_run_script_no_args(tmp_path: Path, fake_sub: FakeSubprocess) -> None:
    path = tmp_path / "run.py"
    path.write_text("x", encoding="utf-8")
    fake_sub.queue(FakeProcess(returncode=0))
    result = await LocalToolRunner().run_script(path)
    args, _kwargs = fake_sub.exec_calls[0]
    assert args == ("python", str(path))
    assert result.exit_code == 0


async def test_run_script_failure(tmp_path: Path, fake_sub: FakeSubprocess) -> None:
    path = tmp_path / "run.py"
    path.write_text("x", encoding="utf-8")
    fake_sub.queue(FakeProcess(stderr=b"traceback", returncode=3))
    result = await LocalToolRunner().run_script(path)
    assert result.success is False
    assert result.exit_code == 3
    assert result.stderr == "traceback"


async def test_run_script_timeout(tmp_path: Path, fake_sub: FakeSubprocess) -> None:
    path = tmp_path / "run.py"
    path.write_text("x", encoding="utf-8")
    proc = fake_sub.queue(FakeProcess(timeout=True))
    result = await LocalToolRunner().run_script(path, timeout=1)
    assert result.exit_code == 124
    assert result.success is False
    assert result.stderr == "Script timed out"
    assert proc.killed is True
    assert proc.waited is True
