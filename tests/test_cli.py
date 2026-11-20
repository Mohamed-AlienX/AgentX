"""CLI tests for agentx.cli: Typer commands plus the shared chat/slash helpers."""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from agentx import cli
from agentx.config import settings
from agentx.core.memory import Finding, memory
from agentx.core.orchestrator import orchestrator
from agentx.core.session import session_manager
from agentx.mcp import mcp_manager, permission_gate
from agentx.recon.pipeline import ReconResult


def _finding(
    session_id: str,
    *,
    severity: str = "HIGH",
    title: str = "Reflected XSS",
    endpoint: str = "/search?q=",
    validation_notes: str = "",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        session_id=session_id,
        skill_name="hunt-xss",
        title=title,
        severity=severity,
        endpoint=endpoint,
        description="A reflected parameter is echoed unescaped.",
        impact="Session theft for any authenticated user.",
        steps_to_reproduce=["open page", "inject payload"],
        evidence={"status": 200},
        validation_notes=validation_notes,
    )


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Keep every test hermetic: private DB, no leaked session/global state."""
    monkeypatch.setattr(memory, "db_path", tmp_path / "agentx.db")
    memory._init_db()
    monkeypatch.setattr(session_manager, "_current_session", None)
    monkeypatch.setattr(session_manager, "_sessions", {})
    monkeypatch.setattr(orchestrator, "auto_execute", False)
    monkeypatch.setattr(orchestrator, "_pending_plan", None)
    yield


def _run(*args: str):
    return CliRunner().invoke(cli.app, list(args))


# ---------------------------------------------------------------------------
# main callback + version / config / debug
# ---------------------------------------------------------------------------


def test_version_flag() -> None:
    result = _run("--version")
    assert result.exit_code == 0
    assert "AgentX v" in result.output


def test_main_without_subcommand_runs_chat_loop(monkeypatch) -> None:
    called: dict[str, object] = {}

    async def fake_loop(invoke_ai: bool = True, seed_target: str | None = None) -> None:
        called["invoke_ai"] = invoke_ai

    monkeypatch.setattr(cli, "_chat_loop", fake_loop)
    result = _run()
    assert result.exit_code == 0
    assert called["invoke_ai"] is True


def test_main_debug_flag(monkeypatch) -> None:
    monkeypatch.setattr(settings, "debug", settings.debug)
    monkeypatch.setattr(memory, "list_sessions", lambda *a, **k: [])
    result = _run("--debug", "sessions")
    assert result.exit_code == 0
    assert settings.debug is True
    assert "No sessions yet" in result.output


def test_main_config_option_loads_file(tmp_path, monkeypatch) -> None:
    src = Path("config") / "default.yaml"
    data = yaml.safe_load(src.read_text(encoding="utf-8")) if src.exists() else {}
    data["orchestrator_model"] = "marker-model-zzz"
    cfg = tmp_path / "custom.yaml"
    cfg.write_text(yaml.dump(data), encoding="utf-8")
    monkeypatch.setattr(settings, "orchestrator_model", settings.orchestrator_model)
    result = _run("--config", str(cfg), "config")
    assert result.exit_code == 0
    assert "marker-model-zzz" in result.output


# ---------------------------------------------------------------------------
# chat / tui / recon / scan
# ---------------------------------------------------------------------------


def test_chat_command(monkeypatch) -> None:
    called: dict[str, object] = {}

    async def fake_loop(invoke_ai: bool = True, seed_target: str | None = None) -> None:
        called["seed"] = seed_target

    monkeypatch.setattr(cli, "_chat_loop", fake_loop)
    result = _run("chat", "-t", "example.com", "--auto")
    assert result.exit_code == 0
    assert called["seed"] == "example.com"
    assert orchestrator.auto_execute is True


def test_tui_command(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_run_tui() -> None:
        called["run"] = True

    monkeypatch.setattr("agentx.tui.run_tui", fake_run_tui)
    result = _run("tui", "-t", "example.com")
    assert result.exit_code == 0
    assert called["run"] is True


def test_recon_command_success_and_failure(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def fake_run(target: str, stages=None):
        captured["stages"] = stages
        return [
            ReconResult("subdomains", True, data=["a.example.com", "b.example.com"], count=2),
            ReconResult("urls", False, error="boom"),
        ]

    monkeypatch.setattr(cli.recon_pipeline, "run", fake_run)
    result = _run("recon", "example.com", "-s", "subdomains, urls")
    assert result.exit_code == 0
    assert captured["stages"] == ["subdomains", "urls"]
    assert "OK" in result.output
    assert "FAIL" in result.output
    assert "boom" in result.output

    result = _run("recon", "example.com")
    assert result.exit_code == 0
    assert captured["stages"] is None


def test_scan_command_custom_request(monkeypatch) -> None:
    calls: dict[str, object] = {}

    async def fake_init() -> None:
        calls["init"] = True

    async def fake_close() -> None:
        calls["close"] = True

    class FakeOrch:
        def __init__(self, auto_execute: bool = False) -> None:
            calls["auto"] = auto_execute

        async def handle_message(self, req, target=None, auto_execute=None):
            calls["req"] = req
            calls["target"] = target
            return SimpleNamespace(text="# plan result", tool_traces=[], findings=[])

    monkeypatch.setattr(cli, "init_ai", fake_init)
    monkeypatch.setattr(cli, "close_ai", fake_close)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrch)
    result = _run("scan", "example.com", "-r", "hunt it", "--no-auto")
    assert result.exit_code == 0
    assert "result" in result.output
    assert calls["req"] == "hunt it"
    assert calls["target"] == "example.com"
    assert calls["auto"] is False
    assert calls["init"] is True
    assert calls["close"] is True


def test_scan_command_default_request(monkeypatch) -> None:
    calls: dict[str, object] = {}

    async def fake_init() -> None:
        calls["init"] = True

    async def fake_close() -> None:
        calls["close"] = True

    class FakeOrch:
        def __init__(self, auto_execute: bool = False) -> None:
            calls["auto"] = auto_execute

        async def handle_message(self, req, target=None, auto_execute=None):
            calls["req"] = req
            return SimpleNamespace(text="done", tool_traces=[], findings=[])

    monkeypatch.setattr(cli, "init_ai", fake_init)
    monkeypatch.setattr(cli, "close_ai", fake_close)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrch)
    result = _run("scan", "example.com")
    assert result.exit_code == 0
    assert "full security assessment" in str(calls["req"])
    assert calls["auto"] is True


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def test_report_no_session() -> None:
    result = _run("report")
    assert result.exit_code == 1
    assert "No active session" in result.output


def test_report_no_findings() -> None:
    session_manager.create_session("example.com")
    result = _run("report")
    assert result.exit_code == 0
    assert "No findings to report" in result.output


def test_report_with_findings_writes_file(tmp_path) -> None:
    session = session_manager.create_session("example.com")
    session_manager.add_finding(_finding(session.id))
    out = tmp_path / "report.md"
    result = _run("report", "-f", "markdown", "-o", str(out))
    assert result.exit_code == 0
    assert out.exists()
    assert "Reflected XSS" in out.read_text(encoding="utf-8")
    assert "Report saved" in result.output


# ---------------------------------------------------------------------------
# skills
# ---------------------------------------------------------------------------


def _patch_skills(monkeypatch, discovered) -> None:
    monkeypatch.setattr(cli.skill_registry, "load_skill_configs", lambda: None)
    monkeypatch.setattr(cli.skill_registry, "discover_skills", lambda: discovered)
    monkeypatch.setattr(cli.skill_registry, "is_enabled", lambda name: True)


def test_skills_list(monkeypatch) -> None:
    _patch_skills(
        monkeypatch,
        {"hunt-xss": {"category": "hunting", "description": "XSS", "path": "p"}},
    )
    result = _run("skills")
    assert result.exit_code == 0
    assert "Available Skills" in result.output
    assert "hunt-xss" in result.output


def test_skills_info_found(monkeypatch) -> None:
    _patch_skills(
        monkeypatch,
        {"hunt-xss": {"category": "hunting", "description": "Cross site", "path": "p"}},
    )
    result = _run("skills", "info", "hunt-xss")
    assert result.exit_code == 0
    assert "Skill Info" in result.output
    assert "Cross site" in result.output


def test_skills_info_missing(monkeypatch) -> None:
    _patch_skills(monkeypatch, {})
    result = _run("skills", "info", "nope")
    assert result.exit_code == 1
    assert "not found" in result.output


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_config_show() -> None:
    result = _run("config")
    assert result.exit_code == 0
    assert "AgentX Configuration" in result.output
    assert "AI Providers" in result.output


def test_config_init_writes_file(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "default.yaml"
    monkeypatch.setattr(cli, "_config_path", lambda: cfg)
    result = _run("config", "--init")
    assert result.exit_code == 0
    assert cfg.exists()
    assert "Wrote default config" in result.output


def _patch_wizard(monkeypatch, tmp_path, ptype: str, confirm_env: bool, confirm_model: bool = True):
    cfg = tmp_path / "default.yaml"
    monkeypatch.setattr(cli, "_config_path", lambda: cfg)
    monkeypatch.setattr(settings, "ai_providers", list(settings.ai_providers))
    monkeypatch.setattr(settings, "orchestrator_model", settings.orchestrator_model)
    monkeypatch.setattr(settings, "skill_model", settings.skill_model)

    def fake_ask(prompt, *a, **k):
        if prompt.startswith("Provider type"):
            return ptype
        if prompt.startswith("Model"):
            return "chosen-model"
        if prompt.startswith("Base URL"):
            return "http://localhost:11434"
        if prompt.startswith("API key"):
            return "sk-test-key"
        return "x"

    monkeypatch.setattr(cli.Prompt, "ask", fake_ask)
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: confirm_model)
    return cfg


def test_config_wizard_local_provider(tmp_path, monkeypatch) -> None:
    cfg = _patch_wizard(monkeypatch, tmp_path, "ollama", confirm_env=True)
    result = _run("config", "--wizard")
    assert result.exit_code == 0
    assert cfg.exists()
    text = cfg.read_text(encoding="utf-8")
    assert "ollama" in text
    assert "chosen-model" in text


def test_config_wizard_env_key(tmp_path, monkeypatch) -> None:
    cfg = _patch_wizard(monkeypatch, tmp_path, "openai", confirm_env=True)
    result = _run("config", "--wizard")
    assert result.exit_code == 0
    assert "${OPENAI_API_KEY}" in cfg.read_text(encoding="utf-8")


def test_config_wizard_manual_key(tmp_path, monkeypatch) -> None:
    cfg = _patch_wizard(monkeypatch, tmp_path, "openai", confirm_env=False, confirm_model=False)
    result = _run("config", "--wizard")
    assert result.exit_code == 0
    assert "sk-test-key" in cfg.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------


def test_tools_table(monkeypatch) -> None:
    inst = cli.get_installer()
    monkeypatch.setattr(inst, "check_all", lambda: {"nmap": True, "jq": False})
    monkeypatch.setattr(inst, "get_path", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    result = _run("tools", "--check")
    assert result.exit_code == 0
    assert "External Tools" in result.output
    assert "installed" in result.output
    assert "missing" in result.output


def test_tools_missing(monkeypatch) -> None:
    inst = cli.get_installer()
    monkeypatch.setattr(inst, "missing_tools", lambda: ["jq", "nmap"])
    result = _run("tools", "--missing")
    assert result.exit_code == 0
    assert "Missing: jq, nmap" in result.output

    monkeypatch.setattr(inst, "missing_tools", lambda: [])
    result = _run("tools", "--missing")
    assert result.exit_code == 0
    assert "All known tools installed" in result.output


def test_tools_install_success_and_failure(monkeypatch) -> None:
    inst = cli.get_installer()

    async def ok(tool, force=False):
        return True

    monkeypatch.setattr(inst, "install_tool", ok)
    result = _run("tools", "--install", "nmap")
    assert result.exit_code == 0
    assert "Installed: nmap" in result.output

    async def fail(tool, force=False):
        return False

    monkeypatch.setattr(inst, "install_tool", fail)
    result = _run("tools", "--install", "nmap")
    assert result.exit_code == 0
    assert "Could not install" in result.output


def test_tools_install_all(monkeypatch) -> None:
    inst = cli.get_installer()
    monkeypatch.setattr(inst, "missing_tools", lambda: ["a", "b"])

    async def fake(tool, force=False):
        return tool == "a"

    monkeypatch.setattr(inst, "install_tool", fake)
    result = _run("tools", "--install-all")
    assert result.exit_code == 0
    assert "ok" in result.output
    assert "fail" in result.output


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------


def test_sessions_empty(monkeypatch) -> None:
    monkeypatch.setattr(memory, "list_sessions", lambda *a, **k: [])
    result = _run("sessions")
    assert result.exit_code == 0
    assert "No sessions yet" in result.output


def test_sessions_rows(monkeypatch) -> None:
    monkeypatch.setattr(
        memory,
        "list_sessions",
        lambda *a, **k: [{"id": "abc", "target": "example.com", "updated_at": "2024-01-01"}],
    )
    result = _run("sessions")
    assert result.exit_code == 0
    assert "abc" in result.output
    assert "example.com" in result.output


# ---------------------------------------------------------------------------
# _chat_loop
# ---------------------------------------------------------------------------


def _patch_chat_loop(monkeypatch, inputs, handler=None):
    monkeypatch.setattr(cli, "load_local_tools", lambda: {})
    monkeypatch.setattr(settings, "mcp_servers", [])

    async def fake_init() -> None:
        return None

    monkeypatch.setattr(cli, "init_ai", fake_init)

    async def fake_close() -> None:
        return None

    monkeypatch.setattr(cli, "close_ai", fake_close)

    async def fake_mcp_close() -> None:
        return None

    monkeypatch.setattr(cli.mcp_manager, "close", fake_mcp_close)

    it = iter(inputs)

    def fake_ask(prompt, *a, **k):
        return next(it)

    monkeypatch.setattr(cli.Prompt, "ask", fake_ask)
    if handler is not None:
        monkeypatch.setattr(cli.orchestrator, "handle_message", handler)


async def test_chat_loop_handles_message_and_slash(monkeypatch) -> None:
    seen: list[str] = []
    trace = SimpleNamespace(ok=True, server="srv", tool="t", summary="did it")

    async def handler(msg, **kw):
        seen.append(msg)
        return SimpleNamespace(text="assistant reply", tool_traces=[trace])

    _patch_chat_loop(monkeypatch, ["/help", "hello there", "/exit"], handler)
    monkeypatch.setattr(settings, "ai_providers", [SimpleNamespace(enabled=True)])
    await cli._chat_loop(invoke_ai=True, seed_target="example.com")
    assert seen == ["hello there"]


async def test_chat_loop_error_branch_and_eof(monkeypatch) -> None:
    async def handler(msg, **kw):
        raise RuntimeError("provider down")

    _patch_chat_loop(monkeypatch, ["/status", "boom", "/exit"], handler)
    await cli._chat_loop(invoke_ai=False)

    _patch_chat_loop(monkeypatch, [EOFError])

    def raise_eof(prompt, *a, **k):
        raise EOFError

    monkeypatch.setattr(cli.Prompt, "ask", raise_eof)
    await cli._chat_loop(invoke_ai=False)


async def test_chat_loop_seed_updates_existing_session(monkeypatch) -> None:
    session = session_manager.create_session("old.example.com")
    _patch_chat_loop(monkeypatch, [EOFError])

    def raise_eof(prompt, *a, **k):
        raise EOFError

    monkeypatch.setattr(cli.Prompt, "ask", raise_eof)
    await cli._chat_loop(invoke_ai=False, seed_target="new.example.com")
    assert session.target == "new.example.com"


async def test_chat_loop_ai_init_warning(monkeypatch) -> None:
    _patch_chat_loop(monkeypatch, [EOFError])

    async def boom_init() -> None:
        raise RuntimeError("no provider")

    def raise_eof(prompt, *a, **k):
        raise EOFError

    monkeypatch.setattr(cli, "init_ai", boom_init)
    monkeypatch.setattr(cli.Prompt, "ask", raise_eof)
    await cli._chat_loop(invoke_ai=True)


async def test_chat_loop_skips_empty_input(monkeypatch) -> None:
    seen: list[str] = []

    async def handler(msg, **kw):
        seen.append(msg)
        return SimpleNamespace(text="ok", tool_traces=[])

    _patch_chat_loop(monkeypatch, ["", "   ", "/exit"], handler)
    await cli._chat_loop(invoke_ai=False)
    assert seen == []


# ---------------------------------------------------------------------------
# _handle_slash
# ---------------------------------------------------------------------------


async def test_handle_slash_basic() -> None:
    assert await cli._handle_slash("/exit", True) is True
    assert await cli._handle_slash("/quit", True) is True
    assert await cli._handle_slash("/q", True) is True
    assert await cli._handle_slash("/help", True) is False
    assert await cli._handle_slash("/unknown", True) is False


async def test_handle_slash_target_and_status(monkeypatch) -> None:
    session_manager.create_session("example.com")
    session = session_manager.get_session()
    session_manager.add_finding(_finding(session.id))
    await cli._handle_slash("/target", True)
    await cli._handle_slash("/target evil.example.com", True)
    assert session.target == "evil.example.com"
    await cli._handle_slash("/status", True)


async def test_handle_slash_target_creates_session() -> None:
    await cli._handle_slash("/target fresh.example.com", True)
    session = session_manager.get_session()
    assert session is not None
    assert session.target == "fresh.example.com"


async def test_handle_slash_status_no_session() -> None:
    await cli._handle_slash("/status", True)


async def test_handle_slash_plan_and_go(monkeypatch) -> None:
    session_manager.create_session("example.com")
    calls: list[tuple] = []

    async def handler(msg, **kw):
        calls.append((msg, kw))
        return SimpleNamespace(text="planned", tool_traces=[])

    monkeypatch.setattr(cli.orchestrator, "handle_message", handler)
    await cli._handle_slash("/plan", True)
    await cli._handle_slash("/plan do the thing", True)
    await cli._handle_slash("/go", True)
    assert calls[-1][0] == "do the thing"

    monkeypatch.setattr(cli.orchestrator, "_pending_plan", object())
    await cli._handle_slash("/go", True)
    assert calls[-1][0] == "go"


async def test_handle_slash_mode_and_auto(monkeypatch) -> None:
    session_manager.create_session("example.com")
    monkeypatch.setattr(settings, "permission_mode", settings.permission_mode)
    monkeypatch.setattr(permission_gate, "mode", permission_gate.mode)
    await cli._handle_slash("/mode bogus", True)
    await cli._handle_slash("/mode auto", True)
    assert settings.permission_mode == "auto"
    await cli._handle_slash("/mode yolo", True)
    assert settings.permission_mode == "yolo"
    await cli._handle_slash("/auto on", True)
    assert orchestrator.auto_execute is True
    await cli._handle_slash("/auto off", True)
    assert orchestrator.auto_execute is False


async def test_handle_slash_misc(monkeypatch, tmp_path) -> None:
    session_manager.create_session("example.com")
    _patch_skills(monkeypatch, {})
    await cli._handle_slash("/skills xss", True)
    await cli._handle_slash("/findings", True)
    await cli._handle_slash("/validate", True)

    monkeypatch.setattr(
        memory, "list_sessions", lambda *a, **k: [{"id": "s1", "target": None, "updated_at": "now"}]
    )
    await cli._handle_slash("/sessions", True)

    monkeypatch.setattr(mcp_manager, "summary", lambda: {"servers": [], "tool_count": 0})
    await cli._handle_slash("/mcp", True)

    await cli._handle_slash("/report", True)

    async def fake_run(target, stages=None):
        return [
            ReconResult("subdomains", True, data=["a"], count=1),
            ReconResult("urls", False, error="nope"),
        ]

    monkeypatch.setattr(cli.recon_pipeline, "run", fake_run)
    await cli._handle_slash("/recon subdomains", True)

    await cli._handle_slash("/handoff", True)

    monkeypatch.setattr(memory, "clear_conversation", lambda sid: None)
    await cli._handle_slash("/clear", True)


async def test_handle_slash_findings_report_validate(monkeypatch, tmp_path) -> None:
    session = session_manager.create_session("example.com")
    session_manager.add_finding(_finding(session.id, severity="HIGH", title="Stored XSS here"))
    _patch_skills(
        monkeypatch,
        {"hunt-xss": {"category": "hunting", "description": "XSS", "path": "p"}},
    )
    await cli._handle_slash("/skills xss", True)
    await cli._handle_slash("/skills zzz", True)
    await cli._handle_slash("/findings high", True)
    await cli._handle_slash("/validate", True)

    saved = tmp_path / "r.md"
    monkeypatch.setattr(cli.report_generator, "save", lambda *a, **k: saved)
    await cli._handle_slash("/report json", True)
    assert session.get_findings()[0].validation_notes != ""


async def test_handle_slash_report_error(monkeypatch) -> None:
    session = session_manager.create_session("example.com")
    session_manager.add_finding(_finding(session.id))

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(cli.report_generator, "save", boom)
    await cli._handle_slash("/report", True)


async def test_handle_slash_no_session_errors() -> None:
    await cli._handle_slash("/findings", True)
    await cli._handle_slash("/validate", True)
    await cli._handle_slash("/report", True)
    await cli._handle_slash("/handoff", True)
    await cli._handle_slash("/recon subdomains", True)
    await cli._handle_slash("/clear", True)


# ---------------------------------------------------------------------------
# remaining helpers
# ---------------------------------------------------------------------------


def test_print_trace(capsys) -> None:
    cli._print_trace(SimpleNamespace(ok=True, server="srv", tool="tool", summary="did it"))
    out = capsys.readouterr().out
    assert "srv.tool" in out
    assert "did it" in out
    cli._print_trace(SimpleNamespace(ok=False, server="srv", tool="tool", summary="bad"))
    assert "bad" in capsys.readouterr().out


def test_print_error_and_success(capsys) -> None:
    cli._print_error("oops")
    cli._print_success("yay")
    out = capsys.readouterr().out
    assert "oops" in out
    assert "yay" in out


async def test_cli_approver(monkeypatch) -> None:
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: True)
    assert await cli._cli_approver("srv", "tool", {"a": 1}, "summary") is True
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: False)
    assert await cli._cli_approver("srv", "tool", {}, "") is False


async def test_init_mcp_no_servers(monkeypatch, capsys) -> None:
    monkeypatch.setattr(settings, "mcp_servers", [])
    await cli._init_mcp()
    assert "No MCP servers enabled" in capsys.readouterr().out


async def test_init_mcp_with_servers(monkeypatch) -> None:
    session_manager.create_session("example.com")
    monkeypatch.setattr(settings, "mcp_servers", [SimpleNamespace(enabled=True)])
    monkeypatch.setattr(permission_gate, "mode", permission_gate.mode)
    called: dict[str, object] = {}

    async def fake_init() -> None:
        called["init"] = True

    monkeypatch.setattr(cli.mcp_manager, "initialize", fake_init)
    monkeypatch.setattr(cli.mcp_manager, "warnings", ["warn-1"])
    monkeypatch.setattr(type(mcp_manager), "server_count", property(lambda self: 1))
    monkeypatch.setattr(type(mcp_manager), "tool_count", property(lambda self: 2))
    await cli._init_mcp()
    assert called["init"] is True
    assert cli.permission_gate.approver is cli._cli_approver


async def test_init_mcp_initialize_warning(monkeypatch, capsys) -> None:
    monkeypatch.setattr(settings, "mcp_servers", [SimpleNamespace(enabled=True)])
    monkeypatch.setattr(permission_gate, "mode", permission_gate.mode)

    async def boom() -> None:
        raise RuntimeError("cannot start")

    monkeypatch.setattr(cli.mcp_manager, "initialize", boom)
    monkeypatch.setattr(type(mcp_manager), "server_count", property(lambda self: 0))
    await cli._init_mcp()
    assert "MCP init warning" in capsys.readouterr().out


async def test_init_mcp_no_connected_servers(monkeypatch, capsys) -> None:
    monkeypatch.setattr(settings, "mcp_servers", [SimpleNamespace(enabled=True)])
    monkeypatch.setattr(permission_gate, "mode", permission_gate.mode)

    async def fake_init() -> None:
        return None

    monkeypatch.setattr(cli.mcp_manager, "initialize", fake_init)
    monkeypatch.setattr(cli.mcp_manager, "warnings", [])
    monkeypatch.setattr(type(mcp_manager), "server_count", property(lambda self: 0))
    await cli._init_mcp()
    assert "no servers connected" in capsys.readouterr().out


def test_print_mcp_no_servers(monkeypatch, capsys) -> None:
    monkeypatch.setattr(mcp_manager, "summary", lambda: {"servers": [], "tool_count": 0})
    cli._print_mcp()
    assert "No MCP servers connected" in capsys.readouterr().out


def test_print_mcp_with_servers(monkeypatch, capsys) -> None:
    servers = [{"name": "burp", "transport": "stdio", "auto_approve": False, "tools": ["a", "b"]}]
    monkeypatch.setattr(mcp_manager, "summary", lambda: {"servers": servers, "tool_count": 2})
    monkeypatch.setattr(mcp_manager, "warnings", ["careful"])
    cli._print_mcp()
    out = capsys.readouterr().out
    assert "burp" in out
    assert "careful" in out


async def test_run_recon_no_target(capsys) -> None:
    await cli._run_recon("subdomains")
    assert "Set a target" in capsys.readouterr().out


async def test_run_recon_with_target(monkeypatch, capsys) -> None:
    session_manager.create_session("example.com")

    async def fake_run(target, stages=None):
        return [
            ReconResult("subdomains", True, data=["a"], count=1),
            ReconResult("urls", False, error="nope"),
        ]

    monkeypatch.setattr(cli.recon_pipeline, "run", fake_run)
    await cli._run_recon("subdomains")
    out = capsys.readouterr().out
    assert "OK" in out
    assert "FAIL" in out


def test_print_findings_no_session(capsys) -> None:
    cli._print_findings("")
    assert "No active session" in capsys.readouterr().out


def test_run_triage_no_session(capsys) -> None:
    cli._run_triage()
    assert "No active session" in capsys.readouterr().out


def test_config_path() -> None:
    assert cli._config_path() == Path("config") / "default.yaml"


def test_dunder_main_import() -> None:
    import agentx.__main__ as entry

    assert entry.app is cli.app
