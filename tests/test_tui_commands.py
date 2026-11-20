"""Behavioral tests for the AgentX TUI: slash commands, bindings and modals."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console
from textual.pilot import Pilot
from textual.widgets import DataTable, Input, RichLog, Static

from agentx.ai.providers import CompletionResponse
from agentx.ai.router import router
from agentx.config import MCPConfig, settings
from agentx.core.executor import ExecutionResult
from agentx.core.memory import Finding, memory
from agentx.core.orchestrator import OrchestratorResponse, orchestrator
from agentx.core.session import HuntSession, session_manager
from agentx.mcp import permission_gate
from agentx.recon.pipeline import ReconResult
from agentx.skills.registry import skill_registry
from agentx.tui.app import AgentXTui, PermissionScreen

PLAN_TEXT = """## Analysis
Recon the target before hunting.

## Selected Skills
- web2-recon: subdomain enumeration

## Execution Plan
1. [web2-recon] Enumerate subdomains of the target

## Questions for User
- Is example.com in scope?

## Estimated Time
5 min
"""


@pytest.fixture(autouse=True)
def hermetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Isolate DB, router, MCP, orchestrator and permission-gate state."""
    state = {"text": "fake model reply"}

    async def _fake_complete_response(
        messages: list[dict[str, Any]],
        task_type: str = "skill",
        preferred_provider: str | None = None,
        **kwargs: Any,
    ) -> CompletionResponse:
        return CompletionResponse(content=state["text"], model="fake-model")

    async def _fake_init_ai() -> None:
        return None

    monkeypatch.setattr(router, "complete_response", _fake_complete_response)
    monkeypatch.setattr("agentx.tui.app.init_ai", _fake_init_ai)
    monkeypatch.setattr(settings, "mcp_servers", [])
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(settings, "permission_mode", "ask")
    monkeypatch.setattr(memory, "db_path", tmp_path / "agentx.db")
    memory._init_db()
    monkeypatch.setattr(session_manager, "_current_session", None)
    monkeypatch.setattr(session_manager, "_sessions", {})
    monkeypatch.setattr(orchestrator, "_pending_plan", None)
    monkeypatch.setattr(orchestrator, "auto_execute", False)
    monkeypatch.setattr(permission_gate, "mode", "ask")
    monkeypatch.setattr(permission_gate, "approver", None)
    monkeypatch.setattr(permission_gate, "session_approved", set())
    return state


@asynccontextmanager
async def _tui() -> AsyncIterator[tuple[AgentXTui, Pilot]]:
    app = AgentXTui()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        yield app, pilot


def _chat_lines(app: AgentXTui) -> list[str]:
    log = app.query_one("#chat", RichLog)
    return [" ".join(strip.text.split()) for strip in log.lines]


def _chat(app: AgentXTui) -> str:
    return " ".join(line for line in _chat_lines(app) if line)


def _panel_text(widget: Static) -> str:
    buffer = StringIO()
    Console(file=buffer, width=160, color_system=None).print(widget.content)
    return " ".join(buffer.getvalue().split())


async def _flush(app: AgentXTui, pilot: Pilot) -> None:
    await pilot.pause()
    await app.workers.wait_for_complete()
    await pilot.pause()


async def _submit(pilot: Pilot, app: AgentXTui, text: str) -> None:
    app.query_one("#prompt", Input).value = text
    await pilot.press("enter")
    await _flush(app, pilot)


def _finding(finding_id: str, **overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "id": finding_id,
        "session_id": "unused",
        "skill_name": "hunt-xss",
        "title": "Reflected XSS in search",
        "severity": "HIGH",
        "endpoint": "/search",
        "description": "User input reflected into the response body",
        "impact": "Attacker steals session cookies",
        "steps_to_reproduce": ["GET /search?q=1", "Payload executes"],
        "evidence": {"request": "GET /search?q=1"},
    }
    fields.update(overrides)
    return Finding(**fields)


class _FakeMCP:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.warnings = ["browser: connection refused"]
        self.server_count = 0
        self.tool_count = 0

    async def initialize(self) -> int:
        if self.fail:
            raise RuntimeError("spawn failed")
        self.server_count = 2
        self.tool_count = 5
        return self.server_count

    def summary(self) -> dict[str, Any]:
        return {
            "servers": [
                {
                    "name": "browser",
                    "transport": "stdio",
                    "auto_approve": False,
                    "tools": ["navigate", "click"],
                }
            ],
            "tool_count": 5,
        }

    async def close(self) -> None:
        return None

    @property
    def is_connected(self) -> bool:
        return self.server_count > 0


class _FakeRecon:
    async def run(self, target: str, stages: list[str] | None = None) -> list[ReconResult]:
        return [
            ReconResult(stage="subdomains", success=True, count=3),
            ReconResult(stage="urls", success=False, error="gau missing"),
        ]


async def test_blank_input_and_help_bindings(hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        log = app.query_one("#chat", RichLog)
        before = len(log.lines)
        await _submit(pilot, app, "   ")
        assert len(log.lines) == before

        await _submit(pilot, app, "/help")
        assert _chat(app).count("Slash commands") == 1

        await app._handle_slash("/h")
        await _flush(app, pilot)
        assert _chat(app).count("Slash commands") == 2

        await app._handle_slash("/?")
        await _flush(app, pilot)
        assert _chat(app).count("Slash commands") == 3

        await pilot.press("f1")
        await pilot.pause()
        assert _chat(app).count("Slash commands") == 4


async def test_plain_turn_traces_and_worker_error(
    hermetic: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _tui() as (app, pilot):
        prompt = app.query_one("#prompt", Input)
        idle_placeholder = prompt.placeholder

        await _submit(pilot, app, "hello agentx")
        text = _chat(app)
        assert "you hello agentx" in text
        assert "fake model reply" in text
        assert prompt.value == ""
        assert prompt.placeholder == idle_placeholder

        async def _traced(*args: Any, **kwargs: Any) -> OrchestratorResponse:
            return OrchestratorResponse(
                text="traced reply",
                tool_traces=[
                    SimpleNamespace(server="burp", tool="send_http_request", ok=True),
                    SimpleNamespace(server="browser", tool="navigate", ok=False),
                ],
            )

        monkeypatch.setattr(orchestrator, "handle_message", _traced)
        await _submit(pilot, app, "run a tool")
        text = _chat(app)
        assert "burp.send_http_request ok" in text
        assert "browser.navigate fail" in text
        assert "traced reply" in text

        async def _boom(*args: Any, **kwargs: Any) -> OrchestratorResponse:
            raise RuntimeError("provider exploded")

        monkeypatch.setattr(orchestrator, "handle_message", _boom)
        await _submit(pilot, app, "one more turn")
        assert "Error: provider exploded" in _chat(app)
        assert prompt.placeholder == idle_placeholder


async def test_target_usage_update_and_create(hermetic: dict[str, str]) -> None:
    first = session_manager.create_session("pre.example.com")
    async with _tui() as (app, pilot):
        assert "Target: pre.example.com" in _chat(app)

        await app._handle_slash("/target")
        await _flush(app, pilot)
        assert "Usage: /target <url|domain>" in _chat(app)

        await app._handle_slash("/target example.com")
        await _flush(app, pilot)
        current = session_manager.get_session()
        assert current is not None and current.id == first.id
        assert current.target == "example.com"
        assert current.context.target == "example.com"
        assert "Target set: example.com" in _chat(app)
        assert "example.com" in _panel_text(app.query_one("#status", Static))

        session_manager.close_session()
        await app._handle_slash("/target fresh.test")
        await _flush(app, pilot)
        created = session_manager.get_session()
        assert created is not None and created.id != first.id
        assert created.target == "fresh.test"
        assert "Target set: fresh.test" in _chat(app)


async def test_status_findings_and_validate(hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        session = session_manager.get_session()
        assert session is not None
        session_manager.add_finding(_finding("f-high"))
        session_manager.add_finding(
            _finding(
                "f-med",
                severity="MEDIUM",
                title="Open redirect",
                endpoint="/next",
                steps_to_reproduce=[],
            )
        )

        await app._handle_slash("/status")
        await _flush(app, pilot)
        text = _chat(app)
        assert f"Session: {session.id}" in text
        assert "Target: (unset)" in text
        assert "Findings: 2 (" in text
        assert "HIGH=1" in text and "MEDIUM=1" in text

        await app._handle_slash("/findings")
        await _flush(app, pilot)
        table = app.query_one("#findings", DataTable)
        assert table.row_count == 2
        rows = {tuple(table.get_row_at(i)) for i in range(table.row_count)}
        assert ("HIGH", "Reflected XSS in search", "/search") in rows
        assert ("MEDIUM", "Open redirect", "/next") in rows
        assert "Findings: 2" in _chat(app)

        await app._handle_slash("/findings high")
        await _flush(app, pilot)
        assert table.row_count == 1
        assert table.get_row_at(0)[0] == "HIGH"

        await app._handle_slash("/validate")
        await _flush(app, pilot)
        assert "1/2 passed the automated gate" in _chat(app)
        findings = session.get_findings()
        notes = {f.id: f.validation_notes for f in findings}
        assert notes["f-high"] == "Passed automated triage gate."
        assert notes["f-med"].startswith("Missing required field(s)")
        assert "steps_to_reproduce" in notes["f-med"]
        assert {f.id: f.validated for f in findings} == {"f-high": True, "f-med": False}
        panel = _panel_text(app.query_one("#status", Static))
        assert session.id in panel
        assert "1 validated" in panel

        await app._handle_slash("/validate")
        await _flush(app, pilot)
        assert "No untriaged findings." in _chat(app)


async def test_sync_slash_commands(hermetic: dict[str, str]) -> None:
    session_manager._current_session = HuntSession(id="ghost-session")
    async with _tui() as (app, pilot):
        await app._handle_slash("/skills")
        await _flush(app, pilot)
        expected = skill_registry.discover_skills()
        assert f"Skills ({len(expected)}):" in _chat(app)

        app.query_one("#chat", RichLog).clear()
        await app._handle_slash("/skills hunt-xss")
        await _flush(app, pilot)
        bullets = [line for line in _chat_lines(app) if line.startswith("•")]
        assert len(bullets) == 1
        assert "hunt-xss" in bullets[0]

        await app._handle_slash("/sessions")
        await _flush(app, pilot)
        assert "No sessions yet." in _chat(app)

        session_manager.create_session("real.dev")
        await app._handle_slash("/sessions")
        await _flush(app, pilot)
        text = _chat(app)
        assert "Sessions:" in text
        assert "real.dev" in text

        await app._handle_slash("/auto on")
        await _flush(app, pilot)
        assert orchestrator.auto_execute is True
        assert "Auto-execute: True" in _chat(app)
        await app._handle_slash("/auto off")
        await _flush(app, pilot)
        assert orchestrator.auto_execute is False
        assert "Auto-execute: False" in _chat(app)

        await app._handle_slash("/mode")
        await _flush(app, pilot)
        assert "Usage: /mode ask|auto|yolo" in _chat(app)
        await app._handle_slash("/mode ask")
        await _flush(app, pilot)
        assert permission_gate.mode == "ask"
        assert "Permission mode: ask" in _chat(app)
        await app._handle_slash("/mode yolo")
        await _flush(app, pilot)
        assert permission_gate.mode == "yolo"
        assert settings.permission_mode == "yolo"
        assert "state-changing tools will run with no review" in _chat(app)

        await app._handle_slash("/mcp")
        await _flush(app, pilot)
        assert "No MCP servers connected." in _chat(app)

        await app._handle_slash("/plan")
        await _flush(app, pilot)
        assert "Usage: /plan <request>" in _chat(app)

        await app._handle_slash("/target sync.test")
        await _flush(app, pilot)
        await app._handle_slash("/handoff")
        await _flush(app, pilot)
        text = _chat(app)
        assert "Handoff" in text
        assert "sync.test" in text

        await app._handle_slash("/frobnicate")
        await _flush(app, pilot)
        assert "Unknown command: /frobnicate. Try /help" in _chat(app)

        await app._handle_slash("/clear")
        await _flush(app, pilot)
        after_clear = _chat(app)
        assert "Conversation cleared." in after_clear
        assert "Unknown command" not in after_clear


async def test_mcp_init_and_show(hermetic: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        settings, "mcp_servers", [MCPConfig(name="browser", transport="stdio", command="npx")]
    )
    monkeypatch.setattr("agentx.tui.app.mcp_manager", _FakeMCP())
    async with _tui() as (app, pilot):
        text = _chat(app)
        assert "MCP: 2 server(s), 5 tool(s)" in text
        assert "MCP: browser: connection refused" in text
        assert permission_gate.approver is not None
        panel = _panel_text(app.query_one("#status", Static))
        assert "2 servers · 5 tools" in panel

        await app._handle_slash("/mcp")
        await _flush(app, pilot)
        text = _chat(app)
        assert "MCP connected tools (5):" in text
        assert "browser (stdio)" in text
        assert "navigate, click" in text

    monkeypatch.setattr("agentx.tui.app.mcp_manager", _FakeMCP(fail=True))
    async with _tui() as (app, pilot):
        text = _chat(app)
        assert "MCP init warning: spawn failed" in text
        assert "MCP: browser: connection refused" in text


async def test_recon_command(hermetic: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentx.tui.app.recon_pipeline", _FakeRecon())
    async with _tui() as (app, pilot):
        await app._handle_slash("/recon")
        await _flush(app, pilot)
        assert "Set a target first with /target" in _chat(app)

        session = session_manager.get_session()
        assert session is not None
        session.target = "recon.test"

        await app._handle_slash("/recon subdomains,urls")
        await _flush(app, pilot)
        text = _chat(app)
        assert "OK subdomains: 3 results" in text
        assert "FAIL urls: gau missing" in text

        await app._handle_slash("/recon")
        await _flush(app, pilot)
        assert _chat(app).count("OK subdomains: 3 results") == 2


async def test_report_command(hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        await app._handle_slash("/report")
        await _flush(app, pilot)
        assert "No findings to report." in _chat(app)

        session = session_manager.get_session()
        assert session is not None
        session.target = "rep.test"
        session_manager.add_finding(_finding("rep-1"))

        await app._handle_slash("/report")
        await _flush(app, pilot)
        assert "Report saved:" in _chat(app)
        reports_dir = settings.data_dir / "reports"
        assert len(list(reports_dir.glob("*.md"))) == 1

        await app._handle_slash("/report json")
        await _flush(app, pilot)
        assert "Report saved:" in _chat(app)
        assert len(list(reports_dir.glob("*.json"))) == 1


async def test_plan_and_go_commands(
    hermetic: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    hermetic["text"] = PLAN_TEXT
    async with _tui() as (app, pilot):
        await app._handle_slash("/go")
        await _flush(app, pilot)
        assert "No pending plan. Use /plan first." in _chat(app)

        await app._handle_slash("/plan hunt example.com")
        await _flush(app, pilot)
        text = _chat(app)
        assert "Execution Plan" in text
        assert "to run this plan" in text
        assert orchestrator._pending_plan is not None

        async def _fake_execute(plan: Any) -> ExecutionResult:
            return ExecutionResult(plan=plan, step_results=[], errors=[], new_findings=[])

        monkeypatch.setattr(
            "agentx.core.orchestrator.executor",
            SimpleNamespace(execute_plan=_fake_execute),
        )
        await app._handle_slash("/go")
        await _flush(app, pilot)
        text = _chat(app)
        assert "Executing 1 step(s)" in text
        assert "[auto-execute]" in text
        assert "Execution Result" in text
        assert "Success: True" in text
        assert orchestrator._pending_plan is None


async def test_commands_without_active_session(hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        session_manager.close_session()
        assert session_manager.get_session() is None

        await app._handle_slash("/status")
        await app._handle_slash("/validate")
        await app._handle_slash("/handoff")
        await app._handle_slash("/findings")
        app._update_status()
        app._refresh_findings()
        await app._handle_slash("/report")
        await _flush(app, pilot)

        text = _chat(app)
        assert text.count("No active session.") == 4
        assert "Findings: 0" in text
        assert app.query_one("#findings", DataTable).row_count == 0

        panel = _panel_text(app.query_one("#status", Static))
        assert "Providers" in panel
        assert "Session" not in panel
        assert "(unset)" not in panel

        await app._handle_slash("/clear")
        await _flush(app, pilot)
        assert _chat(app) == "Conversation cleared."


async def test_function_key_bindings(hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        session_manager.add_finding(_finding("fk1"))
        log = app.query_one("#chat", RichLog)

        await pilot.press("f2")
        await pilot.pause()
        assert app.query_one("#findings", DataTable).row_count == 1
        assert "1 (0 validated)" in _panel_text(app.query_one("#status", Static))

        await pilot.press("f3")
        await pilot.pause()
        assert any(line.startswith("Skills (") for line in _chat_lines(app))

        await pilot.press("ctrl+l")
        await pilot.pause()
        assert len(log.lines) == 0

        try:
            await pilot.press("ctrl+q")
        except Exception:
            pass
        assert app._exit is True


@pytest.mark.parametrize("cmd", ["/exit", "/quit", "/q"])
async def test_exit_commands(cmd: str, hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        await app._handle_slash(cmd)
        assert app._exit is True


def test_permission_screen_ctor_and_buttons() -> None:
    screen = PermissionScreen("browser", "start_scan", "run a scan")
    assert screen._server == "browser"
    assert screen._tool == "start_scan"
    assert screen._summary == "run a scan"

    dismissed: list[Any] = []

    def _record(value: Any = None) -> None:
        dismissed.append(value)

    screen.dismiss = _record
    screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="allow_session")))
    screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="allow_once")))
    screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="deny")))
    screen.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id=None)))
    assert dismissed == ["session", "once", "deny", "deny"]


async def test_permission_screen_mounts_with_box(hermetic: dict[str, str]) -> None:
    async with _tui() as (app, pilot):
        screen = PermissionScreen("browser", "scan", "scan the target")
        app.push_screen(screen)
        await pilot.pause()
        box = screen.query_one(".permission-box")
        assert "permission-box" in box.classes


async def test_mcp_approve_callback_flows(
    hermetic: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _tui() as (app, _pilot):

        def _push_session_twice(screen: Any, callback: Any = None) -> None:
            if callback:
                callback("session")
                callback("once")

        monkeypatch.setattr(app, "push_screen", _push_session_twice)
        assert await app._mcp_approve("browser", "navigate", {}, "open the target") is True
        assert "browser.navigate" in permission_gate.session_approved

        def _push_once(screen: Any, callback: Any = None) -> None:
            if callback:
                callback("once")

        monkeypatch.setattr(app, "push_screen", _push_once)
        assert await app._mcp_approve("browser", "click", {}, "click a button") is True
        assert "browser.click" not in permission_gate.session_approved

        def _push_deny(screen: Any, callback: Any = None) -> None:
            if callback:
                callback(None)

        monkeypatch.setattr(app, "push_screen", _push_deny)
        assert await app._mcp_approve("browser", "type", {}, "type into the page") is False

        def _push_boom(screen: Any, callback: Any = None) -> None:
            raise RuntimeError("screen stack unavailable")

        monkeypatch.setattr(app, "push_screen", _push_boom)
        assert await app._mcp_approve("browser", "close", {}, "nope") is False
