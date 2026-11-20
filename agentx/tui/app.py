"""AgentX full-screen terminal user interface (Textual)."""

from __future__ import annotations

import asyncio

from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Static

from agentx import __version__
from agentx.ai.router import close_ai, init_ai
from agentx.config import settings
from agentx.core.handoff import generate_handoff
from agentx.core.memory import memory
from agentx.core.orchestrator import orchestrator
from agentx.core.session import session_manager
from agentx.core.triage import triage_findings
from agentx.mcp import mcp_manager, permission_gate
from agentx.recon.pipeline import recon_pipeline
from agentx.reporting.generator import report_generator
from agentx.skills.registry import skill_registry
from agentx.tools.local_tools import load_local_tools

BANNER = r"""
   _                    _  __  __
  /_\  __ _ ___ _ _  | |_\ \/ /
 / _ \/ _` / -_) ' \ |  _|\  /
/_/ \_\__, \___|_||_| \__|/_/
      |___/
"""

SLASH_HELP = (
    "[bold]Slash commands[/bold]\n"
    "  /help                 Show this help\n"
    "  /target <url|domain>  Set the target\n"
    "  /status               Session status\n"
    "  /skills [filter]      List skills\n"
    "  /plan <request>       Build a plan\n"
    "  /go                   Execute the pending plan\n"
    "  /findings [severity]  List findings\n"
    "  /validate             Triage findings\n"
    "  /report [format]      Report (markdown|html|json)\n"
    "  /recon [stages]       Run recon stages\n"
    "  /mcp                  Show connected MCP tools\n"
    "  /mode ask|auto|yolo   Permission gate mode\n"
    "  /auto on|off          Toggle auto-execute\n"
    "  /sessions             Past sessions\n"
    "  /handoff              Cross-session handoff report\n"
    "  /clear                Clear the conversation\n"
    "  /exit                 Quit"
)


class PermissionScreen(ModalScreen[str]):
    """Ask the operator whether an MCP tool call is allowed."""

    def __init__(self, server: str, tool: str, summary: str) -> None:
        super().__init__()
        self._server = server
        self._tool = tool
        self._summary = summary

    def compose(self) -> ComposeResult:
        with Vertical(classes="permission-box"):
            yield Label("[yellow bold]MCP tool approval[/yellow bold]", id="ptitle")
            yield Label(
                f"[bold]{escape(self._server)}.{escape(self._tool)}[/bold]\n\n{escape(self._summary)}",
                id="psummary",
            )
            with Horizontal():
                yield Button("Allow once", id="allow_once", variant="success")
                yield Button("Allow session", id="allow_session", variant="primary")
                yield Button("Deny", id="deny", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "allow_once":
            self.dismiss("once")
        elif event.button.id == "allow_session":
            self.dismiss("session")
        else:
            self.dismiss("deny")


class AgentXTui(App):
    """Full-screen AgentX console."""

    TITLE = "AgentX"
    SUB_TITLE = f"v{__version__}"

    CSS = """
    Screen { layout: vertical; }
    #body { height: 1fr; }
    #main { width: 3fr; height: 1fr; }
    #sidebar {
        width: 38;
        height: 1fr;
        border-left: solid $panel;
        padding: 0 1;
    }
    #chat { height: 1fr; border: solid $panel; padding: 0 1; }
    #prompt { border: tall $accent; }
    #status { height: auto; margin-bottom: 1; }
    #findings { height: 1fr; }
    PermissionScreen {
        align: center middle;
        background: $surface;
        border: thick $primary;
    }
    .permission-box { width: 86; max-height: 60%; }
    #ptitle { text-align: center; text-style: bold; }
    #psummary {
        margin: 1 0;
        padding: 0 1;
        height: auto;
        max-height: 22;
        overflow-y: auto;
    }
    PermissionScreen Horizontal { height: 3; align: center middle; }
    """

    BINDINGS = [
        ("f1", "help", "Help"),
        ("f2", "findings", "Findings"),
        ("f3", "skills", "Skills"),
        ("ctrl+l", "clear_log", "Clear"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="main"):
                yield RichLog(id="chat", wrap=True, markup=True, highlight=True)
                yield Input(placeholder="Ask AgentX… or /help  (F1 help)", id="prompt")
            with Vertical(id="sidebar"):
                yield Static(id="status")
                yield DataTable(id="findings", zebra_stripes=True)
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_columns("Sev", "Title", "Endpoint")

        load_local_tools()
        session = session_manager.get_session() or session_manager.create_session("")

        try:
            await init_ai()
        except Exception as exc:  # pragma: no cover - defensive
            self._write_system(f"AI init warning: {exc}")

        if not settings.get_enabled_providers():
            self._write_system(
                "No AI provider enabled. Edit config/default.yaml (set enabled: true)."
            )

        await self._mcp_init()

        log = self.query_one("#chat", RichLog)
        log.write(Panel(escape(BANNER.strip("\n")), title="AgentX", border_style="cyan"))
        if session.target:
            self._write_system(f"Target: {session.target}")
        self._write_system("Type a request, or /help for commands.")

        self._update_status()
        self.query_one("#prompt", Input).focus()

    async def _mcp_init(self) -> None:
        """Connect configured MCP servers and attach the TUI approval prompt."""
        if not settings.get_enabled_mcp_servers():
            self._write_system(
                "[dim]No MCP servers enabled. Add `mcp_servers` to config/default.yaml.[/dim]"
            )
            return
        permission_gate.set_mode(settings.permission_mode)
        permission_gate.approver = self._mcp_approve
        try:
            await mcp_manager.initialize()
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            self._write_system(f"MCP init warning: {exc}")
        if mcp_manager.server_count:
            self._write_system(
                f"[green]MCP:[/green] {mcp_manager.server_count} server(s), "
                f"{mcp_manager.tool_count} tool(s)"
            )
        for warning in mcp_manager.warnings:
            self._write_system(f"[yellow]MCP:[/yellow] {warning}")

    async def on_unmount(self) -> None:
        await close_ai()
        await mcp_manager.close()
        session_manager.close_session()

    # ------------------------------------------------------------------ input

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        self.query_one("#prompt", Input).value = ""
        self._write_user(text)

        if text.startswith("/"):
            await self._handle_slash(text)
        else:
            self._run_turn(text)

    # ---------------------------------------------------------------- workers

    @work(exclusive=True)
    async def _run_turn(self, text: str) -> None:
        await self._with_busy(self._do_turn(text))

    @work(exclusive=True)
    async def _run_async_slash(self, command: str, arg: str) -> None:
        await self._with_busy(self._do_async_slash(command, arg))

    async def _with_busy(self, coro) -> None:
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = "AgentX is working…"
        try:
            await coro
        except Exception as exc:  # pragma: no cover - surfaced to the user
            self._write_system(f"[red]Error:[/red] {escape(str(exc))}")
        finally:
            prompt.placeholder = "Ask AgentX… or /help  (F1 help)"
            prompt.focus()
            self._update_status()

    async def _do_turn(self, text: str) -> None:
        resp = await orchestrator.handle_message(text)
        for tr in resp.tool_traces:
            mark = "[green]ok[/green]" if tr.ok else "[red]fail[/red]"
            self._write_system(f"[dim]  {tr.server}.{tr.tool}[/dim] {mark}")
        if resp.text:
            self._write_agent(resp.text)

    async def _do_async_slash(self, command: str, arg: str) -> None:
        session = session_manager.get_session()

        if command == "/plan":
            if not arg:
                self._write_system("Usage: /plan <request>")
                return
            resp = await orchestrator.handle_message(arg, auto_execute=False)
            self._write_agent(resp.text)

        elif command == "/go":
            if orchestrator._pending_plan is None:
                self._write_system("No pending plan. Use /plan first.")
                return
            resp = await orchestrator.handle_message("go")
            self._write_agent(resp.text)

        elif command == "/recon":
            if not session or not session.target:
                self._write_system("Set a target first with /target")
                return
            stages = [s.strip() for s in arg.split(",")] if arg else None
            results = await recon_pipeline.run(session.target, stages)
            for r in results:
                if r.success:
                    self._write_system(f"[green]OK[/green] {r.stage}: {r.count} results")
                else:
                    self._write_system(f"[red]FAIL[/red] {r.stage}: {r.error}")

        elif command == "/report":
            if not session:
                self._write_system("No active session.")
                return
            findings = session.get_findings()
            if not findings:
                self._write_system("No findings to report.")
                return
            path = report_generator.save(
                findings,
                target=session.target,
                session_id=session.id,
                fmt=arg or "markdown",
            )
            self._write_system(f"[green]Report saved:[/green] {path}")

    # ------------------------------------------------------------ slash logic

    async def _handle_slash(self, cmd: str) -> None:
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        session = session_manager.get_session()

        if command in ("/exit", "/quit", "/q"):
            self.exit()
        elif command in ("/help", "/h", "/?"):
            self.query_one("#chat", RichLog).write(Markdown(SLASH_HELP))
        elif command == "/target":
            if not arg:
                self._write_system("Usage: /target <url|domain>")
                return
            if not session:
                session = session_manager.create_session(arg)
            session.target = arg
            session.context.target = arg
            self._write_system(f"Target set: {arg}")
            self._update_status()
        elif command == "/status":
            self._write_system(self._status_text())
        elif command == "/skills":
            self._show_skills(arg)
        elif command == "/findings":
            self._refresh_findings(arg.upper() if arg else None)
            total = len(session.get_findings()) if session else 0
            self._write_system(f"Findings: {total}")
        elif command == "/validate":
            self._run_validation()
        elif command == "/sessions":
            self._show_sessions()
        elif command == "/auto":
            orchestrator.auto_execute = arg.lower() in ("on", "true", "1", "yes")
            self._write_system(f"Auto-execute: {orchestrator.auto_execute}")
        elif command == "/mcp":
            self._show_mcp()
        elif command == "/mode":
            mode = arg.lower()
            if mode not in ("ask", "auto", "yolo"):
                self._write_system("Usage: /mode ask|auto|yolo")
            else:
                settings.permission_mode = mode
                permission_gate.set_mode(mode)
                suffix = (
                    " [bold red](state-changing tools will run with no review)[/bold red]"
                    if mode == "yolo"
                    else ""
                )
                self._write_system(f"Permission mode: {mode}{suffix}")
        elif command == "/clear":
            if session:
                memory.clear_conversation(session.id)
            self.query_one("#chat", RichLog).clear()
            self._write_system("Conversation cleared.")
        elif command == "/handoff":
            if not session:
                self._write_system("No active session.")
                return
            self.query_one("#chat", RichLog).write(Markdown(generate_handoff(session)))
        elif command in ("/plan", "/go", "/recon", "/report"):
            self._run_async_slash(command, arg)
        else:
            self._write_system(f"Unknown command: {escape(command)}. Try /help")

    def _run_validation(self) -> None:
        session = session_manager.get_session()
        if not session:
            self._write_system("No active session.")
            return
        findings = [f for f in session.get_findings() if not f.validation_notes]
        if not findings:
            self._write_system("No untriaged findings.")
            return
        passed, total = triage_findings(findings)
        self._write_system(f"[green]Triage:[/green] {passed}/{total} passed the automated gate.")
        self._refresh_findings()
        self._update_status()

    # ------------------------------------------------------------- ui helpers

    def _write_user(self, text: str) -> None:
        self.query_one("#chat", RichLog).write(f"[bold cyan]you[/bold cyan]  {escape(text)}")

    def _write_agent(self, text: str) -> None:
        self.query_one("#chat", RichLog).write(Markdown(text))

    def _write_system(self, text: str) -> None:
        self.query_one("#chat", RichLog).write(f"[dim]{text}[/dim]")

    def _status_text(self) -> str:
        session = session_manager.get_session()
        if not session:
            return "No active session."
        findings = session.get_findings()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        sev = ", ".join(f"{k}={v}" for k, v in by_sev.items()) or "none"
        return (
            f"Session: {session.id}\n"
            f"Target: {session.target or '(unset)'}\n"
            f"Phase: {session.current_phase}\n"
            f"Findings: {len(findings)} ({sev})"
        )

    def _update_status(self) -> None:
        session = session_manager.get_session()
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold cyan")
        table.add_column()

        if session:
            findings = session.get_findings()
            protected = sum(1 for f in findings if f.validated)
            table.add_row("Session", session.id)
            table.add_row("Target", session.target or "(unset)")
            table.add_row("Phase", session.current_phase)
            table.add_row("Findings", f"{len(findings)}  ({protected} validated)")
            table.add_row(
                "Skills done",
                str(len(session.completed_skills)),
            )

        table.add_row(
            "Providers",
            str(len(settings.get_enabled_providers())) + " enabled",
        )
        table.add_row(
            "MCP",
            f"{mcp_manager.server_count} servers · {mcp_manager.tool_count} tools",
        )
        table.add_row("Auto", "on" if orchestrator.auto_execute else "off")
        self.query_one("#status", Static).update(Panel(table, title="Status"))

        if session:
            self._refresh_findings()

    def _refresh_findings(self, severity: str | None = None) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear()
        session = session_manager.get_session()
        if not session:
            return
        findings = session.get_findings(severity)
        for f in findings:
            table.add_row(f.severity[:8], f.title[:44], f.endpoint[:30])

    def _show_skills(self, filter_text: str) -> None:
        skill_registry.load_skill_configs()
        discovered = skill_registry.discover_skills()
        names = sorted(n for n in discovered if not filter_text or filter_text.lower() in n.lower())
        self._write_system(f"Skills ({len(names)}):\n" + "\n".join(f"  • {n}" for n in names))

    def _show_sessions(self) -> None:
        rows = memory.list_sessions()
        if not rows:
            self._write_system("No sessions yet.")
            return
        lines = ["Sessions:"]
        for row in rows:
            lines.append(f"  {row['id']}  {row.get('target') or '-'}  {row.get('updated_at', '')}")
        self._write_system("\n".join(lines))

    def _show_mcp(self) -> None:
        summary = mcp_manager.summary()
        servers = summary["servers"]
        if not servers:
            self._write_system(
                "No MCP servers connected. Enable `mcp_servers` in config/default.yaml, "
                "then restart."
            )
            return
        lines = [f"MCP connected tools ({summary['tool_count']}):"]
        for s in servers:
            lines.append(f"  • {s['name']} ({s['transport']})")
            tool_names = ", ".join(s["tools"][:40])
            if tool_names:
                lines.append(f"      {tool_names}")
        for warning in mcp_manager.warnings:
            lines.append(f"[yellow]  MCP: {warning}[/yellow]")
        self._write_system("\n".join(lines))

    async def _mcp_approve(self, server: str, tool: str, arguments: dict, summary: str) -> bool:
        """Show the approval modal and wait for the operator's answer."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bool] = loop.create_future()

        def _on_result(value: str | None) -> None:
            if future.done():
                return
            if value == "session":
                permission_gate.allow_session(f"{server}.{tool}")
                future.set_result(True)
            elif value == "once":
                future.set_result(True)
            else:
                future.set_result(False)

        try:
            self.push_screen(PermissionScreen(server, tool, summary), callback=_on_result)
        except Exception:  # noqa: BLE001 - deny instead of hanging
            return False
        return await future

    # actions for bindings
    def action_help(self) -> None:
        self.query_one("#chat", RichLog).write(Markdown(SLASH_HELP))

    def action_findings(self) -> None:
        self._refresh_findings()
        self._update_status()

    def action_skills(self) -> None:
        self._show_skills("")

    def action_clear_log(self) -> None:
        self.query_one("#chat", RichLog).clear()

    def action_quit(self) -> None:
        self.exit()
