"""AgentX CLI - command-line interface powered by Typer + Rich."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from agentx import __version__
from agentx.ai.router import close_ai, init_ai
from agentx.attack_lookup import get_attack_index
from agentx.config import load_config, save_config, settings
from agentx.core.handoff import generate_handoff
from agentx.core.memory import memory
from agentx.core.orchestrator import Orchestrator, orchestrator
from agentx.core.session import session_manager
from agentx.core.triage import triage_findings
from agentx.mcp import mcp_manager, permission_gate
from agentx.recon.pipeline import recon_pipeline
from agentx.reporting.generator import report_generator
from agentx.skills.install import (
    Target,
    detect_targets,
    find_target,
    install,
    known_targets,
    post_install_hint,
)
from agentx.skills.registry import skill_registry
from agentx.tools.installer import get_installer
from agentx.tools.local_tools import load_local_tools

_DEFAULT_CONFIG = Path("config") / "default.yaml"
if _DEFAULT_CONFIG.exists():
    try:
        load_config(_DEFAULT_CONFIG)
    except Exception as exc:  # pragma: no cover - config errors should not crash CLI
        Console().print(f"[yellow]Config load warning: {exc}[/yellow]")

app = typer.Typer(
    name="agentx",
    help="AgentX - AI-powered penetration testing and bug bounty agent.",
    add_completion=False,
    no_args_is_help=False,
)
console = Console()

BANNER = r"""
   _                    _  __  __
  /_\  __ _ ___ _ _  | |_\ \/ /
 / _ \/ _` / -_) ' \ |  _|\  /
/_/ \_\__, \___|_||_| \__|/_/
      |___/
"""

_PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o",
        "env": "OPENAI_API_KEY",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-3-5-sonnet-20241022",
        "env": "ANTHROPIC_API_KEY",
    },
    "ollama": {"base_url": "http://localhost:11434", "model": "llama3.1:8b", "env": None},
    "lmstudio": {"base_url": "http://localhost:1234/v1", "model": "local-model", "env": None},
    "custom": {
        "base_url": "https://api.example.com/v1",
        "model": "my-model",
        "env": "MY_API_KEY",
    },
}

SLASH_HELP = """
[bold]Slash commands[/bold]
  /help                 Show this help
  /target <url|domain>  Set the target
  /status               Show session status
  /skills [filter]      List available skills
  /plan <request>       Build an execution plan
  /go                   Execute the pending plan
  /findings [severity]  List findings
  /validate             Triage findings with the automated gate
  /report [format]      Generate a report (markdown|html|json)
  /recon [stages]       Run recon stages (subdomains,http_probe,urls,fingerprint)
  /mcp                  Show connected MCP servers and tools
  /mode ask|auto|yolo   Permission gate: ask / auto / yolo (no review)
  /auto on|off          Toggle auto-execute
  /sessions             List past sessions
  /handoff              Generate a cross-session handoff report
  /clear                Clear the conversation
  /exit                 Quit
"""


def _print_error(msg: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {msg}")


def _print_success(msg: str) -> None:
    console.print(f"[bold green]{msg}[/bold green]")


def _config_path() -> Path:
    return Path("config") / "default.yaml"


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config YAML."),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging."),
) -> None:
    """Launch the AgentX interactive chat or a subcommand."""
    if version:
        console.print(f"AgentX v{__version__}")
        raise typer.Exit()

    if config:
        load_config(config)

    if debug:
        settings.debug = True

    # If a subcommand is invoked, don't run the REPL
    if ctx.invoked_subcommand is not None:
        return

    asyncio.run(_chat_loop(invoke_ai=True))


@app.command()
def chat(
    target: str | None = typer.Option(None, "--target", "-t", help="Set target on start."),
    auto: bool = typer.Option(False, "--auto", help="Auto-execute plans."),
) -> None:
    """Start the interactive chat REPL."""
    if target:
        session_manager.create_session(target)
    orchestrator.auto_execute = auto
    asyncio.run(_chat_loop(invoke_ai=True, seed_target=target))


@app.command()
def tui(
    target: str | None = typer.Option(None, "--target", "-t", help="Set target on start."),
    auto: bool = typer.Option(False, "--auto", help="Auto-execute plans."),
) -> None:
    """Launch the full-screen terminal UI (TUI)."""
    if target:
        session_manager.create_session(target)
    orchestrator.auto_execute = auto
    from agentx.tui import run_tui

    run_tui()


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target domain or URL."),
    stages: str | None = typer.Option(
        None,
        "--stages",
        "-s",
        help="Comma-separated stages: subdomains,http_probe,urls,fingerprint",
    ),
) -> None:
    """Run a reconnaissance pipeline against a target."""
    session_manager.create_session(target)
    stage_list = [s.strip() for s in stages.split(",")] if stages else None

    async def _run() -> None:
        console.print(Panel(f"Recon on [bold cyan]{target}[/bold cyan]", title="AgentX Recon"))
        results = await recon_pipeline.run(target, stage_list)
        for r in results:
            if r.success:
                console.print(f"[green]OK[/green] {r.stage}: {r.count} results")
                if r.data:
                    table = Table(title=r.stage, show_lines=False)
                    table.add_column("#", justify="right", style="dim")
                    table.add_column("Result")
                    for i, item in enumerate(r.data[:25], 1):
                        table.add_row(str(i), str(item)[:160])
                    console.print(table)
            else:
                console.print(f"[red]FAIL[/red] {r.stage}: {r.error}")

    asyncio.run(_run())


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or URL."),
    request: str | None = typer.Option(
        None, "--request", "-r", help="Custom hunt request/instruction."
    ),
    auto: bool = typer.Option(True, "--auto/--no-auto", help="Auto-execute the plan."),
) -> None:
    """Recon + plan + hunt a target in one shot."""
    session_manager.create_session(target)
    req = (
        request
        or f"Perform a full security assessment of {target}: recon, map endpoints, then hunt for vulnerabilities."
    )

    async def _run() -> None:
        await init_ai()
        orch = Orchestrator(auto_execute=auto)
        try:
            resp = await orch.handle_message(req, target=target, auto_execute=auto)
            console.print(Markdown(resp.text))
        finally:
            await close_ai()

    asyncio.run(_run())


@app.command()
def report(
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown|html|json"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path."),
    session_id: str | None = typer.Option(None, "--session", "-s", help="Session id."),
) -> None:
    """Generate a findings report."""
    session = session_manager.get_session(session_id)
    if not session:
        _print_error("No active session found.")
        raise typer.Exit(1)

    findings = session.get_findings()
    if not findings:
        console.print("[yellow]No findings to report.[/yellow]")
        raise typer.Exit()

    path = report_generator.save(
        findings, target=session.target, session_id=session.id, fmt=fmt, output_path=output
    )
    _print_success(f"Report saved: {path}")


@app.command()
def skills(
    action: str = typer.Argument("list", help="list | info"),
    name: str | None = typer.Argument(None, help="Skill name (for info)."),
) -> None:
    """List or inspect available skills."""
    skill_registry.load_skill_configs()
    discovered = skill_registry.discover_skills()

    if action == "info" and name:
        info = discovered.get(name)
        if not info:
            _print_error(f"Skill '{name}' not found.")
            raise typer.Exit(1)
        techniques = info.get("mitre_attack") or []
        attack_line = ", ".join(techniques) if techniques else "none"
        console.print(
            Panel(
                f"[bold]{name}[/bold]\n\n{info.get('description', '')}\n\n"
                f"Category: {info.get('category')}\nPath: {info.get('path')}\n"
                f"ATT&CK: {attack_line}",
                title="Skill Info",
            )
        )
        return

    table = Table(title=f"Available Skills ({len(discovered)})")
    table.add_column("Skill", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Enabled", justify="center")
    table.add_column("Description")
    for skill_name in sorted(discovered):
        meta = discovered[skill_name]
        enabled = "yes" if skill_registry.is_enabled(skill_name) else "no"
        table.add_row(
            skill_name,
            str(meta.get("category", "")),
            enabled,
            str(meta.get("description", ""))[:70],
        )
    console.print(table)


@app.command()
def install_skills(
    target: list[str] | None = typer.Option(
        None, "--target", help="Target key (claude, opencode, ...) or a directory path. Repeatable."
    ),
    all_agents: bool = typer.Option(
        False, "--all", help="Install into every known location, not only detected ones."
    ),
    project: bool = typer.Option(
        False, "--project", help="Include project-scoped locations under the current directory."
    ),
    only: str | None = typer.Option(
        None, "--only", help="Comma-separated skill slugs to install (default: all)."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would happen."),
    force: bool = typer.Option(
        True, "--force/--keep", help="Overwrite existing skill directories (default: overwrite)."
    ),
    list_targets: bool = typer.Option(False, "--list", help="List known and detected locations."),
) -> None:
    """Install the skill playbooks into a host LLM agent (no API key needed)."""
    project_root = Path.cwd() if project else None

    if list_targets:
        table = Table(title="Skill install locations")
        table.add_column("Key", style="cyan")
        table.add_column("Agent")
        table.add_column("Detected", justify="center")
        table.add_column("Path")
        for item in known_targets(project=project_root):
            table.add_row(
                item.key,
                item.label,
                "yes" if item.detected() else "no",
                str(item.path),
            )
        console.print(table)
        return

    if target:
        chosen = []
        for value in target:
            try:
                chosen.append(find_target(value, project=project_root))
            except KeyError:
                path = Path(value).expanduser()
                chosen.append(
                    Target(key="custom", label=f"Custom ({path.name})", path=path, probe=None)
                )
    elif all_agents:
        chosen = known_targets(project=project_root)
    else:
        chosen = detect_targets(project=project_root)

    if not chosen:
        _print_error("No agent skill directory detected. Use --list, --target PATH or --all.")
        raise typer.Exit(1)

    selected = {name.strip() for name in only.split(",") if name.strip()} if only else None
    skills_dir = Path(settings.skills_dir)
    if not skills_dir.is_dir():
        _print_error(f"Skills directory not found: {skills_dir}")
        raise typer.Exit(1)

    failures = 0
    for item in chosen:
        report = install(skills_dir, item, only=selected, force=force, dry_run=dry_run)
        if not report.ok:
            failures += len(report.failed)
            for slug, error in report.failed:
                _print_error(f"{item.key}/{slug}: {error}")
        prefix = "[dry-run] " if dry_run else ""
        console.print(
            f"{prefix}[bold]{item.label}[/bold] -> {item.path}\n"
            f"  new: {len(report.created)}  updated: {len(report.updated)}  "
            f"kept: {len(report.kept)}  failed: {len(report.failed)}"
        )
        if not dry_run and report.installed:
            console.print(f"  [dim]{post_install_hint(item, report.installed)}[/dim]")

    if failures:
        raise typer.Exit(1)


@app.command()
def attack(
    technique: str | None = typer.Argument(None, help="Technique ID, e.g. T1190."),
    skill: str | None = typer.Option(None, "--skill", help="Techniques for one skill."),
    tactic: str | None = typer.Option(None, "--tactic", help="Tactic ID, e.g. TA0001."),
    search: str | None = typer.Option(None, "--search", help="Search IDs, names, skills."),
) -> None:
    """Query the MITRE ATT&CK coverage map for skills."""
    index = get_attack_index()
    totals = index.totals()

    def _technique_table(rows: list[Any], title: str) -> None:
        table = Table(title=title)
        table.add_column("Technique", style="cyan", no_wrap=True)
        table.add_column("Tactic", style="magenta")
        table.add_column("Name")
        table.add_column("Skills")
        for info in rows:
            table.add_row(
                info.id,
                info.tactic_name,
                info.name,
                ", ".join(info.skills) or "-",
            )
        console.print(table)

    if skill:
        techniques = index.techniques_for_skill(skill)
        if not techniques:
            _print_error(f"No ATT&CK techniques mapped for '{skill}'.")
            raise typer.Exit(1)
        rows = [info for t in techniques if (info := index.technique(t))]
        _technique_table(rows, f"ATT&CK for {skill}")
        return

    if tactic:
        rows = index.by_tactic(tactic)
        if not rows:
            _print_error(f"No techniques covered for tactic '{tactic}'.")
            raise typer.Exit(1)
        _technique_table(rows, f"ATT&CK {tactic} coverage")
        return

    if technique:
        info = index.technique(technique)
        if not info:
            _print_error(f"Unknown technique '{technique}'.")
            raise typer.Exit(1)
        console.print(
            Panel(
                f"[bold]{info.id} — {info.name}[/bold]\n\n"
                f"Tactic: {info.tactic_name} ({info.tactic})\n"
                f"Reference: {info.url}\n\n"
                f"Skills: {', '.join(info.skills) or 'none'}",
                title="ATT&CK Technique",
            )
        )
        return

    if search:
        rows = index.search(search)
        if not rows:
            _print_error(f"No ATT&CK match for '{search}'.")
            raise typer.Exit(1)
        _technique_table(rows, f"ATT&CK search: {search}")
        return

    table = Table(title="MITRE ATT&CK Coverage")
    table.add_column("Tactic", style="magenta")
    table.add_column("ID", style="dim")
    table.add_column("Techniques", justify="right")
    table.add_column("Catalog", justify="right")
    table.add_column("Skill links", justify="right")
    for tactic_id, row in index.coverage().items():
        table.add_row(
            str(row["name"]),
            tactic_id,
            str(row["covered"]),
            str(row["catalog"]),
            str(row["skills"]),
        )
    console.print(table)
    console.print(
        f"[dim]{totals['mapped_skills']}/{totals['skills']} skills mapped, "
        f"{totals['techniques']} techniques covered. "
        "Use `agentx attack T1190`, `--skill`, `--tactic`, or `--search`.[/dim]"
    )


def _config_wizard() -> None:
    """Interactively configure an AI provider and write it to the config file."""
    from agentx.config import AIProviderConfig

    console.print(Panel("Interactive provider setup", title="AgentX Config Wizard"))

    ptype = Prompt.ask(
        "Provider type",
        choices=list(_PROVIDER_PRESETS),
        default="openai",
    )
    preset = _PROVIDER_PRESETS[ptype]

    model = Prompt.ask("Model", default=str(preset["model"]))
    base_url = Prompt.ask("Base URL", default=str(preset["base_url"]))

    api_key: str | None = None
    env_var = preset["env"]
    if ptype in ("ollama", "lmstudio"):
        console.print("[dim]No API key needed for a local provider.[/dim]")
    elif env_var and Confirm.ask(
        f"Read the API key from the ${env_var} environment variable?", default=True
    ):
        api_key = "${" + str(env_var) + "}"
        console.print(f'[dim]Set it with: setx {env_var} "..."  (then reopen the terminal)[/dim]')
    else:
        api_key = Prompt.ask("API key", password=True) or None

    provider = AIProviderConfig(
        name=ptype,
        type=ptype,  # type: ignore[arg-type]
        api_key=api_key,
        base_url=base_url,
        model=model,
        enabled=True,
    )

    settings.ai_providers = [p for p in settings.ai_providers if p.name != ptype]
    settings.ai_providers.append(provider)

    if Confirm.ask("Use this model for planning and execution too?", default=True):
        settings.orchestrator_model = model
        settings.skill_model = model

    path = _config_path()
    save_config(path)
    _print_success(f"Saved configuration to {path}")
    console.print("Verify with [bold]agentx config --show[/bold]")


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration."),
    init: bool = typer.Option(False, "--init", help="Write a default config file."),
    wizard: bool = typer.Option(
        False, "--wizard", "-w", help="Interactively configure an AI provider."
    ),
) -> None:
    """Show, initialize, or interactively configure AgentX."""
    if wizard:
        _config_wizard()
        return

    if init:
        path = _config_path()
        save_config(path)
        _print_success(f"Wrote default config to {path}")
        return

    if show or True:
        enabled = settings.get_enabled_providers()
        console.print(
            Panel(
                f"[bold]AI Providers:[/bold] {len(enabled)} enabled / {len(settings.ai_providers)} configured\n"
                f"[bold]Orchestrator model:[/bold] {settings.orchestrator_model}\n"
                f"[bold]Skill model:[/bold] {settings.skill_model}\n"
                f"[bold]Local model:[/bold] {settings.local_model}\n"
                f"[bold]Skills dir:[/bold] {settings.skills_dir}\n"
                f"[bold]Data dir:[/bold] {settings.data_dir}\n"
                f"[bold]Burp enabled:[/bold] {settings.burp.enabled}",
                title="AgentX Configuration",
            )
        )


@app.command()
def tools(
    check: bool = typer.Option(False, "--check", help="Check installed tools."),
    missing: bool = typer.Option(False, "--missing", help="List missing tools."),
    install: str | None = typer.Option(None, "--install", help="Install a tool by name."),
    install_all: bool = typer.Option(False, "--install-all", help="Install every missing tool."),
) -> None:
    """Inspect or install external tools."""
    inst = get_installer()

    if install:

        async def _one() -> None:
            ok = await inst.install_tool(install, force=True)
            if ok:
                _print_success(f"Installed: {install}")
            else:
                _print_error(f"Could not install '{install}' (missing package manager?)")

        asyncio.run(_one())
        return

    if install_all:

        async def _all() -> None:
            for name in inst.missing_tools():
                ok = await inst.install_tool(name)
                console.print(f"{'[green]ok[/green]' if ok else '[red]fail[/red]'} {name}")

        asyncio.run(_all())
        return

    status = inst.check_all()

    if missing:
        miss = inst.missing_tools()
        if miss:
            console.print("Missing: " + ", ".join(miss))
        else:
            _print_success("All known tools installed.")
        return

    table = Table(title="External Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Path")
    for tool_name in sorted(status):
        ok = status[tool_name]
        table.add_row(
            tool_name,
            "[green]installed[/green]" if ok else "[red]missing[/red]",
            inst.get_path(tool_name) or "-",
        )
    console.print(table)


@app.command()
def sessions() -> None:
    """List past sessions."""
    rows = memory.list_sessions()
    if not rows:
        console.print("[yellow]No sessions yet.[/yellow]")
        return
    table = Table(title="Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Updated")
    for row in rows:
        table.add_row(row["id"], row.get("target") or "-", row.get("updated_at", ""))
    console.print(table)


# ---------------------------------------------------------------------------
# Interactive chat loop
# ---------------------------------------------------------------------------


async def _chat_loop(invoke_ai: bool = True, seed_target: str | None = None) -> None:
    """Interactive REPL chat loop."""
    console.print(
        Panel(
            Text.from_markup(BANNER + f"\nv{__version__}  -  type [bold]/help[/bold] for commands"),
            title="AgentX",
            border_style="cyan",
        )
    )

    session = session_manager.get_session()
    if not session:
        session = session_manager.create_session(seed_target or "")
    elif seed_target:
        session.target = seed_target
        session.context.target = seed_target

    load_local_tools()

    ai_ready = False
    if invoke_ai:
        try:
            await init_ai()
            ai_ready = bool(settings.get_enabled_providers())
        except Exception as e:
            console.print(f"[yellow]AI init warning: {e}[/yellow]")

    if not ai_ready:
        console.print(
            "[yellow]No AI provider configured. Chat/planning will be limited. "
            "Edit config/default.yaml to add a provider.[/yellow]"
        )

    await _init_mcp()

    if session.target:
        console.print(f"[dim]Target: {session.target}[/dim]")

    try:
        while True:
            try:
                user_input = Prompt.ask("\n[bold cyan]agentx[/bold cyan]")
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Bye.[/dim]")
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            if user_input.startswith("/"):
                if await _handle_slash(user_input, ai_ready):
                    break
                continue

            try:
                resp = await orchestrator.handle_message(user_input)
                for tr in resp.tool_traces:
                    _print_trace(tr)
                if resp.text:
                    console.print(Markdown(resp.text))
            except Exception as e:
                _print_error(str(e))
    finally:
        await close_ai()
        await mcp_manager.close()
        session_manager.close_session()


async def _handle_slash(cmd: str, ai_ready: bool) -> bool:
    """Handle a slash command. Returns True to exit."""
    parts = cmd.strip().split(maxsplit=1)
    command = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    session = session_manager.get_session()

    if command in ("/exit", "/quit", "/q"):
        console.print("[dim]Bye.[/dim]")
        return True

    if command in ("/help", "/h", "/?"):
        console.print(Panel(Markdown(SLASH_HELP), title="Help"))
    elif command == "/target":
        if not arg:
            _print_error("Usage: /target <url|domain>")
        else:
            if not session:
                session = session_manager.create_session(arg)
            session.target = arg
            session.context.target = arg
            _print_success(f"Target set: {arg}")
    elif command == "/status":
        if session:
            console.print(_status_text(session))
        else:
            console.print("[yellow]No active session.[/yellow]")
    elif command == "/skills":
        _print_skills(arg)
    elif command == "/findings":
        _print_findings(arg)
    elif command == "/validate":
        _run_triage()
    elif command == "/plan":
        if not arg:
            _print_error("Usage: /plan <request>")
        else:
            resp = await orchestrator.handle_message(arg, auto_execute=False)
            console.print(Markdown(resp.text))
    elif command == "/go":
        if orchestrator._pending_plan is None:
            console.print("[yellow]No pending plan. Use /plan first.[/yellow]")
        else:
            resp = await orchestrator.handle_message("go")
            console.print(Markdown(resp.text))
    elif command == "/report":
        _generate_report(arg or "markdown")
    elif command == "/recon":
        await _run_recon(arg)
    elif command == "/mcp":
        _print_mcp()
    elif command == "/mode":
        mode = arg.lower()
        if mode not in ("ask", "auto", "yolo"):
            _print_error("Usage: /mode ask|auto|yolo")
        else:
            settings.permission_mode = mode
            permission_gate.set_mode(mode)
            _print_success(f"Permission mode: {mode}")
            if mode == "yolo":
                console.print(
                    "[bold red]YOLO mode: state-changing tools will run with no review.[/bold red]"
                )
    elif command == "/auto":
        orchestrator.auto_execute = arg.lower() in ("on", "true", "1", "yes")
        _print_success(f"Auto-execute: {orchestrator.auto_execute}")
    elif command == "/sessions":
        _print_sessions()
    elif command == "/handoff":
        if not session:
            _print_error("No active session.")
        else:
            console.print(Markdown(generate_handoff(session)))
    elif command == "/clear":
        if session:
            memory.clear_conversation(session.id)
            _print_success("Conversation cleared.")
    else:
        console.print(f"[yellow]Unknown command: {command}. Try /help[/yellow]")

    return False


def _status_text(session) -> Panel:
    findings = session.get_findings()
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    body = (
        f"[bold]Session:[/bold] {session.id}\n"
        f"[bold]Target:[/bold] {session.target or '(unset)'}\n"
        f"[bold]Phase:[/bold] {session.current_phase}\n"
        f"[bold]Findings:[/bold] {len(findings)}"
        + (f" ({', '.join(f'{k}={v}' for k, v in by_sev.items())})" if by_sev else "")
        + f"\n[bold]Completed:[/bold] {', '.join(session.completed_skills) or 'none'}"
    )
    return Panel(body, title="Status")


def _print_skills(filter_text: str) -> None:
    skill_registry.load_skill_configs()
    discovered = skill_registry.discover_skills()
    if not discovered:
        console.print(
            "[yellow]No skills discovered. Run scripts/copy_skills.py to install skills.[/yellow]"
        )
        return
    table = Table(title=f"Skills ({len(discovered)})")
    table.add_column("Skill", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Enabled", justify="center")
    for name in sorted(discovered):
        if filter_text and filter_text.lower() not in name.lower():
            continue
        meta = discovered[name]
        enabled = "yes" if skill_registry.is_enabled(name) else "no"
        table.add_row(name, str(meta.get("category", "")), enabled)
    console.print(table)


def _print_findings(severity: str) -> None:
    session = session_manager.get_session()
    if not session:
        console.print("[yellow]No active session.[/yellow]")
        return
    findings = session.get_findings(severity.upper() if severity else None)
    if not findings:
        console.print("[yellow]No findings.[/yellow]")
        return
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Endpoint")
    for i, f in enumerate(findings, 1):
        table.add_row(str(i), f.severity, f.title[:50], f.endpoint[:40])
    console.print(table)


def _run_triage() -> None:
    session = session_manager.get_session()
    if not session:
        console.print("[yellow]No active session.[/yellow]")
        return
    findings = [f for f in session.get_findings() if not f.validation_notes]
    if not findings:
        console.print("[yellow]No untriaged findings.[/yellow]")
        return
    passed, total = triage_findings(findings)
    _print_success(f"Triage: {passed}/{total} passed the automated gate.")


def _print_sessions() -> None:
    rows = memory.list_sessions()
    table = Table(title="Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Updated")
    for row in rows:
        table.add_row(row["id"], row.get("target") or "-", row.get("updated_at", ""))
    console.print(table)


def _generate_report(fmt: str) -> None:
    session = session_manager.get_session()
    if not session:
        _print_error("No active session.")
        return
    findings = session.get_findings()
    if not findings:
        console.print("[yellow]No findings to report.[/yellow]")
        return
    try:
        path = report_generator.save(
            findings, target=session.target, session_id=session.id, fmt=fmt
        )
        _print_success(f"Report saved: {path}")
    except Exception as e:
        _print_error(str(e))


async def _run_recon(stages: str) -> None:
    session = session_manager.get_session()
    if not session or not session.target:
        _print_error("Set a target first with /target")
        return
    stage_list = [s.strip() for s in stages.split(",")] if stages else None
    results = await recon_pipeline.run(session.target, stage_list)
    for r in results:
        if r.success:
            console.print(f"[green]OK[/green] {r.stage}: {r.count} results")
        else:
            console.print(f"[red]FAIL[/red] {r.stage}: {r.error}")


async def _init_mcp() -> None:
    """Connect configured MCP servers and attach the CLI approval prompt."""
    if not settings.get_enabled_mcp_servers():
        console.print(
            "[dim]No MCP servers enabled - add `mcp_servers` to config/default.yaml. "
            "See /mcp.[/dim]"
        )
        return

    permission_gate.set_mode(settings.permission_mode)
    permission_gate.approver = _cli_approver
    try:
        await mcp_manager.initialize()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]MCP init warning: {exc}[/yellow]")

    if mcp_manager.server_count:
        console.print(
            f"[green]MCP: connected {mcp_manager.server_count} server(s), "
            f"{mcp_manager.tool_count} tool(s)[/green]"
        )
    for warning in mcp_manager.warnings:
        console.print(f"[yellow]  MCP: {warning}[/yellow]")
    if not mcp_manager.server_count:
        console.print("[yellow]MCP: no servers connected. Use /mcp to inspect.[/yellow]")


def _print_mcp() -> None:
    summary = mcp_manager.summary()
    servers = summary["servers"]
    if not servers:
        console.print(
            "[yellow]No MCP servers connected. Enable `mcp_servers` in "
            "config/default.yaml, then restart.[/yellow]"
        )
        return
    table = Table(title=f"MCP connected tools ({summary['tool_count']})")
    table.add_column("Server", style="cyan")
    table.add_column("Transport", style="magenta")
    table.add_column("Auto-approve", justify="center")
    table.add_column("Tools")
    for s in servers:
        table.add_row(
            s["name"],
            s["transport"],
            "yes" if s["auto_approve"] else "no",
            ", ".join(s["tools"][:40]) or "-",
        )
    console.print(table)
    if mcp_manager.warnings:
        for warning in mcp_manager.warnings:
            console.print(f"[yellow]  MCP: {warning}[/yellow]")


def _print_trace(tr: Any) -> None:
    mark = "[green]ok[/green]" if tr.ok else "[red]fail[/red]"
    console.print(f"  [dim]{tr.server}.{tr.tool}[/dim] {mark} {tr.summary[:120]}")


async def _cli_approver(server: str, tool: str, arguments: dict[str, Any], summary: str) -> bool:
    console.print(
        Panel(
            f"[bold]{server}.{tool}[/bold]\n\n[dim]{summary}[/dim]",
            title="MCP tool approval",
            border_style="yellow",
        )
    )
    return Confirm.ask("Allow this tool call?", default=False)


if __name__ == "__main__":
    app()
