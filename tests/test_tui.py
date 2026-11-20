"""Smoke tests for the Textual TUI."""

from __future__ import annotations

from agentx.tui.app import AgentXTui


async def test_tui_mounts() -> None:
    app = AgentXTui()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        assert app.query_one("#chat")
        assert app.query_one("#prompt")
        assert app.query_one("#findings")
        assert app.query_one("#status")


async def test_tui_help_command() -> None:
    app = AgentXTui()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        prompt = app.query_one("#prompt")
        prompt.value = "/help"
        await pilot.press("enter")
        await pilot.pause()
        log = app.query_one("#chat")
        assert len(log.lines) > 0


async def test_tui_target_command() -> None:
    from agentx.core.session import session_manager

    app = AgentXTui()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        prompt = app.query_one("#prompt")
        prompt.value = "/target example.com"
        await pilot.press("enter")
        await pilot.pause()
        session = session_manager.get_session()
        assert session is not None
        assert session.target == "example.com"
