"""AgentX terminal user interface."""

from __future__ import annotations


def run_tui() -> None:
    """Launch the AgentX full-screen TUI."""
    from agentx.tui.app import AgentXTui

    AgentXTui().run()


__all__ = ["run_tui"]
