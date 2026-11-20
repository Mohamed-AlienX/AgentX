"""AgentX - AI-powered penetration testing and bug bounty agent."""

__version__ = "0.1.0"
__author__ = "AgentX Team"
__description__ = "Unified agent for penetration testing and bug bounty hunting"

from agentx.config import load_config, save_config, settings

__all__ = ["settings", "load_config", "save_config"]
