from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIProviderConfig(BaseModel):
    """Configuration for a single AI provider."""

    name: str
    type: Literal["openai", "anthropic", "ollama", "lmstudio", "custom"]
    api_key: str | None = None
    base_url: str | None = None
    model: str
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 60
    enabled: bool = True


class SkillConfig(BaseModel):
    """Configuration for a skill."""

    name: str
    enabled: bool = True
    priority: int = 10
    config: dict[str, Any] = Field(default_factory=dict)


class ToolConfig(BaseModel):
    """Configuration for external tools."""

    name: str
    path: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    timeout: int = 300
    auto_install: bool = True


class DatabaseConfig(BaseModel):
    """Database configuration."""

    type: Literal["sqlite", "postgresql"] = "sqlite"
    path: str = "data/agentx.db"
    host: str = "localhost"
    port: int = 5432
    username: str = ""
    password: str = ""
    database: str = "agentx"


class BurpConfig(BaseModel):
    """Burp Suite integration configuration."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 1337
    api_key: str | None = None
    use_https: bool = False


class MCPConfig(BaseModel):
    """Configuration for a single MCP (Model Context Protocol) server."""

    name: str
    transport: Literal["stdio", "http", "sse"] = "stdio"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    auto_approve: bool = False
    enabled: bool = True


class AgentXSettings(BaseSettings):
    """Main AgentX configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # General
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    data_dir: Path = Path("data")
    skills_dir: Path = Path("skills")
    scripts_dir: Path = Path("scripts")
    tools_dir: Path = Path("tools")

    # AI Providers
    ai_providers: list[AIProviderConfig] = Field(default_factory=list)
    orchestrator_model: str = "claude-3-5-sonnet-20241022"
    skill_model: str = "claude-3-haiku-20240307"
    local_model: str = "llama3.1:8b"

    # Skills
    skills: list[SkillConfig] = Field(default_factory=list)
    default_skills: list[str] = Field(
        default_factory=lambda: [
            "web2-recon",
            "offensive-osint",
            "hunt-source-leak",
            "hunt-spa-api",
            "hunt-shadow-api",
            "hunt-xss",
            "hunt-sqli",
            "hunt-ssrf",
            "hunt-idor",
            "hunt-rce",
            "hunt-auth-bypass",
            "hunt-jwt-crypto",
            "hunt-mfa-bypass",
            "hunt-session",
            "hunt-oauth",
            "hunt-graphql",
            "hunt-api-misconfig",
            "hunt-websocket",
            "hunt-business-logic",
            "hunt-race-condition",
            "hunt-cloud-misconfig",
            "hunt-cicd",
            "hunt-access-control",
            "hunt-auth-session",
            "hunt-injection",
            "hunt-client-side",
            "hunt-lfi",
            "hunt-ssrf-xxe",
            "triage-validation",
            "security-arsenal",
            "evidence-hygiene",
            "bb-methodology",
            "bug-bounty",
            # --- imported from pentest-ai-agents (MIT) ---
            "llm-redteam",
            "ai-recon",
            "poc-validator",
            "fix-verifier",
            "report-generator",
            "exploit-chainer",
            "attack-planner",
            "code-auditor",
            "vuln-scanner",
            "database-attacker",
            "credential-tester",
            "crypto-analyzer",
            "supply-chain-auditor",
            "ctf-solver",
            "password-auditor",
            "ad-attacker",
            "privesc-advisor",
            "lateral-movement",
            "c2-operator",
            "container-breakout",
            "persistence-planner",
            "evasion-specialist",
            "data-exfiltrator",
            "payload-crafter",
            "reverse-engineer",
            "network-attacker",
            "wireless-pentester",
            "mobile-pentester",
            "traffic-analyzer",
            "social-engineer",
            "phishing-operator",
            "threat-modeler",
            "engagement-planner",
            "opsec-anonymizer",
            "swarm-orchestrator",
            "exploit-guide",
            "detection-engineer",
        ]
    )

    # Tools
    tools: list[ToolConfig] = Field(default_factory=list)
    local_tools: dict[str, dict[str, Any]] = Field(default_factory=dict)
    tool_timeout: int = 300
    wordlists_dir: Path = Path("data/wordlists")
    payloads_dir: Path = Path("data/payloads")

    # Database
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    # Burp Suite
    burp: BurpConfig = Field(default_factory=BurpConfig)

    # MCP (Model Context Protocol) tools: browser, Burp, etc.
    mcp_servers: list[MCPConfig] = Field(default_factory=list)
    # Tool names (e.g. "browser.navigate") that never require approval
    mcp_auto_approve: list[str] = Field(default_factory=list)
    # Permission gate: ask (approve sensitive tools) | auto | yolo
    permission_mode: Literal["ask", "auto", "yolo"] = "ask"
    # Max plan->act->observe steps in one agent loop turn
    max_agent_steps: int = 20

    # Reporting
    report_templates_dir: Path = Path("agentx/reporting/templates")
    default_report_format: Literal["markdown", "html", "json"] = "markdown"

    # Triage
    auto_triage: bool = True

    # Session
    session_timeout: int = 3600
    max_concurrent_tasks: int = 5

    @field_validator(
        "data_dir",
        "skills_dir",
        "scripts_dir",
        "tools_dir",
        "wordlists_dir",
        "payloads_dir",
        "report_templates_dir",
        mode="before",
    )
    @classmethod
    def resolve_path(cls, v: str | Path) -> Path:
        if isinstance(v, str):
            return Path(v).expanduser().resolve()
        return v.expanduser().resolve()

    def get_enabled_providers(self) -> list[AIProviderConfig]:
        return [p for p in self.ai_providers if p.enabled]

    def get_enabled_skills(self) -> list[SkillConfig]:
        return [s for s in self.skills if s.enabled]

    def get_provider(self, name: str) -> AIProviderConfig | None:
        for p in self.ai_providers:
            if p.name == name:
                return p
        return None

    def get_enabled_mcp_servers(self) -> list[MCPConfig]:
        return [m for m in self.mcp_servers if m.enabled]


# Default configuration instance
settings = AgentXSettings()


def _expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} references from the environment."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_config(config_path: Path | None = None) -> AgentXSettings:
    """Load configuration from a YAML file (expanding ${ENV} references).

    The global ``settings`` object is updated in place so that every module
    that imported it by reference observes the new values.
    """
    if config_path and config_path.exists():
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        new = AgentXSettings(**_expand_env(data))
        for name in AgentXSettings.model_fields:
            setattr(settings, name, getattr(new, name))
    return settings


def save_config(config_path: Path, settings_obj: AgentXSettings | None = None) -> None:
    """Save configuration to YAML file."""
    s = settings_obj or settings
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        yaml.dump(s.model_dump(mode="json"), default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
