<p align="center">
  <img src="docs/images/hero.png" alt="AgentX — AI penetration testing agent" width="860">
</p>

# AgentX

**An AI penetration-testing agent. Use it as a set of playbooks inside the agent you already use, or run it standalone with your own API key or a local model.**

`Python 3.11+` · `153 skills` · `MITRE ATT&CK mapped` · `Local findings database` · `Markdown / HTML / JSON reports`

> For **authorized targets only**. Always verify AI-generated results manually before submitting.

---

## What is AgentX, and how does it work?

AgentX turns a target into a structured security assessment. It does not just chat: it discovers attack surface, builds a plan, runs proven playbooks, verifies what it finds, stores every result, and exports a report.

<p align="center">
  <img src="docs/images/workflow.png" alt="Recon to report pipeline" width="860">
</p>

| Stage | What happens | Examples |
|-------|--------------|----------|
| **1. Recon** | Map subdomains, live hosts, endpoints, technologies, and leaked secrets. | `web2-recon`, `offensive-osint`, `hunt-source-leak` |
| **2. Plan** | Rank what to test and produce an ordered, reviewable hunt plan. | `attack-planner`, `threat-modeler`, `bug-bounty` |
| **3. Hunt** | Run vulnerability-specific playbooks and local tools. | `hunt-xss`, `hunt-sqli`, `hunt-idor`, `hunt-ssrf`, ... |
| **4. Validate** | Confirm impact, discard false positives, check evidence hygiene. | `poc-validator`, `triage-validation`, `fix-verifier` |
| **5. Report** | Save findings and export a client- or bounty-ready report. | `report-writing`, `bounty-reporter`, `redteam-report-template` |

You can use the whole loop, or just the skills you need.

---

## Install

```powershell
cd C:\Users\KTS\Documents\agent\AgentX
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows PowerShell — Linux/macOS: source .venv/bin/activate
pip install -e .
agentx --version                    # AgentX v0.1.0
```

If PowerShell blocks activation, run once:
`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

---

## Pick your mode

| | Mode 1 — Skills on your agent | Mode 2 — Standalone agent | Mode 3 — TUI |
|---|---|---|---|
| **Who thinks** | Claude Code / OpenCode / Codex / Gemini / Copilot / Cursor | AgentX itself | AgentX itself, in a full-screen UI |
| **API key needed** | **No** — your existing agent is the LLM | Yes (cloud), or none with Ollama | Yes (cloud), or none with Ollama |
| **Get started** | `agentx install-skills` | `agentx config --init` + enable a provider | `agentx tui --target example.com` |

### Mode 1 — Install the skills into Claude Code, OpenCode, and friends (no API key)

AgentX skills are plain `SKILL.md` playbooks in the open [Agent Skills](https://agentskills.io) format. Your host agent does the reasoning, so **no AgentX key and no extra process** are needed.

```powershell
agentx install-skills --list        # show detected agents and paths
agentx install-skills --dry-run     # preview the copy
agentx install-skills               # install into every agent detected on this machine
```

Known destinations (user scope):

| Key | Agent | Path |
|-----|-------|------|
| `universal` | Codex, Gemini CLI, Copilot, Cursor, OpenCode | `~/.agents/skills` |
| `claude` | Claude Code | `~/.claude/skills` |
| `opencode` | OpenCode | `~/.config/opencode/skills` |
| `gemini` | Gemini CLI | `~/.gemini/skills` |
| `copilot` | GitHub Copilot CLI | `~/.copilot/skills` |
| `cursor` | Cursor | `~/.cursor/skills` |

Useful flags: `--target claude` (repeatable, or a custom path), `--all`, `--project` for repo-scoped copies, `--only hunt-xss,hunt-ssrf` for a subset, and `--keep` to avoid overwriting existing skills. Copies are idempotent and nothing is ever deleted; installing back into the source `skills/` folder is refused.

Afterwards, restart the agent and check its skills list (`/skills` in Claude Code and OpenCode) — it will now route to `hunt-xss`, `sast-sqli`, `osint-methodology`, and the rest.

> No `agentx` entry point? Run `python scripts\install_to_agents.py --all` instead.

### Mode 2 — Run AgentX standalone with an API token (or local Ollama)

Here AgentX is the LLM. Enable **one** provider in `config/default.yaml` (all are disabled by default), then set `orchestrator_model` and `skill_model` to a model that provider actually serves.

| Provider | `type` | `base_url` | Key variable |
|----------|--------|------------|--------------|
| OpenAI | `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| Anthropic | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| Custom endpoint / IP + token | `custom` | your OpenAI-compatible URL, e.g. `http://192.168.1.50:8000/v1` | any `${ENV_VAR}` |
| Ollama (local, no key) | `ollama` | `http://localhost:11434` | *(none)* |
| LM Studio (local, no key) | `lmstudio` | `http://localhost:1234/v1` | *(none)* |

Example — a custom endpoint with a token:

```yaml
ai_providers:
  - name: "my-endpoint"
    type: "custom"                       # OpenAI-compatible API
    api_key: "${MY_API_TOKEN}"
    base_url: "http://192.168.1.50:8000/v1"
    model: "my-model"
    enabled: true

orchestrator_model: "my-model"
skill_model: "my-model"
```

```powershell
setx MY_API_TOKEN "your-token"          # then reopen the terminal
agentx config --show                    # enabled provider count must be > 0
agentx                                  # interactive chat
agentx scan example.com --request "focus on IDOR in the API"
```

With Ollama, just set `type: "ollama"`, `enabled: true`, and leave `api_key` empty. Keys written as `${VAR}` are expanded from the environment — never commit real tokens.

### Mode 3 — Full-screen TUI

```powershell
agentx tui --target example.com
```

Same commands as chat, with a live status panel and a findings table.

| Key | Action |
|-----|--------|
| `F1` | Help |
| `F2` | Findings table |
| `F3` | Skill browser |
| `Ctrl+L` | Clear log |
| `Ctrl+Q` | Quit |

---

## MCP tools: browser + Burp

<p align="center">
  <img src="docs/images/mcp.png" alt="Agent connected to browser and Burp through MCP" width="860">
</p>

With [MCP](https://modelcontextprotocol.io) enabled, AgentX stops being only a text advisor: it **opens pages itself** and **sends raw requests through Burp**, then reads the results in a plan → act → observe loop. Both servers are off by default.

**1. Browser** — Playwright MCP (needs Node.js 20+; downloads on first run via `npx`):

```yaml
mcp_servers:
  - name: "browser"
    transport: "stdio"
    command: "npx"
    args: ["-y", "@playwright/mcp@latest", "--headless"]
    enabled: true
```

Prefer driving your **real Chrome** with its existing logins and extensions? Point the browser MCP at a Chrome-connected bridge such as `browse` instead of headless Playwright.

**2. Burp** — install PortSwigger's **MCP Server** BApp: *Extensions → BApp Store → MCP Server → open its tab → Start server*. It exposes SSE at `http://127.0.0.1:9876`:

```yaml
  - name: "burp"
    transport: "sse"
    url: "http://127.0.0.1:9876"
    enabled: true
```

**3. Permission gate** — with `permission_mode: "ask"` (default), every state-changing call (click, type, send request) asks for approval; reads run automatically.

| `/mode` | Behaviour |
|---------|-----------|
| `ask` | Approve state-changing tools; auto-run reads (default) |
| `auto` | Never prompt — scripted runs |
| `yolo` | Never prompt and skip review of state-changing tools (dangerous) |

Check connections with `/mcp`; pre-approve trusted tools with `auto_approve: true` or `mcp_auto_approve: ["browser.navigate"]`; cap loop length with `max_agent_steps`.

**What this unlocks:** live page snapshots and DOM inspection, authenticated flows using your browser session, raw HTTP replay and proxy-history review in Burp, and faster proof of impact — all with an approval prompt before anything changes state.

---

## What's inside

- **153 skills** — recon, hunting, cloud, AD, mobile, web3, reporting, and process playbooks, auto-discovered from `skills/<name>/SKILL.md`.
- **MITRE ATT&CK** — 140/153 skills mapped to 77 techniques; see [`ATTACK_COVERAGE.md`](ATTACK_COVERAGE.md) and [`mappings/attack-navigator-layer.json`](mappings/attack-navigator-layer.json). Process-only skills are intentionally unmapped.
- **Quality gates** — `agentx-skill-qa all` validates, lints, de-collides, and indexes the skill set; drift fails the check.
- **Findings database** — SQLite at `data/agentx.db`; every finding keeps severity, endpoint, impact, steps, and evidence.
- **Reports** — Markdown, HTML, or JSON via `agentx report --format markdown --output report.md`.
- **Handoff** — `/handoff` prints a context-safe summary (masked secrets, findings by severity, attack chains, next steps).
- **Escalation tools** — `agentx tools --check` / `--install <name>` for `subfinder`, `httpx`, `nuclei`, `ffuf`, `sqlmap`, and more.

---

## Quick reference

```powershell
agentx                              # interactive chat (default)
agentx tui --target example.com     # full-screen TUI
agentx recon example.com            # discovery only
agentx scan example.com -r "focus on IDOR"
agentx report -f markdown -o report.md
agentx skills                       # list skills; "info hunt-xss" for detail
agentx attack T1190                 # MITRE ATT&CK lookup
agentx install-skills --list        # push skills into a host agent
agentx tools --check                # external tool status
agentx config --show                # active configuration
agentx sessions                     # past sessions
```

In-chat commands: `/help` `/target` `/status` `/skills` `/plan` `/go` `/findings` `/validate` `/report` `/recon` `/mcp` `/mode` `/auto` `/sessions` `/handoff` `/clear` `/exit`

| Problem | Fix |
|---------|-----|
| `agentx: command not found` | Activate the venv, or use `python -m agentx` |
| `No AI provider configured` | Set `enabled: true` for one provider; re-run `agentx config --show` |
| `401` / `AuthenticationError` | Check the `${ENV_VAR}` name, reopen the terminal |
| Model silent / wrong answers | Make `orchestrator_model` match the enabled provider's `model` |
| MCP tools not listed | Set `enabled: true`, restart, check `/mcp` (Burp server must be started) |
| Skills missing in Claude Code | Restart the agent; re-run `agentx install-skills --force` |

---

## Disclaimer

Use AgentX only on systems you have **explicit written permission** to test. You are responsible for how it is used, and every AI-generated finding must be verified by a human before action or submission.
