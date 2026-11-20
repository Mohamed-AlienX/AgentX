# PHASE 4: VALIDATE

## The 7-Question Gate (Run BEFORE Writing ANY Report)

All 7 must be YES. Any NO -> STOP.

### Q1: Can I exploit this RIGHT NOW with a real PoC?
Write the exact HTTP request. If you cannot produce a working request -> KILL IT.

### Q2: Does it affect a REAL user who took NO unusual actions?
No "the user would need to..." with 5 preconditions. Victim did nothing special.

### Q3: Is the impact concrete (money, PII, ATO, RCE)?
"Technically possible" is not impact. "I read victim's SSN" is impact.

### Q4: Is this in scope per the program policy?
Check the exact domain/endpoint against the program's scope page.

### Q5: Did I check Hacktivity/changelog for duplicates?
Search the program's disclosed reports and recent changelog entries.

### Q6: Is this NOT on the "always rejected" list?
Check the list below. If it's there and you can't chain it -> KILL IT.

### Q7: Would a triager reading this say "yes, that's a real bug"?
Read your report as if you're a tired triager at 5pm on a Friday. Does it pass?

## 4 Pre-Submission Gates

### Gate 0: Reality Check (30 seconds)
```
[ ] The bug is real -- confirmed with actual HTTP requests, not just code reading
[ ] The bug is in scope -- checked program scope explicitly
[ ] I can reproduce it from scratch (not just once)
[ ] I have evidence (screenshot, response, video)
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] I can answer: "What can an attacker DO that they couldn't before?"
[ ] The answer is more than "see non-sensitive data"
[ ] There's a real victim: another user's data, company's data, financial loss
[ ] I'm not relying on the user doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title
[ ] Searched GitHub issues for target repo
[ ] Read the most recent 5 disclosed reports for this program
[ ] This is not a "known issue" in their changelog or public docs
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: One sentence, contains vuln class + location + impact
[ ] Steps to reproduce: Copy-pasteable HTTP request
[ ] Evidence: Screenshot/video showing actual impact (not just 200 response)
[ ] Severity: Matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
```

## CVSS 3.1 Quick Guide

| Factor | Low (0-3.9) | Medium (4-6.9) | High (7-8.9) | Critical (9-10) |
|--------|-------------|----------------|--------------|-----------------|
| Attack Vector | Physical | Local | Adjacent | Network |
| Privileges | High | Low | None | None |
| User Interaction | Required | Required | None | None |
| Impact | Partial | Partial | High | High (all 3) |

### Typical Scores by Bug Class

| Bug | Typical CVSS | Severity |
|----|------|---------|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass -> admin | 9.8 | Critical |
| Stored XSS | 5.4-8.8 | Med-High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race condition (double spend) | 7.5 | High |
| GraphQL auth bypass | 8.7 | High |
| JWT none algorithm | 9.1 | Critical |

---

# ALWAYS REJECTED -- Never Submit These

Missing CSP/HSTS/security headers, missing SPF/DKIM/DMARC, GraphQL introspection alone, banner/version disclosure without working CVE exploit, clickjacking on non-sensitive pages, tabnabbing, CSV injection, CORS wildcard without credential exfil PoC, logout CSRF, self-XSS, open redirect alone, OAuth client_secret in mobile app, SSRF DNS-ping only, host header injection alone, no rate limit on non-critical forms, session not invalidated on logout, concurrent sessions, internal IP disclosure, mixed content, SSL weak ciphers, missing HttpOnly/Secure cookie flags alone, broken external links, pre-account takeover (usually), autocomplete on password fields.

**N/A hurts your validity ratio. Informative is neutral. Only submit what passes the 7-Question Gate.**

## Conditionally Valid With Chain

These low findings become valid bugs when chained:

| Low Finding | + Chain | = Valid Bug |
|------------|---------|-------------|
| Open redirect | + OAuth code theft | ATO |
| Clickjacking | + sensitive action + PoC | Account action |
| CORS wildcard | + credentialed exfil | Data theft |
| CSRF | + sensitive state change | Account takeover |
| No rate limit | + OTP brute force | ATO |
| SSRF (DNS only) | + internal access proof | Internal network access |
| Host header injection | + password reset poisoning | ATO |
| Self-XSS | + login CSRF | Stored XSS on victim |

---

# PHASE 5: REPORT

## HackerOne Report Template

```
Title: [Vuln Class] in [endpoint/feature] leads to [Impact]

## Summary
[2-3 sentences: what it is, where it is, what attacker can do]

## Steps To Reproduce
1. Log in as attacker (account A)
2. Send request: [paste exact request]
3. Observe: [exact response showing the bug]
4. Confirm: [what the attacker gained]

## Supporting Material
[Screenshot / video of exploitation]
[Burp Suite request/response]

## Impact
An attacker can [specific action] resulting in [specific harm].
[Quantify if possible: "This affects all X users" or "Attacker can access Y data"]

## Severity Assessment
CVSS 3.1 Score: X.X ([Severity label])
Attack Vector: Network | Complexity: Low | Privileges: None | User Interaction: None
```

## Bugcrowd Report Template

```
Title: [Vuln] at [endpoint] -- [Impact in one line]

Bug Type: [IDOR/SSRF/XSS/etc]
Target: [URL or component]
Severity: [P1/P2/P3/P4]

Description:
[Root cause + exact location]

Reproduction:
1. [step]
2. [step]
3. [step]

Impact:
[Concrete business impact]

Fix Suggestion:
[Specific remediation]
```

## Human Tone Rules (Avoid AI-Sounding Writing)
- Start sentences with the impact, not the vulnerability name
- Write like you're explaining to a smart developer, not a textbook
- Use "I" and active voice: "I found that..." not "A vulnerability was discovered..."
- One concrete example beats three abstract sentences
- No em dashes, no "comprehensive/leverage/seamless/ensure"

## Report Title Formula

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**Good titles:**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel -- allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**Bad titles:**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
```

## Impact Statement Formula (First Paragraph)

```
An [attacker with X access level] can [exact action] by [method], resulting in [business harm].
This requires [prerequisites] and leaves [detection/reversibility].
```

## The 60-Second Pre-Submit Checklist

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or response body)
[ ] Two test accounts used (not just one account testing itself)
[ ] CVSS score calculated and included
[ ] Recommended fix is one sentence (not a lecture)
[ ] No typos in the endpoint path or parameter names
[ ] Report is < 600 words (triagers skim long reports)
[ ] Severity claimed matches impact described (don't overclaim)
```

## Severity Escalation Language

When payout is being downgraded, use these counters:

| Program Says | You Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account (no special role)" |
| "Limited impact" | "Affects [N] users / [PII type] / [$ amount]" |
| "Already known" | "Show me the report number -- I searched and found none" |
| "By design" | "Show me the documentation that states this is intended" |
| "Low CVSS score" | "CVSS doesn't account for business impact -- attacker can steal [X]" |

---

# RESOURCES

## Bug Bounty Platforms
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) -- Disclosed reports
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) -- Public findings
- [Intigriti Leaderboard](https://www.intigriti.com/researcher/leaderboard)

## Learning
- [PortSwigger Web Academy](https://portswigger.net/web-security) -- Free vuln labs (best)
- [HackTricks](https://book.hacktricks.xyz) -- Attack technique reference
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) -- Payload reference
- [Solodit](https://solodit.cyfrin.io) -- 50K+ searchable audit findings (Web3)
- [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) -- Free subdomain datasets

## Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) -- Comprehensive wordlists
- [HowToHunt](https://github.com/KathanP19/HowToHunt) -- Step-by-step vuln hunting
- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) -- Default credentials

## Payload Databases
- [XSSHunter](https://xsshunter.trufflesecurity.com/) -- Blind XSS detection
- [interactsh](https://app.interactsh.com) -- OOB callback server

---

# INSTALLATION (Claude Code Skill)

To use this as a Claude Code skill, copy this file to your skills directory:

```bash
# Option A: Clone the repo and link the skill
git clone https://github.com/shuvonsec/claude-bug-bounty.git ~/.claude/skills/bug-bounty
ln -s ~/.claude/skills/bug-bounty/SKILL.md ~/.claude/skills/bug-bounty/SKILL.md

# Option B: Direct copy
mkdir -p ~/.claude/skills/bug-bounty
curl -s https://raw.githubusercontent.com/shuvonsec/claude-bug-bounty/main/SKILL.md \
  -o ~/.claude/skills/bug-bounty/SKILL.md
```

Then in Claude Code, this skill loads automatically when you ask about bug bounty, recon, or vulnerability hunting.

---

## Related Skills & Chains

- **`bug-bounty`** — When the user wants general bug-bounty guidance rather than tool location. Workflow primitive: `bug-bounty` is the orchestrator and routes to topic-matched hunt-* skills; this skill (`bb-local-toolkit`) answers "where is the tool / wordlist / clone on disk for that hunt?"
- **`web2-recon`** — When recon needs to be run via specific tool invocations. Workflow primitive: this skill names the local install path (e.g., `~/tools/SecretFinder/.venv/bin/activate`); `web2-recon` is the pipeline that strings those tool paths together.
- **`offensive-osint`** — When the operational arsenal (probes, regexes, wordlists) needs a tool to execute it. Workflow primitive: `offensive-osint` provides the regex / probe; this skill provides the local trufflehog / jhaddix / SecLists clone that runs it.
- **`security-arsenal`** — When the payload library needs a tool to fire payloads at scale. Workflow primitive: `security-arsenal` is the payload syntax; this skill names the ffuf / dalfox / ghauri install that delivers them.
- **`bb-methodology`** — When Phase 1 (Recon) or Phase 3 (Discovery) needs tooling routed. Workflow primitive: `bb-methodology`'s "Tool Routing by Phase" table is general; this skill resolves the abstract tool names to concrete local paths.
