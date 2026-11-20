## 26. Anti-Patterns & Common Failure Modes

A non-exhaustive list of mistakes that come up often.

- **Single-source attribution.** Three weak OR one strong + one weak.
- **Trusting vendor labels as ground truth.** Treat labels as hypotheses.
- **Assuming favicon-hash = ownership.** Shared infra, shared CMS templates, shared CDN.
- **Asserting 1:1 bridge flows.** Bridges mint and burn; aggregators rebalance.
- **Treating snippet-only Google dorks as confirmed.** TENTATIVE until you visit.
- **Pasting real PII / creds into cloud LLMs.** Local models for sensitive analysis.
- **Mirror-imaging the threat actor.** They don't think like you.
- **Attribution by IP geolocation.** IPs lie; VPNs and residential proxies exist.
- **Ignoring the 7-day optimistic-rollup challenge window.** L2 finality is delayed.
- **Ignoring CT-log lag.** New certs take minutes-to-hours to surface; absence ≠ doesn't exist.
- **Counting Wayback snapshots as "the site at time T."** Best-effort; many requests fail.
- **Trusting `whoami` from a discovered API.** Could be a honeypot.
- **Letting the asset graph carry untyped strings.** Every discovery is an asset.
- **Skipping the scope check.** Ask once when in doubt.
- **Forgetting UTC.** Local time creates correlation bugs.
- **Continuing to probe after a WAF block.** See §6.4 — back off.
- **Skipping confidence-upgrade documentation.** TENTATIVE assets need a path to CONFIRMED.
- **Treating exec-summary writing as an afterthought.** See §31 — plan deliverables at engagement start, not at the end.

---

## 27. WAF / CDN Bypass & Origin Discovery

Web targets are increasingly behind Cloudflare / Akamai / Fastly / AWS CloudFront. The CDN itself is hard to attack; the **origin server** is often softly defended. Six techniques to find it.

### 27.1 DNS history pivot

The target's domain may have pointed directly at the origin IP **before** the CDN was deployed. Query historical passive DNS:

- **SecurityTrails** — `https://api.securitytrails.com/v1/history/<domain>/dns/a` (paid; the most complete).
- **RiskIQ PassiveTotal** — passive DNS lookups; freemium.
- **DNSDB** (Farsight) — paid; long history.
- **Validin.com** — newer, has free tier.
- **Censys host search** — historical IP-cert mapping.

What to look for: an IP that resolved 1–5 years ago and is **not** in the current CDN's published IP ranges (Cloudflare / Akamai / etc.). Cross-check the IP's current banner — if it serves the same site without the CDN, you've got the origin.

### 27.2 Certificate SAN pivot

Certificates often get re-issued with the same SAN list across origin and CDN. Search CT logs:

- crt.sh `?q=%.<target.com>&exclude=expired` — find certs with the target's domain in SAN.
- Cross-reference issued certs against current CDN-fronted cert. The "extra" cert (not the CDN one) often points to origin via its CN/SAN.
- Tools like `cero` (`go install github.com/glebarez/cero@latest`) crawl IPs and pull certs; correlate IPs whose certs include the target's hostname.

### 27.3 Favicon hash + JARM origin clustering

If the target has a unique favicon, the origin server still serves it (CDNs proxy but don't strip the favicon). Compute the favicon's mmh3 hash and search:

- Shodan: `http.favicon.hash:<mmh3-hash>`.
- Censys: `services.http.response.favicons.hashes:<mmh3-hash>`.

Returned IPs that are **not** in CDN ranges are origin candidates.

JARM (TLS handshake hash) works similarly: compute the target's JARM via `jarm`, search Shodan `ssl.jarm:<jarm-hash>`. Origin servers usually have a different JARM than CDNs.

### 27.4 Direct IP probe with Host header

If you have an origin candidate IP from steps 27.1–27.3:

```bash
curl -sk -H "Host: target.example.com" https://<candidate-IP>/
```

If the response matches the public site (same title, same body fingerprint) — you've found the origin. CDN-only IPs return generic CDN error pages or 403 to wrong Host.

### 27.5 mail.* / ftp.* / cpanel.* exception

Targets often forget to put auxiliary subdomains behind the CDN:

- `mail.<target>` — often points at the actual mail server, sometimes co-located with web origin.
- `ftp.<target>`, `sftp.<target>` — likewise.
- `cpanel.<target>`, `whm.<target>`, `webmail.<target>` — shared hosting controls; same IP as web origin.
- `direct.<target>`, `origin.<target>`, `direct-connect.<target>`, `noproxy.<target>` — ironic admin labels.
- `dev.<target>`, `staging.<target>` — dev environments often skip CDN.

Probe each. If any resolves to a non-CDN IP, that IP often hosts the prod origin too.

### 27.6 Error page / misconfig leakage

When the CDN throws an error (request triggers WAF, origin is down, configuration mismatch), it sometimes leaks the origin IP in the error body:

- Cloudflare 5xx error pages historically included a `cf-ray` and sometimes the underlying upstream details.
- 502/504 from CDN tells you the origin exists but is unreachable from the CDN — useful confirmation it's not just NXDOMAIN.
- `X-Cache: MISS from <origin-host>` headers.
- HTTP response with origin headers leaking through (`X-Powered-By`, `Server`, `X-Backend-Server`).

### 27.7 Email-header bounce trick (for email-server origin)

Send an email to a non-existent address at the target. The bounce often reveals origin mail server IPs in the `Received:` headers — these mail servers are sometimes on the same IP / netblock as the web origin. (Use a sock-puppet email; never your real engagement persona.)

### 27.8 Confidence rules

- Origin IP found via DNS history: **TENTATIVE** until corroborated by direct probe.
- Origin IP corroborated by Host-header probe matching content: **FIRM**.
- Origin IP corroborated by Host-header probe + cert SAN match + favicon match: **CONFIRMED**.

When unsure, document the hypothesis in the asset attrs — don't claim origin discovery without ≥2 corroborating signals.

---

## 28. Vulnerability Prioritization (CVE / EPSS / KEV)

A Nuclei scan can return 100+ CVEs against a target. You can't validate all of them. Prioritize by exploitability.

### 28.1 Data sources (companion skill §29.2 has the URLs)

- **NVD** (National Vulnerability Database) — base CVE catalog, CVSS scores.
- **EPSS** (Exploit Prediction Scoring System) — probability of exploit in the next 30 days, scale 0.0–1.0.
- **CISA KEV** (Known Exploited Vulnerabilities) — vulnerabilities proven exploited in the wild; includes federal-agency due-by dates.
- **ExploitDB** — POC code presence.
- **Metasploit module catalog** — automation availability.
- **InTheWild.io** — community-curated "actively exploited" tracker.
- **OpenCVE** — timeline + watchlist + alerts.
- **Trickest CVE → POC mapping** — community-maintained mapping of CVEs to public POCs.

### 28.2 Prioritization rubric

For each CVE in your list, score:

| Signal | Weight |
|---|---|
| Listed in CISA KEV | **+50** (proven exploited; treat as immediate) |
| EPSS score ≥ 0.7 | **+30** |
| EPSS score 0.3–0.69 | **+15** |
| Public Metasploit module exists | **+25** |
| Public POC on ExploitDB / GitHub | **+15** |
| Vendor-issued advisory + patch | **+10** (means the vuln is real and patchable; not always exploitable) |
| Auth-required vs unauth-required | unauth +20, post-auth +0 |
| Network-vector (network) vs adjacent / local | network +15, adjacent +5, local +0 |
| CVSS v3 base ≥ 9.0 | **+15** |

**Total score → priority tier:**

| Score | Tier | Action |
|---|---|---|
| ≥ 100 | P0 | Immediate validation; surface in engagement summary now. |
| 70–99 | P1 | Validate this engagement; include in technical report. |
| 40–69 | P2 | Mention in technical report; validate if time permits. |
| < 40 | P3 | List in appendix; no validation expected. |

### 28.3 Validation discipline

- **Validate** = run a single read-only proof (e.g., a version banner check, a static-page fetch that confirms the vulnerable component) **without** triggering exploitation.
- **Do NOT** run the actual exploit unless the rules of engagement explicitly permit. Many bug bounty programs forbid PoC execution against production.
- For client engagements: deliver the prioritized list with reproduction commands but defer actual exploitation to a follow-on assessment if needed.

### 28.4 Handle CVE-less findings

Many real-world findings (sourcemap exposure, open GraphQL introspection, public bucket) don't have a CVE. Score them by their independent interest score (companion skill §20 for endpoints; §40 for severity-mapping examples). Don't gate on CVE availability.

---

## 29. Phishing Infrastructure & Pretext Development

Authorized red team engagements often include phishing. The **OSINT side** of phishing — building the phishing-feasibility shortlist and the pretext list — is in scope here. Crafting actual phishing payloads is **out of scope** (operational tradecraft, separate domain).

### 29.1 Phishing-feasibility shortlist

For an authorized engagement, the operator typically wants three lists:

**A. Already-registered typosquats** — these are *findings* (someone is squatting; client should know).

**B. Available-for-registration typosquats** — these are the *operator's phishing-domain shortlist* for the engagement.

**C. Cert-SAN impersonation patterns** — domains the operator could register that would make convincing certs (e.g., `acme-secure.com`, `acme-login.com`, `acme-vpn-portal.com`).

**Generation pattern:**
1. Run dnstwist (or equivalent) on the target's primary domain → get all variations (homoglyph, typosquatting, bit-flip, hyphenation, addition).
2. Check WHOIS for each: registered = list A, unregistered = list B.
3. For list C: combine target stem + plausible service words (`secure`, `login`, `vpn`, `portal`, `mail`, `helpdesk`, `it`, `account`, `verify`, `support`, `password`, `auth`, `sso`).

### 29.2 Subdomain takeover for trusted-domain phishing

If you found a takeover-able subdomain (companion skill §16.12), you can host phishing content **on a subdomain of the actual target**. This bypasses every brand-impersonation defense the user has.

**Procedure:**
1. Confirm takeover signature on the candidate (`<sub>.target.com` CNAMEd to unclaimed `<x>.herokuapp.com`).
2. Register the unclaimed resource (`<x>.herokuapp.com` on Heroku).
3. Now `<sub>.target.com` serves your content.
4. **Stop and consult the engagement lead before going live with phishing content.** Even in authorized engagements, the takeover step itself may need explicit client sign-off.

### 29.3 Email spoof feasibility

Use email security analysis (companion skill §16.14) to determine spoof feasibility:

| SPF policy | DMARC policy | Spoof feasibility |
|---|---|---|
| `~all` (softfail) or absent | `p=none` or absent | **HIGH** — direct spoof of `<anything>@<target>` likely lands. |
| `~all` | `p=quarantine` | MEDIUM — lands in spam folder, but lands. |
| `-all` (hardfail) | `p=quarantine` | LOW — most providers reject; some still deliver to spam. |
| `-all` | `p=reject` | VERY LOW — spoof rejected by major providers. Requires lookalike domain. |

If spoof is hard, fall back to lookalike (list B) or compromised-third-party (different engagement). Document the postural finding regardless.

### 29.4 Pretext development from OSINT

Pretexts work when they tap a target's existing context. Build pretexts from harvested OSINT.

**Pretext sources:**

- **Job titles + reporting structure** (LinkedIn) — "Hi <name>, this is <CFO-name>'s assistant; can you look at this finance file?"
- **Recent corporate events** (press releases, news, careers page) — "We're following up on the layoffs / new acquisition; please confirm your benefits info."
- **Vendor relationships** (job postings mentioning "experience with Workday/Salesforce/etc.") — "Workday password reset required by EOD."
- **Public conferences / travel** (LinkedIn posts, conference pages) — "Hi <name>, we met at <conference last week>; following up on what we discussed."
- **GitHub commits / open-source work** — "I saw your fix in <repo>; want to collaborate on a related PR?"
- **Office locations** (LinkedIn) — "On-site IT for the <city> office requires a quick auth check."

**Per-role pretext templates** (the ones operators use most):

- **End-users (general staff):** IT helpdesk password reset, Workday HR action required, Microsoft 365 storage full, package delivery confirmation.
- **Executives:** finance authority (BEC-style "wire approval needed"), board materials shared, M&A NDA review, executive assistant request.
- **Developers / engineers:** GitHub security alert, CI build failed, package security advisory, conference CFP follow-up.
- **HR / Finance:** payroll vendor change, expense report rejection, benefits enrollment deadline, vendor invoice discrepancy.
- **IT / Security:** vendor security update notification, on-call escalation, monitoring tool alert.

### 29.5 Operational discipline for phishing infrastructure

- All phishing infrastructure must be approved by the engagement lead **before** going live.
- Document every domain registered + every email sent (sender, recipient, subject, timestamp UTC).
- Keep phishing infrastructure isolated from your normal recon infrastructure (different IPs, different personas, different domain registrar accounts).
- Use dedicated payment methods for phishing-domain registration (engagement-specific corporate card; don't use personal).
- Tear down promptly after engagement; transfer/expire all domains; close all hosting accounts.

---

## 30. Bug Bounty Submission & Responsible Disclosure

When you find an issue on a bug-bounty target (HackerOne, Bugcrowd, Intigriti, YesWeHack) or on a non-program target where you choose to disclose responsibly.

### 30.1 Platform-specific basics

| Platform | URL | Notes |
|---|---|---|
| HackerOne | hackerone.com | Largest; strong scope-tracking; CVSS-based reward calc. |
| Bugcrowd | bugcrowd.com | VRT (Vulnerability Rating Taxonomy) instead of CVSS for severity. |
| Intigriti | intigriti.com | EU-strong; flexible scope models. |
| YesWeHack | yeswehack.com | EU-headquartered; growing. |
| HackenProof | hackenproof.com | Crypto/blockchain-focused programs. |
| Open Bug Bounty | openbugbounty.org | Free for sites without official programs (only XSS/SSRF disclosure). |
| security.txt | rfc9116 | Universal: every site should publish `/.well-known/security.txt`. |

### 30.2 Report structure (works on any platform)

```
Title: [Severity] [Affected component] Brief description
   Example: [HIGH] [api.acme.com] Unauthenticated SSRF via /v1/proxy

Summary
   2-3 sentences explaining what was found and why it matters.

Steps to Reproduce
   1. Numbered, copy-pasteable.
   2. Include exact URLs, payloads, expected vs actual response.
   3. Reproduce the issue from a fresh state where possible.

Proof of Concept
   - Screenshot showing the vulnerability triggered.
   - HTTP request/response (sanitize sensitive data; redact other users' data).
   - Or short video/GIF for complex multi-step issues.

Impact
   Quantify: what data is at risk, how many users, what business functions break.
   Tie to the program's impact criteria where defined.

Severity (per program criteria)
   - CVSS v3 vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   - Score: 9.8 (Critical)
   - Justification: <1-2 sentence reasoning>

Remediation
   - Concrete recommendation. "Validate the URL parameter against an allowlist before fetching."
   - If a quick fix: WAF rule, header check.
   - If a structural fix: refactor recommendation.

Affected component
   - URL: https://api.acme.com/v1/proxy
   - Date discovered: 2026-04-27 14:23 UTC
   - Method: HTTP GET / POST / etc.
```

### 30.3 Severity inference per program

- HackerOne uses CVSS v3 with program-specific multipliers (some programs cap at HIGH; some pay 10x for CRITICAL).
- Bugcrowd VRT: P1 (Critical) → P5 (Informational); maps roughly to CRIT/HIGH/MED/LOW/INFO.
- Intigriti uses `Exceptional / Critical / High / Medium / Low` tiers.
- For programs that pay flat rates per severity tier, **don't inflate**. Conservative severity → trust → repeat awards.

### 30.4 Disclosure for unprogrammed targets (CVD)

If the target has no bug bounty program but you found a real vulnerability during authorized testing (e.g., a customer's external assessment surfacing a third-party vendor's bug):

1. Check for `<target>/.well-known/security.txt` — if present, follow its `Contact:` and `Encryption:` (PGP) instructions.
2. If absent, try `security@<target>` then `abuse@<target>`.
3. If those bounce, escalate via the registered abuse contact in WHOIS.
4. CERT/CC (cert.org) and national CERTs (CISA, CERT-EU, JPCERT) for coordination if vendor unresponsive.
5. Standard 90-day disclosure window before public release (Project Zero norm).

### 30.5 Cloud provider / SaaS-specific channels

- AWS abuse: `aws-security@amazon.com`. For exposed AWS keys: also notify the account owner if discoverable via WHOIS/contact.
- GCP: `google-cloud-trust@google.com`.
- Azure: Microsoft Security Response Center (MSRC) at `https://msrc.microsoft.com/`.
- GitHub: secret-scanning auto-revokes most published secrets via GitHub's partner program; if you find one, the scanning is usually faster than manual disclosure but back-up notify GitHub at `security@github.com`.
- npm / PyPI / Docker Hub: each has an `abuse@` or `security@` channel; npm specifically auto-revokes leaked tokens via their secret scanner.

### 30.6 Things to avoid in reports

- Don't include anyone else's PII / passwords / data in the report (redact).
- Don't post the report or PoC publicly until the disclosure window expires.
- Don't escalate via social media first (always direct channel first).
- Don't demand a specific bounty amount; let the program decide.
- Don't submit the same finding to multiple programs (duplicates can hurt your reputation).

---

## 31. Client Deliverable Templates

Operator-facing artifacts (asset graph, JSONL log, finding DB) are not the same as **client-facing artifacts** (exec summary, technical report). Build deliverables intentionally.

### 31.1 Executive summary template

```
ENGAGEMENT: <Client Name>
ASSESSMENT TYPE: External Attack Surface Assessment
ENGAGEMENT WINDOW: <start date> – <end date>
SCOPE: <one-line scope description, e.g., "All internet-facing assets of acme.com and its 3 brand domains">
LEAD: <your name / team>

----- KEY FINDINGS -----

1. [CRITICAL] <One-line title>
   Business impact: <one sentence in business language>
   Estimated remediation effort: <hours / days / weeks>
   Recommended action: <verb + object, e.g., "Rotate the exposed AWS access key and audit CloudTrail">

2. [CRITICAL] <One-line title>
   …

3. [HIGH] <One-line title>
   …

(Top 3-5 findings only; full list in technical report)

----- POSTURAL OBSERVATIONS -----

- Email security (SPF/DMARC): <2-3 sentences on posture, e.g., "DMARC is set to p=none, allowing spoof of <target>.com email; tightening to p=reject would block external spoofing.">
- Identity fabric (SSO): <2-3 sentences>
- Cloud surface (S3/GCS/Azure): <2-3 sentences>
- Mobile attack surface: <2-3 sentences if applicable>

----- AGGREGATE METRICS -----

- Assets discovered: <N> (<breakdown>)
- Findings: <N CRIT, M HIGH, P MED, Q LOW, R INFO>
- Live credentials confirmed: <N>
- Detectability of our operations: <90% low / 8% medium / 2% high>

----- RECOMMENDED NEXT STEPS -----

1. Address P0 findings in next 7 days.
2. Address P1 findings in next 30 days.
3. Schedule re-test for: <date>.
4. Consider follow-on assessments: <if applicable, e.g., authenticated app testing, internal pentest>.
```

### 31.2 Per-finding report card template

Each finding in the technical report uses this card:

```
═══════════════════════════════════════════════════════════
FINDING #<N>: <Title>
SEVERITY: <CRIT / HIGH / MED / LOW / INFO>
CONFIDENCE: <CONFIRMED / FIRM / TENTATIVE>
ASSET: <typed asset key>
DISCOVERED: <UTC timestamp>
═══════════════════════════════════════════════════════════

DESCRIPTION
  <2-5 sentence technical explanation>

EVIDENCE
  - URL: <where it was found>
  - Tool: <how it was discovered>
  - Screenshot: <attachment ref>
  - Raw HTTP: <sanitized capture>
  - Hash (SHA-256): <of any downloaded artifact>

REPRODUCTION
  Step 1: <command or action>
    Expected: <output>
  Step 2: …

IMPACT
  <Business-language impact statement>
  Affected systems: <list>
  Affected user populations: <if applicable>

REMEDIATION
  Immediate (within hours):
    - <action>
  Short-term (within days):
    - <action>
  Long-term (within weeks):
    - <action>

REFERENCES
  - <CVE-ID, advisory URL, OWASP top-10 link, vendor doc>

ATTACK PATH HINT
  <If applicable, the one-sentence hint from companion skill §39>
```

### 31.3 Risk translation matrix

Engineers think in CVSS. Executives think in business outcomes. Translate.

| Technical finding | Business-language impact |
|---|---|
| Listable S3 bucket with PII | "Customer records publicly downloadable. Potential GDPR/CCPA notification trigger if accessed. Estimated cost of disclosure: 30-day notification + credit monitoring + legal review." |
| Exposed `.env` with DB credentials | "Database access to all customer data. Pivots to backups, billing systems, employee PII. If exploited: full data breach scope." |
| Live AWS access key with admin scope | "Full cloud account compromise. Attacker can spin up cryptominers, exfiltrate all data, lateral-move to connected accounts. If exploited: 6-figure cloud bill + complete environment rebuild." |
| Open GraphQL introspection on prod | "API attack surface fully mapped by attackers. Enables more precise follow-on attacks; not directly exploitable but attacker reconnaissance is now zero-effort." |
| Subdomain takeover possible | "Attackers can host content under your trusted domain. Phishing emails from this domain bypass brand-impersonation defenses; users will trust them." |
| Open Firebase Realtime Database | "Mobile app's backend database is publicly readable. All user data, possibly writable. If exploited: full data breach + potential service disruption." |
| Missing HSTS on /login | "Login pages can be downgraded to HTTP via active network attacks. Credentials potentially captured by anyone with network access (coffee shop, conference WiFi)." |
| DMARC `p=none` | "Anyone on the internet can send email appearing to be from your domain. Phishing campaigns become trivially convincing for both customers and employees." |
| ≥10 employees in breach corpus | "Stolen credentials for your staff are circulating; attackers can attempt these against your SSO. Even if SSO has MFA, password reuse against other services puts those at risk." |
| `android:debuggable=true` | "Mobile app can be reverse-engineered and modified by anyone. Trust boundary between app and server is undermined; backend assumes app integrity that doesn't exist." |
| Vendor product (Citrix/F5/Pulse) version with KEV CVE | "Network appliance has a known-exploited vulnerability. Attackers are actively scanning the internet for this exact issue. Patch immediately." |

### 31.4 Reporting cadence for engagements > 1 day

- **Day 1 EOD** — short kickoff confirmation: "Stage 1 complete. Identified <N> assets so far. Initial posture: <one paragraph>."
- **Mid-engagement check-in** — when you find your first CRITICAL OR at the 50% time mark, whichever first. Heads-up to engagement lead: "Found <CRIT description>; recommend you alert <client contact> now to begin remediation prep."
- **End-of-engagement preliminary** — same day as last probe: top 5 findings + plan for full report delivery within X business days.
- **Final report** — formal deliverable; both exec summary + technical report.
- **Re-test offer** — proactive: "We're available for a re-test in <window>; recommend re-testing CRITICAL/HIGH findings after remediation."

### 31.5 Reproduction package contents

Deliver alongside the report:

```
<engagement-id>-reproduction-package.zip
├── README.md                    # how to use the package
├── engagement-metadata.json     # client, dates, scope, lead
├── tools-used.txt               # tool name + version, one per line
├── run-log.jsonl                # every event during engagement
├── assets.db                    # SQLite of all discovered assets
├── findings.db                  # SQLite of all findings
├── evidence/
│   ├── screenshots/             # PNG, named by finding-id
│   ├── http/                    # raw HTTP captures (sanitized)
│   ├── downloads/               # any binary artifacts (with .sha256 alongside)
│   └── code/                    # any extracted source (sanitized)
├── re-test-script.sh            # reruns probes for the CRIT/HIGH findings
└── disclosure/                  # if applicable: bounty submissions, vendor notifications
```

The package is the source of truth — the report is the human-readable view. Anyone with the package can reproduce the engagement and verify findings.

---

## 32. Skill Self-Test

Drop these prompts into a fresh Claude session to verify the skill loads and behaves correctly. Pass criteria: expected sections referenced, no hallucinated content, scope-check invoked when needed.

1. *"I'm doing external recon on acme.com (in-scope bug bounty). Where do I start?"* → §0, §1, §7, §7.5, §11.
2. *"How do I tell if a target uses Entra, Okta, or ADFS without active probing?"* → §11.2-11.4 + companion skill §22.
3. *"What should I look for when I scrape JS bundles?"* → §13.
4. *"What's the workflow for finding and analyzing a target's Android apps?"* → §14.
5. *"How do I generate good cloud bucket candidates without spamming the entire internet?"* → §15.
6. *"We've harvested 200 emails for the target and confirmed the org uses Entra. Highest-ROI next step?"* → §22.
7. *"I found a live AWS access key in a public GitHub repo. Should I check if it works?"* → §6.3 + companion skill §23.2.
8. *"Our team just acquired a 4GB stealer-log dump. How do we handle it?"* → §22.4.
9. *"I found three indicators that look like APT28 — does that confirm it?"* → §20.2 + §2.
10. *"Investigating a Russian cybercrime actor. What corporate/people pivots?"* → §20.3.
11. *"How do I link a `.cn` domain to its operating company?"* → §20.4 + companion skill §14.2.
12. *"List the most common mistakes red teamers make during external recon."* → §26.
13. *"Run a full subdomain enum on chase.com."* → §1 (scope check; should NOT run).
14. *"My subdomain marked TENTATIVE — how to upgrade?"* → §2.1.
15. *"How long should a 1-week recon engagement take across the 5 stages?"* → §7.6.
16. *"50 subdomains, 12 webapps, 4 IPs, 23 emails — triage order?"* → §8.5 + §7.5.
17. *"Probing a 50-employee SaaS company with M365 + GitHub + AWS. Where to focus?"* → §10.1 + §11.10 + §22.
18. *"Target is fully behind Cloudflare. How do I find the origin?"* → §27.
19. *"100 CVEs from a Nuclei scan. How do I prioritize?"* → §28.
20. *"My probes are getting 429s and a Cloudflare interstitial. What now?"* → §6.4.
21. *"Authorized engagement asks for phishing-feasibility shortlist. Walk me through it."* → §29.
22. *"Found unauth POST endpoint on a HackerOne target. Write me the report."* → §30.2.
23. *"Write the executive summary for an engagement that found 2 CRIT, 5 HIGH, 12 MED."* → §31.1 + §31.3.

---

## 33. Changelog

- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-test smoke-test gap analysis. Added: confidence upgrade workflows (§2.1), detection-aware probing (§6.4), time budgeting & engagement profiles (§7.6), asset-level triage rules (§8.5), scale-based tactics (§10.1), Microsoft 365 deep surface (§11.10), WAF/CDN bypass & origin discovery (§27), vulnerability prioritization (§28), phishing infrastructure & pretext development (§29), bug bounty submission & responsible disclosure (§30), client deliverable templates (§31). Self-Test section refreshed with v2.1 prompts.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture. Added: 5-stage pipeline, asset-graph discipline, findings rubric, bug-bounty pivot modes, identity-fabric mapping, API & auth-map methodology, JS deep analysis, mobile attack surface, cloud attack surface, breach × identity correlation, detectability tagging, validator discipline, cross-module coordination, multi-engine corpus run, evidence preservation, anti-patterns. Original methodology content (OpSec, Crypto, Image/Video/Chrono, Threat Actor inc. RU/CN, Synthetic Media) retained.
- **v1.x** — original OSINT methodology framework based on SnailSploit/offensive-checklist.

---

## Related Skills & Chains

- **`offensive-osint`** — When the methodology needs to be executed with concrete probes. Workflow primitive: this skill is the planning skeleton (5-stage pipeline, asset graph, findings rubric); `offensive-osint` is the operational arsenal that fills each stage with curl one-liners, wordlists, and regexes.
- **`web2-recon`** — When asset discovery moves from planning to running. Workflow primitive: after this skill's §7 pipeline is scoped, `web2-recon` runs the subfinder → dnsx → httpx → katana commands and produces the URL set.
- **`hunt-subdomain`** — When the asset graph surfaces stale CNAMEs. Workflow primitive: §8 Asset Graph entries with CNAME pointing to S3 / GitHub Pages / Heroku / Shopify / Azure auto-route to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When the asset graph surfaces exposed buckets / actuators / Firebase. Workflow primitive: §15 Cloud Attack Surface findings (open S3, /actuator/env, /firebaseio.com/.json) hand off to `hunt-cloud-misconfig` for exploitation.
- **`bb-methodology`** — When the engagement mode is bug-bounty rather than pure recon. Workflow primitive: this skill's §10 bug-bounty pivot modes are the bridge; once mode is confirmed, `bb-methodology` PART 0 + 5-phase workflow takes over.
