## 7. External Red-Team Recon Pipeline

A 5-stage pipeline for any authorized external assessment. Stages are sequential; modules within a stage can run concurrently.

### Stage 1 — Seed Discovery
Establish the ground truth of who/what the target is.

- WHOIS on the seed domain (registrant, dates, name servers).
- ASN enumeration: which AS does the org own/use? (Hurricane Electric BGP Toolkit, RIPEstat, BGPView.)
- DNS records (A/AAAA/MX/TXT/NS/SOA/CAA) — records-only, no walking yet.
- Certificate Transparency history for the root domain (crt.sh, Censys).

### Stage 2 — Asset Expansion
Discover everything that might belong to the target.

- Subdomain enumeration (passive sources first: crt.sh, VirusTotal, AlienVault OTX, Shodan, then permutations and bruteforce).
- Cloud bucket enumeration (S3/GCS/Azure permutations from company name + subdomain stems — see §15).
- Typosquat domain generation (dnstwist variants → resolve → WHOIS) — for both phishing risk and adjacent corp assets.
- Wayback CDX archive endpoints for forgotten paths.
- Mobile app discovery (Android via google-play-scraper, iOS via iTunes Search API — see §14).
- DNS deep walking (NSEC walk on misconfigured zones, AXFR opportunism).
- LinkedIn employee enumeration → email-pattern derivation.

### Stage 3 — Enrichment
Add depth to the discovered assets.

- Port + service detection (Shodan InternetDB free → naabu/masscan if authorized).
- Live TLS handshakes (cert chain, JARM, favicon mmh3 hash).
- Web tech detection (Wappalyzer-style ~600 signatures via httpx).
- WAF/CDN inference (header markers).
- Origin discovery if behind CDN (see §27).
- Security header audit.
- Bulk screenshots (triage 1000s of hosts visually).
- Email harvesting (6 parallel sources).
- Email security audit (SPF/DMARC/DKIM/BIMI/MTA-STS).
- GitHub code-search dorking (13 dork templates × 29+ secret regexes).
- JavaScript deep analysis (sourcemaps, secrets, endpoints, internal-host leakage).
- SSO/IdP tenant fingerprinting (Entra, Okta, ADFS, Google, SAML, M365 Teams/SharePoint/OAuth — see §11).
- API & auth-map discovery (Swagger/OpenAPI, GraphQL, Postman).
- Secrets-beyond-GitHub sweep (Postman public workspaces, Stack Exchange, Trello/Notion/Atlassian dorks).
- Vendor product fingerprinting (Citrix/F5/PaloAlto/Pulse/Fortinet/Cisco/VMware/Exchange).
- Container / CI-CD / cloud-native exposure check.
- Job posting harvest for tech-stack inference.

### Stage 4 — Exposure Analysis
Convert assets into findings.

- Nuclei (15 always-on built-in checks + optional binary).
- TLS deep audit (sslyze / testssl.sh).
- Breach × identity correlation (HudsonRock Cavalier, HIBP, DeHashed, IntelX, local corpus → SSO_EXPOSURE findings).
- Targeted misconfiguration probes (`.git/config`, `.env`, `phpinfo.php`, `/actuator/env`, `/actuator/heapdump`, `_cat/indices`, `/console`, `/manager/html`).
- Vulnerability prioritization (CVE × EPSS × CISA KEV × public-POC availability — see §28).

### Stage 5 — Reporting
Make the work usable.

- Risk scoring per finding (CVSS + program-specific weights).
- Asset graph export (D3-friendly nodes/links, GraphML, JSON).
- Client-facing report (executive summary + technical detail + remediation — see §31).
- Reproduction package (run_id, tool versions, raw evidence, JSONL log).
- Bug bounty submission (if applicable — see §30).

### 7.5 Pipeline Priority Order (highest signal density first)

When budget is constrained, work in this order:

1. **Breaches** — infostealer logs (HudsonRock Cavalier free tier) + HIBP + DeHashed. Highest ROI for red teams; often gives valid plaintext creds for corp SSO. Requires emails as input.
2. **GitHub recon** — code-search dorks. Finds AWS keys, Slack tokens, JWT secrets, `.env` files. Fastest path to cloud pivot.
3. **Nuclei misconfig sweep** — exposed admin panels, CVEs with public POCs.
4. **Cloud buckets** — permutate company name + subdomain stems. Listable bucket = CRITICAL.
5. **Ports** — Shodan InternetDB first (free, keyless). VPN concentrators, RDP, Jenkins, GitLab-CE, Elasticsearch are the high-value pivot points.
6. **Email OSINT** — feeds breaches; feeds phishing list.
7. **Web tech / WAF / screenshots** — triage thousands of hosts; know the stack before probing.
8. **Wayback** — archived JS often has hard-coded keys; archived endpoints reveal removed admin/dev paths.
9. **DNS deep + email security** — SPF/DMARC gaps enable email spoofing; TXT verification tokens reveal SaaS tenancies.
10. **Certificates** — CT-log timeline catches forgotten subdomains; weak ciphers = cheap findings.
11. **ASN + reverse DNS** — corporate IP space hosts unadvertised infra.
12. **WHOIS** — registrant PII reveals adjacent corp assets.
13. **Typosquat** — actively-registered squats are findings; unregistered ones go on the phishing-domain shortlist.
14. **Security headers** — low standalone value but required for client reports.

### 7.6 Time Budgeting & Engagement Profiles

Stage and asset count drive how long a recon takes. Rough estimates (single operator on a typical SaaS-style target):

| Stage | Small org (<100 employees) | Medium (100–1K) | Large (1K+) |
|---|---|---|---|
| 1. Seed discovery | 30 min | 30 min | 30 min |
| 2. Asset expansion | 1–2 h | 2–4 h | 4–8 h |
| 3. Enrichment (per 100 alive webapps) | ~1 h | ~1 h | ~1 h |
| 4. Exposure analysis | 1–3 h | 3–6 h | 6–12 h |
| 5. Reporting | 2–4 h | 4–8 h | 1–2 days |

**Engagement profiles:**

- **1-hour rapid recon ("how exposed is X?")** — Stage 1 (15 min) → passive subdomain (crt.sh + Subfinder, 10 min) → Shodan InternetDB on resolved IPs (5 min) → email harvest via Hunter+IntelX (10 min) → breach lookup on emails (10 min) → executive-summary-only output (10 min).
- **4-hour focused recon ("phish-readiness check")** — adds: full email harvest, LinkedIn employee enum, SPF/DMARC analysis, typosquat candidate generation, SSO/IdP fingerprinting. Output: phishing-feasibility report + target email list.
- **1-day standard recon** — full Stages 1–4 with the priority order above. Output: per-asset finding list + asset graph + exec summary.
- **1-week deep recon** — all of standard, plus: deep-mode user enumeration, JS deep analysis at full budget, mobile attack surface, cloud-native fingerprinting, vendor product fingerprinting, package registry leak hunting, vulnerability prioritization. Output: full client deliverable package + reproduction bundle.
- **Ongoing monitoring (weekly diff)** — re-run Stages 1–3 weekly; diff against baseline; alert on new asset / new finding / asset disappeared.

**When to abort early:**
- After Stage 1 if scope is wrong (target turns out to be subsidiary of unrelated corp; rules of engagement need clarification).
- After Stage 2 if attack surface is below threshold (no public webapps + no exposed services + no leaked emails → little to find externally).
- During any stage if you hit the WAF / detection signs in §6.4.

---

## 8. Asset Graph Discipline

Treat every discovery as a typed asset in a graph, not a free-floating string.

### 8.1 Asset Taxonomy (29 types)

| Category | Asset Types |
|---|---|
| **DNS / Network** | `domain`, `subdomain`, `ip`, `netblock`, `asn` |
| **Service** | `port`, `service`, `certificate` |
| **Identity** | `email`, `person`, `credential` |
| **Code / Config** | `repo`, `secret` |
| **Cloud / Storage** | `bucket`, `firebase_project` |
| **Web** | `webapp`, `wayback_endpoint`, `api_endpoint`, `api_spec`, `graphql_schema` |
| **Mobile** | `mobile_app`, `deep_link`, `exported_component` |
| **Phishing / Adversarial** | `typosquat_domain` |
| **Collaboration / SaaS** | `postman_collection`, `postman_workspace`, `postman_api_key`, `stack_post`, `saas_public_surface` |

### 8.2 Asset Schema

Every asset carries:
- `type` — one of the 29 above.
- `key` — unique dedup id (typed prefix, e.g. `sub:api.example.com`, `email:alice@example.com`).
- `value` — the actual string/object.
- `sources[]` — every source that confirmed this asset (deduplicated).
- `confidence` — TENTATIVE / FIRM / CONFIRMED.
- `first_seen`, `last_seen` — UTC timestamps.
- `attrs{}` — type-specific metadata (e.g., for a `webapp`: status_code, title, tech-stack list, JARM, favicon mmh3, screenshot path).

### 8.3 Edge Taxonomy

Relationships are typed edges, not text:
`RESOLVES_TO`, `HOSTED_ON`, `IN_NETBLOCK`, `BELONGS_TO_ASN`, `LISTED_IN_CERT`, `OWNED_BY`, `ALIAS_OF`, `BREACHED_FROM`, `EMPLOYED_BY`, `HOSTS_REPO`, `TYPOSQUAT_OF`, `EXPOSES`, `DOCUMENTED_BY`, `BELONGS_TO_HOST`, `REQUIRES_AUTH`, `LEAKS_SCHEMA`, `SHIPPED_BY_ORG`, `CONTAINS_SECRET`, `TALKS_TO_HOST`, `EXPOSES_DEEPLINK`, `HAS_EXPORTED_COMPONENT`, `USES_FIREBASE_PROJECT`, `LACKS_PINNING_FOR`.

### 8.4 Discipline rules

- **Every discovery is an asset.** Don't write findings against free-floating strings; create the asset first, then attach the finding.
- **Dedup by key, not by value.** Same value, different type ≠ same asset (`sub:api.example.com` and `webapp:https://api.example.com/` are different assets with a `BELONGS_TO_HOST` edge).
- **Provenance is non-negotiable.** `sources[]` must list every source. If two sources confirmed it, both go in.
- **Confidence is per-source, then aggregated.** A subdomain returned by 3 passive sources is FIRM; one returned by snippet-only Bing is TENTATIVE.
- **Late binding via sidecars.** When module A produces output that module B needs, write a JSON sidecar (`mobile_endpoints.json`, `secrets_sidecar.json`) — don't block module B on module A. See §24.

### 8.5 Asset-Level Triage Rules

When you have a mixed bag of assets and limited probe budget, prioritize by what each asset *enables*:

**WebApp priority by hostname signal (highest first):**

1. Auth-related hostnames (`auth.`, `login.`, `sso.`, `idp.`, `accounts.`, `oauth.`).
2. Admin paths (`/admin`, `/dashboard`, `/console`, `/manager`, `/wp-admin`, `/phpmyadmin`).
3. Dev/staging hosts (`dev.`, `staging.`, `stg.`, `qa.`, `uat.`, `test.`, `sandbox.`, `preprod.`, `preview.`) — lower defenses, often dump prod data.
4. API hostnames (`api.`, `services.`, `gateway.`, `graph.`).
5. Customer-facing hostnames (`portal.`, `app.`, `my.`, `account.`).
6. Marketing / content (`www.`, `blog.`, `news.`, `careers.`, `support.`).

**Subdomain priority by inferred function:**

- API > Admin > Dev > Auth > Prod-app > Marketing.

**IP priority by netblock:**

- Corporate ASN-owned (most likely to host unadvertised internal infra).
- Cloud netblocks (AWS / GCP / Azure / DO / OVH) — high turnover but interesting for cloud-native services.
- CDN ranges (Cloudflare / Akamai / Fastly) — usually edge, not origin; defer unless doing origin discovery.

**Email priority by role hint:**

| Role indicator | Priority | Why |
|---|---|---|
| `ceo@`, `cfo@`, `cto@`, `ciso@` | HIGHEST | Exec accounts have highest breach value (BEC, finance authority, board access). |
| `it@`, `helpdesk@`, `support@`, `security@` | HIGH | IT/security accounts have privileged tool access; helpdesk accounts handle reset workflows. |
| `dev`, `engineer`, `architect`, `dba` | MEDIUM | Developer accounts often have GitHub / cloud / CI access. |
| `sales`, `marketing`, `hr`, `finance` | MEDIUM | SaaS access (Salesforce, HubSpot, Workday); finance enables BEC. |
| Generic role accounts (`info@`, `noreply@`, `contact@`) | LOW | Often unmonitored or alias forwarded; less personal context. |

**Repo priority by recency + naming:**

- Recently-pushed (last 30 days) > stale.
- Public repo with target name in description > target name only in code.
- Forked from internal-looking parent > standalone.
- Mentions `prod`, `internal`, `private`, `secret` in name → priority HIGH despite being public (may be misnamed or accidentally exposed).

**Application order:** when you have N assets and budget for M probes (M < N), apply asset-type priority first, then within-type priority. E.g.: 50 subdomains → probe API + admin + dev first (~15), then auth + prod-app (~20), defer marketing/content to a later pass.

---

## 9. Findings Rubric & Severity Mapping

Severity is operational, not subjective. Use these anchors:

### 9.1 CRITICAL

Pre-auth code execution, confirmed valid credentials, listable production data, fundamental trust violations.

Examples:
- `.git/config` exposed on production webapp (full source-code disclosure).
- `/.env` exposed (credentials in plaintext, often DB / cloud / API).
- Spring Boot `/actuator/env` or `/actuator/heapdump` reachable unauthenticated.
- Listable S3 / GCS / Azure bucket containing user data.
- Unauthenticated POST/PUT/DELETE to a write endpoint that mutates state.
- Open Firebase Realtime Database (`https://{project}.firebaseio.com/.json` returns data).
- `android:debuggable=true` in a production Android app.
- Live-validated credential (PMAK, AWS key, Anthropic/OpenAI key) with broad scope.
- ≥10 employees compromised in a breach corpus + their tenant identified (SSO_EXPOSURE).
- Open Elasticsearch cluster (`/_cat/indices` returns data).
- Open Docker API (`/v1.40/containers/json` returns containers).
- Open Redis (no AUTH; can write `authorized_keys`).
- Open Kubernetes API server with anonymous-auth enabled.
- Open kubelet on 10250 (pod exec without auth).
- Open etcd on 2379 (cluster state and secrets).
- BlueKeep-vulnerable RDP, EternalBlue-vulnerable SMB.
- Citrix Netscaler / F5 BIG-IP with version-specific RCE CVE.

### 9.2 HIGH

Significant exposure but not yet RCE; clear path to escalation; high-value information disclosure.

Examples:
- Public secret in a GitHub repo (PAT, AWS key, Slack token, etc.).
- Sourcemap (`.js.map`) accessible — full original-source disclosure of frontend.
- Open GraphQL introspection on production (full schema leaked → mutations to enum).
- Subdomain takeover possible (CNAME points to unclaimed Heroku/Shopify/etc.).
- Reflected CORS with credentials (`Access-Control-Allow-Origin: <reflected>` + `Access-Control-Allow-Credentials: true`).
- Verb tampering: hidden DELETE/PATCH on an endpoint that publicly only allows GET.
- Missing HSTS on a sensitive path (`/login`, `/sso`, `/admin`, `/auth`) — escalated from MED.
- Exposed Jenkins/Tomcat-Manager/phpMyAdmin admin UI (no auth or default creds).
- Telnet (port 23) reachable.
- WebView with JS bridge in a mobile app (XSS → RCE potential).
- Sensitive deep-link handler in a mobile app.
- DMARC policy `p=none` on production sending domain (spoof-feasible).
- Vendor product banner with known unpatched CVE (KEV-listed).

### 9.3 MEDIUM

Information disclosure, hardening gaps, brute-force exposure.

Examples:
- Missing security headers on standard pages: HSTS, CSP.
- Apache `/server-status` or `/server-info` reachable.
- `phpinfo()` or `/info.php` reachable on dev/staging only.
- Internal IP / hostname / K8s service DNS leaked in JS.
- Schema leakage in error pages (stack traces, ORM signatures).
- `android:allowBackup=true` in Android app.
- `android:usesCleartextTraffic=true` in Android app.
- Exported activity/service without `android:permission` protection.
- Missing rate-limit on an API endpoint.
- Wildcard CORS (`Access-Control-Allow-Origin: *`) on an API that returns user-tied data (no creds).
- Slack webhook URL leaked.
- Twilio Account SID leaked (without auth token).
- SPF record permissive (`+all` or many includes).

### 9.4 LOW

Cosmetic or marginal hardening gaps.

Examples:
- Missing `X-Frame-Options`.
- Missing `X-Content-Type-Options`.
- `.DS_Store` exposed.
- Stripe **test** key leaked.
- Firebase URL exposed (URL only, no open RTDB).
- Certificate pinning missing in mobile app.
- Outdated WordPress install detected (no known exploit yet).
- BIMI not configured (brand impersonation risk only).

### 9.5 INFO

Worth recording, no action required immediately.

Examples:
- Missing `Referrer-Policy` / `Permissions-Policy`.
- Discovered `/.well-known/security.txt`.
- `robots.txt` reveals interesting paths.
- Private bucket exists but is locked down.
- Domain detected in a breach corpus with 0 employee accounts.
- DNSSEC not enabled.

### 9.6 Severity escalation rules

- HSTS missing on auth/login/SSO/admin path → **MED → HIGH**.
- Wildcard CORS + credentials → **MED → HIGH**.
- Wildcard CORS + sensitive endpoint → **LOW → MED**.
- API endpoint with score ≥70 on the interest rubric (companion skill §20) → at least **HIGH**.
- Domain breach severity ≥10 employees → **CRITICAL** regardless of stale-data caveats.
- Vendor product version matches CISA KEV entry → **CRITICAL**.
- DMARC `p=reject` + SPF strict + DKIM rotated → no escalation; well-postured.

---

## 10. Bug-Bounty / Red-Team Pivot Modes

Existing investigative work (threat-actor research, doxxing investigations, attribution) operates under different posture than offensive recon. Switch posture explicitly.

| Aspect | Investigative Mode | Offensive Recon Mode |
|---|---|---|
| **Probing rate** | Slow, single-threaded, blend with normal traffic. | Bursts, parallel, but rate-limited per provider. |
| **OpSec posture** | Sock-puppet only, never reveal investigator. | Persona may be the engagement persona; team may notify SOC. |
| **Evidence handling** | Court-grade chain of custody; hashes, timestamps, screenshots. | Engagement-grade; same hashing/timestamp discipline but evidence is for the client report. |
| **Severity in scope** | All severity levels relevant for context. | CRIT/HIGH/MED matter; LOW/INFO often dropped from exec summary. |
| **Authorization posture** | Public-record / OSINT-only; no probing private resources without authorization. | Written rules of engagement; explicit scope; explicit out-of-scope list. |
| **Reporting format** | Narrative + sourced timeline. | Per-asset findings + remediation + reproduction steps. |
| **Stop conditions** | When the question is answered. | When the engagement window closes OR when the report is delivered. |

When you're working with the user, ask which mode they're in if it's unclear from context.

### 10.1 Scale-Based Tactics

Org size shapes which techniques pay off.

**Small org (< 100 employees):**
- Executive accounts disproportionately matter; one CEO/CFO compromise often hands you the keys.
- Email harvest is small enough to enumerate exhaustively (10–50 emails total).
- Likely Microsoft 365 or Google Workspace; identity fabric is one tenant.
- Code repos often public on GitHub under personal accounts (founders moved from solo dev).
- Cloud presence often single-account AWS or GCP project.
- Tactics: deep on every email + every identity-fabric finding; full LinkedIn enum; check founders' personal GitHub orgs.

**Medium org (100–1K):**
- Balanced enumeration. Email list is enumerable but not exhaustive.
- Identity fabric likely one IdP but with multiple SaaS tenants (Slack workspace, Notion org, GitHub org).
- Mobile apps possible; check both stores.
- Cloud presence multi-account or multi-region.
- Tactics: full pipeline at standard depth; sample-and-deepen on each asset class; LinkedIn priority by role.

**Large org (1K–10K):**
- Email enum becomes lossy (sample top roles); breach hits scale up.
- Multi-tenant identity fabric (often Entra + Okta + multiple Auth0 customers).
- Mobile apps, multiple Android packages from different teams.
- Cloud presence sprawling; subsidiaries / acquisitions complicate scope.
- Tactics: breadth-first; rely on automation for asset discovery; manual triage on findings.

**Very large org (10K+) or conglomerate:**
- Brand-pivot maps before anything else: enumerate every brand domain, every subsidiary.
- Breach corpus dominates: 10K+ employees mean significant past-breach exposure.
- Identity fabric may differ per business unit (legal entity boundaries).
- Tactics: scope pruning is the most important step; sampling + automation throughout; deep dive only on high-priority findings.

**Cross-scale principle:** the smaller the org, the more individual-account focus pays off. The larger the org, the more systemic posture findings (DMARC gaps, SSO_EXPOSURE breadth, vendor-product version sweeps) pay off.

---

