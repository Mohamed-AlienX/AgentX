---
name: sast-ssrf
description: >-
  Find SSRF in source: outbound HTTP, webhook, image-fetch and URL-preview sinks fed by
  user input, plus missing destination allowlists, redirect following and reachable cloud
  metadata endpoints. Use when asked about server-side request forgery. Do not use for
  browser-side open redirects - use hunt-open-redirect.
mitre_attack: [T1190, T1090]
---

# Server-Side Request Forgery (SSRF) Detection

You are performing a focused security assessment to find SSRF vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find all places that make outbound TCP, DNS, or HTTP requests), **batched verify** (trace whether user-supplied input reaches those call sites, in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is SSRF

SSRF occurs when an attacker can cause the server to make outbound network requests to an arbitrary destination — including internal services, cloud metadata endpoints, or other external targets — by supplying or influencing the URL, hostname, IP, or port used in a server-side request.

The core pattern: *unvalidated, user-controlled input reaches the destination argument of an outbound network call.*

### What SSRF IS

- HTTP client calls where the URL or host is built from user input: `requests.get(user_url)`
- Fetching a resource whose location is provided by the client: `fetch(req.body.webhook_url)`
- DNS lookups on a hostname supplied by the user: `dns.lookup(req.query.host)`
- Raw TCP connections to a host/port derived from user input: `socket.connect((user_host, user_port))`
- File-fetching functions used with HTTP/FTP URLs from user input: `file_get_contents($user_url)`
- URL redirectors that forward to a user-supplied destination without validation
- Webhooks, import-from-URL, screenshot services, PDF renderers, image proxies — any feature that fetches a remote resource on behalf of the user

### What SSRF is NOT

Do not flag these:

- **Open redirects**: Redirecting the browser (HTTP 302) to a user-supplied URL — that's a client-side redirect, not a server-side request
- **XSS via URL**: Rendering a user-supplied URL in an `<a>` tag without escaping — that's XSS
- **IDOR**: Accessing another user's data by changing an object ID — separate vulnerability class
- **Hardcoded outbound calls**: HTTP requests to fixed, fully hardcoded URLs with no user influence — not SSRF

### Patterns That Prevent SSRF

When you see these patterns, the code is likely **not vulnerable**:

**1. Strict allowlist of permitted destinations**
```python
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Destination not allowed")
requests.get(user_url)
```

**2. Allowlist of permitted URL prefixes / schemes**
```python
ALLOWED_PREFIXES = ["https://api.example.com/", "https://cdn.example.com/"]
if not any(user_url.startswith(p) for p in ALLOWED_PREFIXES):
    abort(400)
requests.get(user_url)
```

**3. No user influence on the destination**
```python
# Destination fully hardcoded — no user input involved
response = requests.get("https://api.thirdparty.com/data")
```

> **Note**: IP blocklists (blocking 169.254.0.0/16, 10.0.0.0/8, etc.) are **not** sufficient protection — they can be bypassed via DNS rebinding, URL encoding, IPv6 notation, decimal IP representation, or redirect chains. Do not treat a blocklist as making a site safe; classify it as Likely Vulnerable.

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
