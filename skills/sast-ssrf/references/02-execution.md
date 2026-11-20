<!-- Part of the `sast-ssrf` skill. Open with ../SKILL.md for the overview. -->

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find All Outbound Network Call Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where the application makes an outbound network request — HTTP, HTTPS, FTP, TCP, or DNS — regardless of whether that destination is user-controlled. Write results to `sast/ssrf-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, HTTP client libraries in use, and any networking or webhook-related components.
>
> **What to search for — outbound request call sites**:
>
> You are looking for any code that opens a network connection or fetches a remote resource. Flag ANY call where a non-trivially-hardcoded URL, host, or address value is passed as an argument. You are not yet tracing whether that value is user-controlled; that is Phase 2's job.
>
> 1. **Python HTTP clients**:
>    - `requests.get(url)`, `requests.post(url)`, `requests.put(url)`, `requests.request(method, url)`, `requests.Session().get(url)`
>    - `urllib.request.urlopen(url)`, `urllib2.urlopen(url)`
>    - `httpx.get(url)`, `httpx.post(url)`, `httpx.AsyncClient().get(url)`
>    - `aiohttp.ClientSession().get(url)`, `aiohttp.ClientSession().post(url)`
>
> 2. **Python socket / DNS**:
>    - `socket.connect((host, port))`, `socket.create_connection((host, port))`
>    - `dns.resolver.resolve(name)`, `socket.getaddrinfo(host, ...)`
>
> 3. **Python file-fetching with remote schemes**:
>    - `urllib.request.urlopen(url)` where url may be http/https/ftp
>    - `open(url)` via `from urllib.request import urlopen` or similar (flag if url may be remote)
>
> 4. **Node.js / JavaScript HTTP clients**:
>    - `fetch(url)`, `node-fetch(url)`
>    - `axios.get(url)`, `axios.post(url)`, `axios.request({url})`
>    - `http.get(url)`, `https.get(url)`, `http.request(options)`, `https.request(options)`
>    - `got(url)`, `superagent.get(url)`, `needle.get(url)`, `undici.request(url)`
>    - `require('request')(options)`
>
> 5. **Node.js socket / DNS**:
>    - `net.createConnection({host, port})`, `net.connect(port, host)`
>    - `dns.lookup(hostname, ...)`, `dns.resolve(hostname, ...)`, `dns.resolve4(hostname)`
>
> 6. **Ruby HTTP clients**:
>    - `Net::HTTP.get(uri)`, `Net::HTTP.start(host, ...)`, `Net::HTTP.get_response(url)`
>    - `URI.open(url)`, `open(url)` (Kernel#open / OpenURI)
>    - `RestClient.get(url)`, `RestClient::Resource.new(url)`
>    - `Faraday.new(url).get(path)`, `HTTParty.get(url)`
>    - `Typhoeus::Request.new(url)`
>
> 7. **PHP HTTP clients and file functions**:
>    - `curl_setopt($ch, CURLOPT_URL, $url)` followed by `curl_exec($ch)`
>    - `file_get_contents($url)` — flag when `$url` may be an http/https/ftp URL
>    - `fopen($url, 'r')` with a remote URL scheme
>    - `Guzzle`: `$client->request('GET', $url)`, `$client->get($url)`
>    - `Symfony HttpClient`: `$client->request('GET', $url)`
>
> 8. **Java HTTP clients**:
>    - `new URL(url).openConnection()`, `new URL(url).openStream()`
>    - `HttpURLConnection` / `HttpsURLConnection` with a dynamic URL
>    - `OkHttpClient().newCall(new Request.Builder().url(url)...)`
>    - `RestTemplate.getForObject(url, ...)`, `RestTemplate.getForEntity(url, ...)`
>    - `WebClient.get().uri(url)`, `WebClient.create(url)`
>    - `Apache HttpClient`: `httpClient.execute(new HttpGet(url))`
>
> 9. **Go HTTP clients and network dials**:
>    - `http.Get(url)`, `http.Post(url, ...)`, `http.NewRequest("GET", url, ...)`
>    - `net.Dial("tcp", addr)`, `net.DialTCP(...)`, `net.DialTimeout("tcp", addr, ...)`
>    - `net.LookupHost(hostname)`, `net.LookupAddr(addr)`, `net.ResolveIPAddr(...)`
>    - `net.ResolveTCPAddr("tcp", addr)`
>
> 10. **C# / .NET HTTP clients**:
>     - `HttpClient.GetAsync(url)`, `HttpClient.PostAsync(url, ...)`, `HttpClient.SendAsync(request)`
>     - `WebRequest.Create(url)`, `WebClient.DownloadString(url)`, `WebClient.DownloadData(url)`
>     - `HttpWebRequest` with a dynamic URL
>
> 11. **Shell-out to network tools** (via subprocess, exec, system, etc.):
>     - `subprocess.run(["curl", url, ...])`, `subprocess.Popen(["wget", url, ...])`
>     - `os.system("curl " + url)`, `exec("wget " + url)`
>     - Any `curl`, `wget`, `nc`, `ncat`, `nmap` invocation where the target is a variable
>
> **What to skip** (these are safe — do not flag):
> - Calls where the entire URL and hostname are fully hardcoded string literals with no dynamic parts: `requests.get("https://api.example.com/data")`
> - Internal loopback connections to `localhost` or `127.0.0.1` that are clearly part of service-to-service architecture (e.g., connecting to a local queue) — flag these if the address is dynamic
>
> **Output format** — write to `sast/ssrf-recon.md`:
>
> ```markdown
> # SSRF Recon: [Project Name]
>
> ## Summary
> Found [N] outbound network call sites.
>
> ## Outbound Call Sites
>
> ### 1. [Descriptive name — e.g., "HTTP GET in webhook dispatcher"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Call type**: [HTTP GET / HTTP POST / TCP dial / DNS lookup / subprocess curl / etc.]
> - **Library / method**: [requests.get / fetch / http.Get / curl_exec / etc.]
> - **Destination argument**: `var_name` or `url_expression` — [brief note, e.g., "assembled from query param" or "partially hardcoded path with variable host"]
> - **Code snippet**:
>   ```
>   [the outbound call and the lines immediately before it that construct the destination]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/ssrf-recon.md`. If the recon found **zero outbound call sites** (the summary reports "Found 0" or the "Outbound Call Sites" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/ssrf-results.md` and stop:

```markdown
# SSRF Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one outbound call site.

### Phase 2: Verify — Trace User Input to Outbound Call Sites (Batched)

After Phase 1 completes, read `sast/ssrf-recon.md` and split the outbound call sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/ssrf-recon.md` and count the numbered site sections (### 1., ### 2., etc.) under "Outbound Call Sites".
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/ssrf-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Node.js with fetch/axios, include only the "Node.js — fetch / axios" and "Node.js — http.request" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned outbound network call site, determine whether a user-supplied value controls or influences the destination (URL, host, path, port, or scheme). Our goal is to find SSRF vulnerabilities. Write results to `sast/ssrf-batch-[N].md`.
>
> **Your assigned outbound call sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand entry points, middleware, and how data flows through the application.
>
> **SSRF reference — what to look for**:
>
> SSRF occurs when user-controlled input reaches the destination argument of a server-side outbound network call without an effective allowlist on where the server may connect.
>
> **What SSRF is NOT** — do not flag these as SSRF:
> - **Open redirects**: HTTP 302 to a user URL — client-side redirect, not a server-side request
> - **XSS via URL**: User URL rendered in HTML without escaping — XSS
> - **IDOR**: Object ID tampering — separate class
> - **Fully hardcoded outbound URLs** with no user influence — not SSRF
>
> **For each outbound call site, trace the destination argument(s) backwards to their origin**:
>
> 1. **Direct user input** — the destination is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get('url')`, `req.query.url`, `params[:url]`, `$_GET['url']`, `c.Query("url")`
>    - Request body / JSON fields: `request.json['webhook_url']`, `req.body.target`, `params[:source]`
>    - Path parameters: `req.params.host`, `params[:endpoint]`
>    - HTTP headers: `request.headers.get('X-Forwarded-For')`, `req.headers['destination']`
>    - Cookies: `req.cookies.redirect_url`
>
> 2. **Indirect / assembled destination** — the URL is built by concatenating a hardcoded prefix with a user-supplied suffix or path:
>    - `"https://example.com/" + user_path` — may still be exploitable via path traversal or scheme injection depending on the HTTP client
>    - `base_url + user_query` — user controls the query string, potentially injectable
>    - Flag these as Likely Vulnerable and note which portion is user-controlled
>
> 3. **User input stored and later fetched** — the destination was previously saved from user input (e.g., a stored webhook URL) and is now retrieved from the database to make a request:
>    - Find where the stored value was written — was it accepted from user input without allowlist validation at write time?
>    - Was any validation applied at read time before the request?
>
> 4. **Server-side / hardcoded value** — the destination comes from config, an environment variable, a hardcoded constant, or server-side logic with no user influence — this site is NOT exploitable.
>
> **For each call site, also check for mitigations**:
> - **Strict allowlist of hosts/prefixes**: A hardcoded set of permitted hostnames or URL prefixes that the destination is validated against before the request is made — this is an effective mitigation. Mark as Not Vulnerable.
> - **Scheme-only restriction** (e.g., only allow `https://`): Partial mitigation — reduces impact but does not prevent SSRF to arbitrary HTTPS hosts. Still flag as Likely Vulnerable.
> - **Blocklist of private IP ranges / metadata endpoints**: `169.254.169.254`, `10.0.0.0/8`, `192.168.0.0/16`, etc. — **not** sufficient. Bypassable via DNS rebinding, alternate IP representations, and redirect chains. Flag as Likely Vulnerable.
> - **DNS resolution + IP check** (resolve hostname first, then check resolved IP against blocklist): Stronger than a pure blocklist, but still susceptible to DNS rebinding between the check and the request (TOCTOU). Flag as Likely Vulnerable unless the same resolved IP is explicitly pinned for the request.
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the outbound request destination with no effective mitigation (no allowlist or only a blocklist/scheme check).
> - **Likely Vulnerable**: User input probably reaches the destination (indirect flow or partial construction), or only weak mitigation is present (blocklist, scheme-only check, partial URL prefix).
> - **Not Vulnerable**: The destination is fully server-side, OR a strict host/prefix allowlist is enforced before the request.
> - **Needs Manual Review**: Cannot determine the destination's origin with confidence (opaque helpers, complex conditional flows, or external libraries that resolve the URL).
>
> **Output format** — write to `sast/ssrf-batch-[N].md`:
>
> ```markdown
> # SSRF Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP query param `url` flows directly into requests.get()"]
> - **Taint trace**: [Step-by-step from entry point to the call site — e.g., "request.args.get('url') → target_url → requests.get(target_url)"]
> - **Impact**: [What an attacker can do — access cloud metadata at 169.254.169.254, pivot to internal services, port scan the internal network, exfiltrate data, bypass firewalls, etc.]
> - **Mitigation present**: [None / Blocklist only / Scheme check only — explain why it's insufficient]
> - **Remediation**: [Strict host allowlist, or remove user control over destination entirely]
> - **Dynamic Test**:
>   ```
>   [curl command or payload to confirm the finding.
>    Show the parameter, payload, and what to look for.
>    Example: curl "https://app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
>    or for internal pivot: curl "https://app.example.com/fetch?url=http://internal-db:5432/"]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "User controls the path portion of a partially hardcoded URL" or "Stored webhook URL accepted without allowlist at write time"]
> - **Taint trace**: [Best-effort trace with the uncertain or partial-control step identified]
> - **Concern**: [Why it's still a risk — e.g., "Attacker may be able to redirect to an internal host via path traversal" or "Blocklist is bypassable via DNS rebinding"]
> - **Remediation**: [Strict allowlist or remove user control]
> - **Dynamic Test**:
>   ```
>   [payload to attempt — e.g., path traversal or DNS rebinding scenario]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "URL is fully hardcoded" or "Strict host allowlist enforced before request"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the destination's origin could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `resolve_target()` in helpers.py to check where the URL originates"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/ssrf-batch-*.md` file and merge them into a single `sast/ssrf-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/ssrf-batch-1.md`, `sast/ssrf-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (total sites analyzed equals the number from recon / sum of assigned sites).
4. Write the merged report to `sast/ssrf-results.md` using this format:

```markdown
# SSRF Analysis Results: [Project Name]

## Executive Summary
- Outbound call sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/ssrf-results.md`, **delete all intermediate batch files** (`sast/ssrf-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 outbound call sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any call site where the destination argument is dynamic (a variable, expression, or assembled string), regardless of whether user input flows there. Do not attempt to trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each site in its batch, trace the destination argument back to its origin. If it comes from a user-controlled source without an effective allowlist, the site is a real vulnerability.
- **Blocklists are not mitigations**: IP blocklists for private ranges and cloud metadata endpoints are easily bypassed. Always classify such sites as Vulnerable or Likely Vulnerable, not as safe.
- **Partial URL control is still dangerous**: even if the attacker only controls the path or query string portion of the URL, flag it as Likely Vulnerable — depending on the HTTP client behavior, redirect following, and target service, partial control can be enough.
- **Stored destinations are tainted**: if a URL or hostname was accepted from user input at write time and is later used for an outbound request, trace the write-time acceptance. Lack of allowlist validation at write time makes it SSRF.
- **Subprocess curl/wget is SSRF too**: shell-outs that run `curl` or `wget` with a user-supplied URL are just as dangerous as HTTP client calls. Check for these, especially in image-processing, import, or download features.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- DNS rebinding note: for findings where only a DNS-resolution-then-blocklist check is present, note the TOCTOU window explicitly in the finding — this is a known bypass technique.
- Clean up intermediate files: delete `sast/ssrf-recon.md` and all `sast/ssrf-batch-*.md` files after the final `sast/ssrf-results.md` is written.
