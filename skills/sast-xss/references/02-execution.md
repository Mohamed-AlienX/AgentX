<!-- Part of the `sast-xss` skill. Open with ../SKILL.md for the overview. -->

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find XSS Sink Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where data is rendered into HTML, JavaScript, or the DOM in a way that could allow script injection — any unescaped or explicitly-marked-safe output, any dangerous DOM property assignment, any JavaScript execution sink. Write results to `sast/xss-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the frontend stack, template engines, server-side rendering frameworks, and any client-side JavaScript patterns.
>
> **What to search for — vulnerable sink patterns**:
>
> Flag ANY dynamic variable passed to a dangerous output sink. You are not yet checking whether the variable is user-controlled — that is Phase 2's job.
>
> **1. Server-side template unescaped output**:
>    - Jinja2/Django: `{{ var | safe }}`, `{% autoescape off %}`, `Markup(var)`, `mark_safe(var)`, `format_html(...)` with direct user-controlled format args
>    - EJS: `<%- var %>`
>    - Handlebars/Mustache: `{{{ var }}}`
>    - Pug: `!{var}`
>    - Thymeleaf: `th:utext="${var}"`, `[(${var})]`
>    - Twig: `{{ var | raw }}`
>    - Blade (Laravel): `{!! $var !!}`
>    - Rails ERB: `raw(var)`, `var.html_safe`, `<%= raw var %>`
>    - PHP: `echo $var`, `print $var`, `<?= $var ?>` without `htmlspecialchars()`
>    - Go: `template.HTML(var)`, `template.JS(var)`, `template.URL(var)`, usage of `text/template` for HTML output
>    - C#/Razor: `@Html.Raw(var)`, `MvcHtmlString.Create(var)`
>
> **2. Direct HTML string construction in server-side code**:
>    - String concatenation or interpolation building an HTML response: `res.send("<p>" + var + "</p>")`, `f"<h1>{var}</h1>"`, `"<div>" + var + "</div>"`
>    - `render_template_string(f"...{var}...")` in Flask
>
> **3. Client-side DOM sinks**:
>    - `element.innerHTML = var`
>    - `element.outerHTML = var`
>    - `document.write(var)`, `document.writeln(var)`
>    - `element.insertAdjacentHTML(position, var)`
>    - jQuery: `$(el).html(var)`, `$(el).append(var)`, `$('<tag>' + var + '</tag>')`, `$.parseHTML(var)` passed to DOM
>    - React: `dangerouslySetInnerHTML={{ __html: var }}`
>    - Angular: `[innerHTML]="var"`, `bypassSecurityTrustHtml(var)`, `bypassSecurityTrustScript(var)`, `bypassSecurityTrustUrl(var)`, `bypassSecurityTrustStyle(var)`, `bypassSecurityTrustResourceUrl(var)`
>    - Vue: `v-html="var"`
>
> **4. JavaScript execution sinks**:
>    - `eval(var)`
>    - `setTimeout(var, ...)` / `setInterval(var, ...)` where `var` is a string variable (not a function reference)
>    - `new Function(var)()`
>    - `scriptElement.text = var`, `scriptElement.textContent = var`
>    - `element.setAttribute('onclick', var)`, `element.setAttribute('href', 'javascript:' + var)`, and similar event-handler attribute assignments
>    - URL-based sinks where `javascript:` URIs could execute: `location.href = var`, `location.replace(var)`, `element.src = var`, `element.action = var`
>
> **5. DOM-based XSS patterns** — client-side code reading from attacker-controlled sources and passing to any sink above:
>    - Reading from: `location.search`, `location.hash`, `location.href`, `document.referrer`, `document.URL`, `document.cookie`, `window.name`, `postMessage` handler (`event.data`), `URLSearchParams`
>    - Then passing to an HTML or JS sink without escaping
>
> **What to skip** (these are safe output patterns — do not flag):
> - Auto-escaped template output: `{{ var }}` in Jinja2 (auto-escape on), `<%= var %>` in EJS, `{{ var }}` in Handlebars double-brace, `@var` in Razor, `th:text` in Thymeleaf
> - `element.textContent = var` and `element.innerText = var` — no HTML parsing, safe
> - React JSX `{var}` — auto-escaped
> - Angular `{{ var }}` interpolation — auto-escaped
> - Vue `{{ var }}` interpolation — auto-escaped
> - `DOMPurify.sanitize(var)` wrapping an innerHTML assignment — typically safe (verify config)
> - `sanitize-html`, `xss`, or similar allowlist sanitizer library wrapping output
>
> **Output format** — write to `sast/xss-recon.md`:
>
> ```markdown
> # XSS Recon: [Project Name]
>
> ## Summary
> Found [N] locations where data is rendered into HTML/JS/DOM without guaranteed escaping.
>
> ## Sink Sites
>
> ### 1. [Descriptive name — e.g., "innerHTML assignment in search results handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint / component**: [function name, route, or component]
> - **Sink type**: [server-side template / HTML string concat / DOM innerHTML / eval / JS execution sink / DOM-based source-to-sink]
> - **Sink call**: [the exact API or property used — e.g., `innerHTML`, `mark_safe()`, `<%- %>`]
> - **Interpolated variable(s)**: `var_name` — [brief note, e.g., "unknown origin" or "looks like user profile field"]
> - **XSS type**: [Reflected / Stored / DOM-based — best guess at this stage]
> - **Code snippet**:
>   ```
>   [the vulnerable sink code]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/xss-recon.md`. If the recon found **zero sink sites** (the summary reports "Found 0" or the "Sink Sites" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/xss-results.md` and stop (you may delete `sast/xss-recon.md` after writing):

```markdown
# XSS Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one sink site.

### Phase 2: Verify — Trace User Input to Sinks (Batched)

After Phase 1 completes, read `sast/xss-recon.md` and split the sink sites into **batches of up to 3 sink sites each**. Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sinks and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/xss-recon.md` and count the numbered sink sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sinks → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those sink sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sinks.
5. Each subagent writes to `sast/xss-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses React with an Express API, include the relevant Node.js and React examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned XSS sink site, determine whether a user-supplied value reaches the output variable. Write results to `sast/xss-batch-[N].md`.
>
> **Your assigned sink sites** (from the recon phase):
>
> [Paste the full text of the assigned sink sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, data flows, middleware, and client-side data sources.
>
> **For each sink site, trace the interpolated variable(s) backwards to their origin**:
>
> **User-controlled sources to look for:**
>
> 1. **HTTP request sources** (server-side):
>    - Query parameters: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`, `r.URL.Query().Get("x")`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`, `$_GET['id']`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `request.form.get(...)`, `$_POST['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`, `$_SERVER['HTTP_X_CUSTOM']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`, `$_COOKIE['x']`
>    - File upload filenames or content: `request.files['x'].filename`
>
> 2. **Attacker-controlled DOM sources** (client-side / DOM-based XSS):
>    - `location.search`, `location.hash`, `location.href`, `document.referrer`, `document.URL`
>    - `window.name`, `document.cookie`
>    - `postMessage` event: `window.addEventListener('message', (e) => { ... e.data ... })`
>    - `URLSearchParams` values derived from `location.search`
>    - `localStorage` / `sessionStorage` values written from URL or postMessage
>
> 3. **Stored (second-order) input** — the variable is read from persistent storage (database, file, cache), but the stored value originally came from user input:
>    - Find the write path: where was this field stored? Was it user-supplied at write time?
>    - Was any escaping or sanitization applied at write time? (Note: HTML-escaping at write time is fragile — it may be double-encoded or stripped elsewhere)
>    - Stored XSS is still a vulnerability even if it was validated or stored safely; track whether the read-back path escapes before rendering
>
> 4. **Server-side / hardcoded value** — the variable comes from config, environment, a hardcoded constant, or server-side logic with no user influence — this site is NOT exploitable.
>
> **For each sink site, also check for mitigations that would prevent exploitation**:
> - Is the output explicitly escaped with a safe function just before the sink? (`htmlspecialchars()`, `escapeHtml()`, `h()`, `fn:escapeXml()`)
> - Is a sanitization library applied with a strict allowlist config? (`DOMPurify.sanitize(input)` — check if the config strips scripts)
> - Is the HTTP response `Content-Type` set to `application/json` or `text/plain` (no HTML rendering)?
> - Is a Content Security Policy header present that blocks inline scripts? (CSP reduces impact but is not a full fix)
> - Is there a WAF or input validation that strictly allowlists the expected format (e.g., a numeric ID)?
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the sink with no effective escaping or sanitization.
> - **Likely Vulnerable**: User input probably reaches the sink (indirect/stored flow) or only weak mitigation is present (CSP-only, WAF-only, partial sanitization, incomplete allowlist).
> - **Not Vulnerable**: The variable is server-side only with no user influence, OR proper context-aware escaping is applied immediately before the sink.
> - **Needs Manual Review**: Cannot determine the variable's origin with confidence (opaque helpers, complex conditional flows, external libraries, or cross-service data flows).
>
> **Output format** — write to `sast/xss-batch-[N].md`:
>
> ```markdown
> # XSS Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / component**: [route, function, or component name]
> - **XSS type**: [Reflected / Stored / DOM-based]
> - **Issue**: [e.g., "HTTP query param `q` flows directly into innerHTML without escaping"]
> - **Taint trace**: [Step-by-step from source to sink — e.g., "req.query.q → query → `<h1>${query}</h1>` → res.send()"]
> - **Impact**: [What an attacker can do — session hijacking, credential theft, keylogging, defacement, redirects to malicious sites, etc.]
> - **Remediation**: [Specific fix — escape with the correct function, switch to textContent, use auto-escaping template syntax, apply DOMPurify]
> - **Dynamic Test**:
>   ```
>   [curl command or browser payload to confirm the finding.
>    Show the exact parameter, payload, and what to observe.
>    Example: curl "https://app.example.com/search?q=<script>alert(1)</script>"
>    Or: Visit https://app.example.com/#<img src=x onerror=alert(1)> and observe alert box]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / component**: [route, function, or component name]
> - **XSS type**: [Reflected / Stored / DOM-based]
> - **Issue**: [e.g., "Stored user bio likely rendered via innerHTML; write path confirmed from user input"]
> - **Taint trace**: [Best-effort trace, with uncertain steps identified]
> - **Concern**: [Why it's still a risk — e.g., "Sanitization library present but configured to allow script-capable tags"]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [payload to attempt]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / component**: [route, function, or component name]
> - **Reason**: [e.g., "Output wrapped in htmlspecialchars() before echo" or "Variable is a hardcoded server constant"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / component**: [route, function, or component name]
> - **Uncertainty**: [Why the variable's origin or escaping status could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `buildProfileHtml()` in utils.js to check where its return value originates"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/xss-batch-*.md` file and merge them into a single `sast/xss-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/xss-batch-1.md`, `sast/xss-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (total sink sites analyzed equals the number from recon; counts per classification sum across batches).
4. Write the merged report to `sast/xss-results.md` using this format:

```markdown
# XSS Analysis Results: [Project Name]

## Executive Summary
- Sink sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/xss-results.md`, **delete all intermediate batch files** (`sast/xss-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sink sites per subagent**. If there are 1-3 sinks total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sinks' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any dynamic variable passed to an HTML/JS/DOM sink, regardless of origin. Do not attempt to trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each sink found in Phase 1, trace the variable back to its origin. If it comes from a user-controlled source with no effective escaping, the site is a real vulnerability.
- Context matters: the same variable may be safe in one output context (HTML body with escaping) and dangerous in another (JavaScript string literal, URL attribute, or event handler attribute). Check the exact rendering context.
- Custom sanitization (homegrown regex stripping, blacklisting `<script>`, etc.) is **not** sufficient — flag as Likely Vulnerable. Only DOMPurify with a strict config or equivalent allowlist library is acceptable.
- Stored XSS is easy to miss: trace the write path to confirm the field is user-supplied, then separately verify the read/render path lacks escaping. Both legs must be true for the vulnerability to be exploitable.
- DOM-based XSS lives entirely in client-side JavaScript: look for `location.*`, `document.referrer`, `event.data`, and other attacker-controlled properties flowing into DOM sinks without passing through the server.
- CSP headers reduce XSS exploitability but are **not** a fix — still flag the underlying injection point.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Angular's `DomSanitizer.bypassSecurityTrust*` methods are always suspicious — flag them whenever the argument is not a hardcoded constant.
- For JavaScript execution sinks (`eval`, `setTimeout` with string arg), even seemingly innocuous data (error messages, IDs) can be dangerous if an attacker can influence them.
- Clean up intermediate files: delete `sast/xss-recon.md` and all `sast/xss-batch-*.md` files after the final `sast/xss-results.md` is written.
