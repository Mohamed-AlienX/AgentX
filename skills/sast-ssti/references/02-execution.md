<!-- Part of the `sast-ssti` skill. Open with ../SKILL.md for the overview. -->

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find Template Rendering Sites Using Dynamic Strings

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a template engine renders, compiles, or evaluates a **dynamically built string** as the template itself — rather than loading a static template file. Write results to `sast/ssti-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, template engines in use, and how views/responses are rendered.
>
> **What to search for — vulnerable template rendering patterns**:
>
> Flag any call where the first argument (the template string) is a variable, a concatenated string, or any non-literal value. You are not yet checking whether that variable comes from user input — that is Phase 2's job.
>
> 1. **Python — Jinja2 / Flask**:
>    - `render_template_string(var)` — any non-literal argument
>    - `Environment().from_string(var)` or `env.from_string(var)`
>    - `jinja2.Template(var).render(...)`
>    - `Template(var)` where Template is imported from jinja2
>
> 2. **Python — Mako**:
>    - `Template(var).render(...)` where Template is from `mako.template`
>    - `mako.template.Template(var)`
>
> 3. **Node.js — EJS**:
>    - `ejs.render(var, ...)` or `ejs.renderFile(var, ...)` where var is not a static string literal
>
> 4. **Node.js — Nunjucks**:
>    - `nunjucks.renderString(var, ...)` — any non-literal first argument
>    - `env.renderString(var, ...)`
>
> 5. **Node.js — Handlebars**:
>    - `Handlebars.compile(var)` — any non-literal argument
>    - `Handlebars.precompile(var)`
>
> 6. **Node.js — Pug/Jade**:
>    - `pug.render(var, ...)` — any non-literal argument
>    - `pug.compile(var, ...)`
>
> 7. **Node.js — Lodash/Underscore**:
>    - `_.template(var)` — any non-literal argument
>    - `Handlebars.compile(var)`
>
> 8. **Node.js — Swig / Twig.js**:
>    - `swig.render(var, ...)`
>    - `twig({ data: var })`
>
> 9. **Ruby — ERB**:
>    - `ERB.new(var).result(...)` — any non-literal argument
>    - `ERB.new(var).result_with_hash(...)`
>
> 10. **Ruby — Liquid**:
>     - `Liquid::Template.parse(var).render(...)` — any non-literal argument
>
> 11. **Java — FreeMarker**:
>     - `new Template(name, new StringReader(var), cfg)` — var is not a literal
>     - `cfg.getTemplate(var)` where var is not a literal (potential template path injection)
>
> 12. **Java — Velocity**:
>     - `Velocity.evaluate(ctx, writer, logTag, var)` — any non-literal fourth argument
>     - `ve.evaluate(ctx, writer, logTag, var)`
>
> 13. **Java — StringTemplate / ST4**:
>     - `new ST(var)` — any non-literal argument
>     - `new STGroup(var, ...)` with non-literal path
>
> 14. **Java — Thymeleaf**:
>     - Controller methods returning a view name built by string concatenation: `return "user/" + var + "/page"` or `return String.format("prefix/%s/suffix", var)`
>     - `templateEngine.process(var, ctx)` with non-literal var
>
> 15. **PHP — Twig**:
>     - `$twig->createTemplate($var)->render(...)` — any non-literal argument
>     - `$environment->createTemplate($var)`
>
> 16. **PHP — Smarty**:
>     - `$smarty->fetch("string:" . $var)` or `$smarty->display("string:" . $var)`
>     - `$smarty->fetch($var)` where var may contain a "string:" prefix
>
> 17. **PHP — Blade / Laravel**:
>     - `Blade::render($var, ...)` — any non-literal argument
>     - `\Illuminate\Support\Facades\View::make($var, ...)` with non-literal name (template path injection)
>
> 18. **Go — text/template or html/template**:
>     - `template.New(name).Parse(var)` — any non-literal argument to Parse
>     - `t.Parse(var)` on any template variable
>     - `t.ParseFiles(var)` with non-literal var (template path injection)
>
> 19. **C# — Scriban / Handlebars.Net / DotLiquid / Fluid**:
>     - `Template.Parse(var)` (Scriban) — non-literal
>     - `Handlebars.Compile(var)` — non-literal
>     - `DotLiquid.Template.Parse(var)` — non-literal
>     - `FluidParser.TryParse(var, ...)` — non-literal
>
> **What to skip** (safe patterns — do not flag):
> - Calls where the first argument is a **string literal**: `render_template_string("<h1>Hello</h1>")`, `ejs.render("<p>static</p>", ctx)`
> - Calls where a file path is loaded from a trusted constant and user input only appears in context: `render_template("profile.html", user=user_obj)`
> - Template engine configuration calls that do not render user-supplied content: `env = Environment(loader=FileSystemLoader("templates/"))`
>
> **Output format** — write to `sast/ssti-recon.md`:
>
> ```markdown
> # SSTI Recon: [Project Name]
>
> ## Summary
> Found [N] locations where a template engine renders a dynamic (non-literal) string as the template.
>
> ## Candidate Rendering Sites
>
> ### 1. [Descriptive name — e.g., "render_template_string in /greet endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Template engine**: [Jinja2 / EJS / Handlebars / FreeMarker / Twig / ERB / etc.]
> - **Rendering call**: [render_template_string / from_string / ejs.render / Handlebars.compile / etc.]
> - **Dynamic argument**: `var_name` — [brief note on what it appears to represent, e.g., "looks like it comes from a form field" or "unknown origin"]
> - **Code snippet**:
>   ```
>   [the rendering call with the dynamic argument]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/ssti-recon.md`. If the recon found **zero candidate rendering sites** (the summary reports "Found 0" or the "Candidate Rendering Sites" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/ssti-results.md` and stop:

```markdown
# SSTI Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate rendering site.

### Phase 2: Verify — Trace User Input (Batched)

After Phase 1 completes, read `sast/ssti-recon.md` and split the candidate rendering sites into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent traces taint for only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/ssti-recon.md` and count the numbered candidate sections under "Candidate Rendering Sites" (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/ssti-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Python/Flask with Jinja2, include only the "Python — Flask / Jinja2" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate rendering site, determine whether a user-supplied value reaches the dynamic template string argument. Our goal is to find SSTI vulnerabilities.Write results to `sast/ssti-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, and how data flows through the application.
>
> **SSTI reference — what to trace**:
>
> For each rendering site, trace the **dynamic template argument** backwards to its origin.
>
> 1. **Direct user input** — the argument is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`
>    - File upload content: if a file's content is read and passed as the template string
>
> 2. **Indirect user input** — the argument is derived from user input through transformations, function calls, or intermediate assignments. Trace the full chain:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - Variable read from a class attribute or shared state set elsewhere → find the setter
>    - Variable conditionally assigned — check all branches
>
> 3. **Second-order input** — the template string is read from the database, a config store, or a file, but the stored value originally came from user input (e.g., user-submitted "custom email template" feature):
>    - Find where this value was written — was it stored from a user-supplied field?
>    - Was it sanitized before storage? Note: sanitizing SSTI payloads is unreliable — still flag.
>
> 4. **Server-side / hardcoded value** — the template string comes from a file loaded at startup, a hardcoded constant, or server-side logic with no user influence — this site is NOT exploitable.
>
> **Template engine risk level**:
> - **Critical**: Jinja2, Mako, Twig, Smarty, FreeMarker, Velocity, ERB, Pug, EJS, Go `text/template`, Thymeleaf — full code execution possible
> - **High**: Handlebars (with prototype pollution gadgets), Nunjucks, Lodash `_.template`, Blade, Razor
> - **Medium / Logic-less**: Mustache, Liquid (without dangerous tags enabled) — arbitrary code execution not typically possible, but still check for data leakage
>
> **Mitigations to check**:
> - Is the template engine running in a sandboxed mode? (e.g., Jinja2 `SandboxedEnvironment`, Twig `sandbox` extension with strict policy)
> - Is the input validated or filtered before being used as a template? Note: blocklist-based filtering of template syntax characters (`{`, `}`, `%`) is **not** a reliable mitigation — attackers can often bypass it.
> - Is the result of rendering passed directly to the response, or is it used in a non-dangerous context?
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the template string argument with no effective mitigation, using a critical/high-risk engine.
> - **Likely Vulnerable**: User input probably reaches the template string (indirect flow or second-order), or a medium-risk engine is used, or only blocklist filtering is applied.
> - **Not Vulnerable**: The template string is server-side only (file, constant, hardcoded), OR a properly configured sandbox is confirmed in place.
> - **Needs Manual Review**: Cannot determine the argument's origin with confidence, or a logic-less engine is used and data leakage scope is unclear.
>
> **Output format** — write to `sast/ssti-batch-[N].md`:
>
> ```markdown
> # SSTI Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Template engine**: [Jinja2 / FreeMarker / Twig / ERB / etc.] (severity: Critical/High)
> - **Issue**: [e.g., "HTTP query param `tmpl` flows directly into render_template_string()"]
> - **Taint trace**: [Step-by-step from entry point to the rendering call — e.g., "request.args.get('tmpl') → tmpl → render_template_string(tmpl)"]
> - **Impact**: Remote code execution — attacker can execute arbitrary OS commands, read files, exfiltrate secrets, or pivot internally.
> - **Proof-of-concept payload**:
>   ```
>   [Template syntax payload appropriate for the engine.
>    Example for Jinja2: ?tmpl={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
>    Example for FreeMarker: ?tmpl=<#assign+ex="freemarker.template.utility.Execute"?new()>${ex("id")}
>    Example for Twig: ?tmpl={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
>    Example for ERB: ?tmpl=<%= `id` %>
>    Example for EJS: ?tmpl=<%- global.process.mainModule.require('child_process').execSync('id') %>]
>   ```
> - **Remediation**: Never use user input as a template string. Pass user data as context variables to a static template. If dynamic templates are a product requirement, use a sandboxed logic-less engine (e.g., Mustache, Liquid with safe config) and enforce strict input validation.
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Template engine**: [engine name] (severity: High/Medium)
> - **Issue**: [e.g., "Template string likely sourced from user input via helper function" or "Second-order: user-submitted template stored in DB then evaluated server-side"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Concern**: [Why it's still a risk — e.g., "Second-order SSTI: user can craft payload at submission time that executes when the template is rendered later"]
> - **Proof-of-concept payload**:
>   ```
>   [payload for the engine]
>   ```
> - **Remediation**: [Specific fix]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Template string is loaded from a hardcoded file path" or "Jinja2 SandboxedEnvironment confirmed in use with restricted globals"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the argument's origin could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `get_custom_template()` in services/email.py to check where its return value originates"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/ssti-batch-*.md` file and merge them into a single `sast/ssti-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/ssti-batch-1.md`, `sast/ssti-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/ssti-results.md` using this format:

```markdown
# SSTI Analysis Results: [Project Name]

## Executive Summary
- Rendering sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/ssti-results.md`, **delete all intermediate batch files** (`sast/ssti-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any dynamic (non-literal) variable used as the template string argument. Do not attempt to trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each site assigned to a batch, trace the dynamic template argument back to its origin. If it comes from a user-controlled source, the site is a real vulnerability.
- The critical distinction is **template string vs. template context**: user input passed as a *variable name/value* inside `render_template("page.html", user=input)` is safe. User input passed as the *template string itself* to `render_template_string(input)` is dangerous.
- **Second-order SSTI is easy to miss**: a "custom template" feature may let users store Jinja2/Twig syntax in the database. When that stored template is later loaded and rendered server-side without sandboxing, it's SSTI. In Phase 2, treat DB-read template strings as potentially tainted.
- **Thymeleaf fragment expressions**: in Spring Boot, if a controller returns a view name constructed from user input (e.g., `return "user/" + lang + "/view"`), Thymeleaf may process Spring EL expressions embedded in the path segment, enabling RCE. Flag any controller that builds a view name string using user-supplied values.
- **Blocklist filtering is not a mitigation**: attempts to strip `{{`, `}}`, `<%`, `%>` etc. from user input are routinely bypassed via encoding, alternate syntax, or nested expressions. Do not classify a finding as "Not Vulnerable" solely because filtering is present.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Include engine-appropriate proof-of-concept payloads for all Vulnerable and Likely Vulnerable findings. Payloads should first test with a math expression (e.g., `{{7*7}}`) to confirm template execution before escalating to RCE payloads.
- Clean up intermediate files: delete `sast/ssti-recon.md` and all `sast/ssti-batch-*.md` files after the final `sast/ssti-results.md` is written.
