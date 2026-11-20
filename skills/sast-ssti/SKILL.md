---
name: sast-ssti
description: >-
  Find server-side template injection in source: user input concatenated into Jinja2,
  Twig, Freemarker, Velocity, ERB, Handlebars or Thymeleaf templates, or passed as the
  template body instead of a bound variable. Use when asked about template injection. Do
  not use for client-side DOM XSS - use sast-xss.
mitre_attack: [T1190, T1059]
---

# Server-Side Template Injection (SSTI) Detection

You are performing a focused security assessment to find Server-Side Template Injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find candidate rendering sites where the template string is dynamic), **batched verify** (trace whether user input reaches each site's template argument, in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is SSTI

Server-Side Template Injection occurs when user-supplied input is embedded directly into a template string that is then evaluated by a template engine. Unlike passing user data as *context variables* to a static template, SSTI means the user can write template syntax that the engine will execute — leading to arbitrary code execution, file read, or full server compromise.

The core pattern: *unvalidated user input is used as the template string passed to a template engine's render/compile/evaluate function.*

### What SSTI IS

- Passing user input as the template string to be compiled or rendered:
  - `Template(user_input).render()` — Jinja2
  - `env.from_string(user_input).render()` — Jinja2
  - `render_template_string(user_input)` — Flask
  - `ejs.render(user_input, ctx)` — EJS (Node.js)
  - `nunjucks.renderString(user_input, ctx)` — Nunjucks
  - `Handlebars.compile(user_input)(ctx)` — Handlebars
  - `pug.render(user_input, ctx)` — Pug/Jade
  - `_.template(user_input)(ctx)` — Lodash/Underscore
  - `Velocity.evaluate(ctx, user_input)` — Apache Velocity (Java)
  - `new Template("anon", new StringReader(user_input), cfg).process(...)` — FreeMarker (Java)
  - `new ST(user_input).render()` — StringTemplate4 (Java)
  - `thymeleafEngine.process(user_input, ctx)` — Thymeleaf (Java)
  - `\Twig\Environment::createTemplate(user_input)->render(ctx)` — Twig (PHP)
  - `$smarty->fetch("string:" . user_input)` — Smarty (PHP)
  - `Liquid::Template.parse(user_input).render(ctx)` — Liquid (Ruby)
  - `ERB.new(user_input).result(binding)` — ERB (Ruby)
  - `t, _ := template.New("x").Parse(user_input); t.Execute(w, data)` — Go `text/template`
  - `Template.fromString(user_input).render(ctx)` — Pebble (Java)

- Dynamic template name construction where the name itself comes from user input and the engine resolves arbitrary files:
  - `render_template(user_input)` (Flask) where `user_input` is not validated against a safe list
  - `res.render(req.query.template)` (Express) where the template name is user-controlled

### What SSTI is NOT

Do not flag these patterns:

- **User input as context data** (safe — the template is static, only the data changes):
  ```
  render_template("profile.html", name=request.args.get("name"))
  env.get_template("report.html").render(user=user_obj)
  res.render("dashboard", { title: req.body.title })
  ```
- **XSS via template output**: If the template outputs unsanitized user data that is then rendered in a browser — that's XSS, not SSTI
- **Static templates with dynamic filenames validated against an allowlist**: If the template name comes from user input but is strictly validated against a hardcoded set of allowed template names, it's not SSTI
- **Sandboxed template engines configured with a restricted environment**: Liquid, Mustache, and similar logic-less engines cannot execute arbitrary code even if the template string comes from user input — but still flag them as "Needs Manual Review" unless you can confirm the engine is logic-less

### Patterns That Prevent SSTI

When you see these patterns, the code is likely **not vulnerable**:

**1. Static template file with dynamic context (most common safe pattern)**
```python
# Flask — static template, user input only in context dict
return render_template("user_profile.html", username=request.args.get("name"))

# Express — static view name
res.render("dashboard", { user: req.user })
```

**2. Allowlist validation for template names**
```python
ALLOWED_TEMPLATES = {"invoice.html", "receipt.html", "summary.html"}
template_name = request.args.get("tmpl", "invoice.html")
if template_name not in ALLOWED_TEMPLATES:
    abort(400)
return render_template(template_name)
```

**3. Logic-less / sandboxed engines that don't support code execution**
```javascript
// Mustache — logic-less, cannot execute arbitrary code even if template is user-supplied
const output = Mustache.render(userTemplate, ctx);  // lower risk, but still flag for review
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
