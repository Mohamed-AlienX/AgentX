---
name: sast-xss
description: >-
  Find XSS in source: unescaped output into HTML, unsafe innerHTML,
  dangerouslySetInnerHTML and document.write sinks, missing contextual encoding, and
  sanitizer bypass in React, Vue or Angular templates. Use when asked about cross-site
  scripting in code. Do not use for server-side template injection - use sast-ssti.
mitre_attack: [T1059.007, T1189]
---

# Cross-Site Scripting (XSS) Detection

You are performing a focused security assessment to find Cross-Site Scripting vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find sink sites), **batched verify** (trace taint for parallel batches of up to 3 sinks each), and **merge** (consolidate batch results into one report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is XSS

XSS occurs when user-supplied input is incorporated into a web page's HTML, JavaScript, or DOM without proper escaping or sanitization. This allows attackers to inject and execute arbitrary scripts in victims' browsers, leading to session hijacking, credential theft, defacement, and malware distribution.

The core pattern: *unescaped, unsanitized user input reaches an HTML/JS output sink.*

### XSS Types

- **Reflected XSS**: User input is immediately echoed back in the HTTP response (e.g., a search term rendered directly into the page HTML).
- **Stored XSS**: User input is saved to persistent storage (database, file) and later rendered in HTML for other users.
- **DOM-based XSS**: Client-side JavaScript reads from an attacker-controlled source (`location.search`, `location.hash`, `document.cookie`) and writes to a dangerous DOM sink (`innerHTML`, `eval`, `document.write`) without server involvement.

### What XSS IS

**Server-side HTML sinks** — rendering user data into HTML responses without escaping:
- Python/Jinja2: `{{ var | safe }}`, `{% autoescape off %}...{{ var }}...{% endautoescape %}`
- Python/Django: `mark_safe(var)`, `format_html(...)` with `%s` and unescaped input, `{{ var | safe }}` in templates
- Python/Flask: `Markup(var)`, `render_template_string(f"...{var}...")`
- PHP: `echo $var`, `print $var`, `<?= $var ?>` without `htmlspecialchars()`
- Ruby/Rails: `raw(var)`, `var.html_safe`, `<%= raw var %>`, `content_tag` with `.html_safe`
- Java/JSP: `<%= var %>`, `${var}` without `<c:out>` or `fn:escapeXml()`
- Java/Thymeleaf: `th:utext="${var}"` (unescaped), `[(${var})]`
- Go/html-template misuse: using `template.HTML(var)`, `template.JS(var)`, `template.URL(var)` to bypass auto-escaping
- C#/Razor: `@Html.Raw(var)`, `MvcHtmlString.Create(var)`
- Node.js/EJS: `<%- var %>` (unescaped), vs `<%= var %>` (safe)
- Node.js/Handlebars: `{{{ var }}}` (triple-brace, unescaped)
- Node.js/Pug: `!{var}` (unescaped)
- Express: `res.send("<html>..." + var + "...")`, `res.write("<p>" + var + "</p>")`

**Client-side DOM sinks** — JavaScript writing user-controlled data to the DOM unsafely:
- `element.innerHTML = var`
- `element.outerHTML = var`
- `document.write(var)`, `document.writeln(var)`
- `element.insertAdjacentHTML('beforeend', var)`
- jQuery: `$(element).html(var)`, `$(element).append(var)` (when var contains HTML), `$('<div>' + var + '</div>')`
- React: `dangerouslySetInnerHTML={{ __html: var }}`
- Angular: `[innerHTML]="var"`, `bypassSecurityTrustHtml(var)`, `bypassSecurityTrustScript(var)`, `bypassSecurityTrustUrl(var)`
- Vue: `v-html="var"`

**JavaScript execution sinks** — user-controlled data evaluated as code:
- `eval(var)`
- `setTimeout(var, delay)` / `setInterval(var, delay)` when `var` is a string
- `new Function(var)()`
- `element.setAttribute('onclick', var)`, `element.setAttribute('href', 'javascript:' + var)`
- `location.href = var`, `location.replace(var)`, `location.assign(var)` (when var is user-controlled and can be `javascript:...`)
- `element.src = var`, `element.action = var` (script injection via `javascript:` URIs)
- `scriptElement.text = var`, `scriptElement.textContent = var`

**DOM-based sources** — attacker-controlled inputs read by client-side JavaScript:
- `location.search` (URL query string)
- `location.hash` (URL fragment)
- `location.href`
- `document.referrer`
- `document.URL`, `document.documentURI`
- `document.cookie`
- `postMessage` event data (`event.data`)
- `window.name`
- `localStorage.getItem(...)`, `sessionStorage.getItem(...)` (if populated from URL or postMessage)

### What XSS is NOT

Do not flag these as XSS:

- **CSRF**: Forging requests on behalf of a user — a separate vulnerability class
- **SQLi via XSS**: Injecting SQL through an XSS vector — the SQL injection itself is the primary finding
- **Clickjacking**: Embedding pages in iframes — different vulnerability class
- **Header injection**: Injecting newlines into HTTP response headers — separate class (HTTP Response Splitting)
- **Safe template output**: Auto-escaped `{{ var }}` in Jinja2/Django/Twig/Blade/Handlebars double-brace syntax with auto-escaping on — these are safe
- **`textContent` / `innerText`**: These write plain text only; no HTML parsing occurs — safe

### Patterns That Prevent XSS

When you see these patterns, the code is likely **not vulnerable**:

**1. Context-aware auto-escaping (most template engines default)**
```
# Jinja2 / Django (auto-escape on by default)
{{ var }}          # HTML-escaped → safe

# EJS
<%= var %>         # HTML-escaped → safe

# Handlebars
{{ var }}          # HTML-escaped → safe

# Pug
= var              # HTML-escaped → safe

# Thymeleaf
th:text="${var}"   # HTML-escaped → safe

# Razor (C#)
@var               # HTML-encoded → safe
```

**2. Explicit escaping before output**
```php
// PHP
echo htmlspecialchars($var, ENT_QUOTES, 'UTF-8');
```
```ruby
# Rails
<%= h(var) %>
<%= ERB::Util.html_escape(var) %>
```
```java
// JSP with JSTL
<c:out value="${var}"/>
// or fn:escapeXml()
${fn:escapeXml(var)}
```
```go
// html/template — auto-escapes by context (HTML, JS, URL, CSS)
{{.Var}}   // safe inside html/template
```

**3. DOM manipulation using safe properties**
```javascript
element.textContent = userInput;   // plain text, no HTML parsing — safe
element.innerText = userInput;     // plain text — safe
```

**4. Sanitization with an allowlisted HTML library**
```javascript
// DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);

// sanitize-html with strict config
const clean = sanitizeHtml(userInput, { allowedTags: [], allowedAttributes: {} });
```

**5. React / Angular / Vue auto-escaping**
```jsx
// React JSX — auto-escaped
return <div>{userInput}</div>;
```
```html
<!-- Angular — auto-escaped -->
<div>{{ userInput }}</div>
<!-- Vue — auto-escaped -->
<div>{{ userInput }}</div>
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
