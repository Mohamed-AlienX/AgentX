<!-- Part of the `sast-xss` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — Flask / Jinja2

```python
# VULNERABLE: Markup() bypasses Jinja2 auto-escaping
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return render_template_string(f"<h1>Hello, {name}!</h1>")   # raw f-string, no template escaping

# VULNERABLE: mark_safe equivalent
@app.route('/profile')
def profile():
    bio = request.args.get('bio', '')
    return render_template('profile.html', bio=Markup(bio))      # Markup() marks it as safe, bypassing escaping

# SECURE: use template with auto-escaping (never pass Markup around user input)
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return render_template('greet.html', name=name)              # template: {{ name }} — auto-escaped
```

### Python — Django

```python
# VULNERABLE: mark_safe() with user input
def user_bio(request):
    bio = request.GET.get('bio', '')
    safe_bio = mark_safe(bio)   # user input bypasses Django's auto-escaping
    return render(request, 'bio.html', {'bio': safe_bio})

# SECURE: pass raw string; template handles escaping
def user_bio(request):
    bio = request.GET.get('bio', '')
    return render(request, 'bio.html', {'bio': bio})   # template: {{ bio }} — auto-escaped
```

### PHP

```php
// VULNERABLE: echo without escaping
function showUsername($username) {
    echo "<p>Welcome, " . $username . "</p>";
}

// SECURE: htmlspecialchars
function showUsername($username) {
    echo "<p>Welcome, " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . "</p>";
}
```

### Node.js — Express (string concatenation)

```javascript
// VULNERABLE: user input concatenated into HTML response
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${query}</h1>`);
});

// SECURE: use a template engine with auto-escaping, or escape manually
const escapeHtml = require('escape-html');
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${escapeHtml(query)}</h1>`);
});
```

### Node.js / EJS

```html
<!-- VULNERABLE: unescaped output -->
<div><%- userInput %></div>

<!-- SECURE: escaped output -->
<div><%= userInput %></div>
```

### Node.js / Handlebars

```html
<!-- VULNERABLE: triple-brace, unescaped -->
<div>{{{ userInput }}}</div>

<!-- SECURE: double-brace, auto-escaped -->
<div>{{ userInput }}</div>
```

### JavaScript — DOM Sinks

```javascript
// VULNERABLE: innerHTML with URL fragment
const name = location.hash.substring(1);
document.getElementById('greeting').innerHTML = 'Hello, ' + name;

// SECURE: textContent
const name = location.hash.substring(1);
document.getElementById('greeting').textContent = 'Hello, ' + name;
```

```javascript
// VULNERABLE: eval with postMessage data
window.addEventListener('message', (event) => {
  eval(event.data);
});

// SECURE: parse and validate; never eval postMessage data
window.addEventListener('message', (event) => {
  const data = JSON.parse(event.data);
  // handle data safely
});
```

### React

```jsx
// VULNERABLE: dangerouslySetInnerHTML with user input
function Comment({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// SECURE: render as text (auto-escaped by React)
function Comment({ content }) {
  return <div>{content}</div>;
}
```

### Angular

```typescript
// VULNERABLE: bypassing Angular's DomSanitizer
constructor(private sanitizer: DomSanitizer) {}
getUserHtml(input: string): SafeHtml {
  return this.sanitizer.bypassSecurityTrustHtml(input);  // unsafe if input is user-controlled
}
```

```html
<!-- VULNERABLE: [innerHTML] with unsanitized value -->
<div [innerHTML]="userInput"></div>

<!-- SECURE: use interpolation (auto-escaped) -->
<div>{{ userInput }}</div>
```

### Ruby on Rails

```erb
<%# VULNERABLE: raw() or html_safe with user input %>
<%= raw(@user.bio) %>
<%= @user.bio.html_safe %>

<%# SECURE: default ERB escaping %>
<%= @user.bio %>
```

### Java — JSP

```jsp
<%-- VULNERABLE: scriptlet echo --%>
<p>Hello, <%= request.getParameter("name") %></p>

<%-- VULNERABLE: EL without c:out --%>
<p>Hello, ${param.name}</p>

<%-- SECURE: c:out escaping --%>
<p>Hello, <c:out value="${param.name}"/></p>
```

### Go — html/template vs. text/template

```go
// VULNERABLE: using text/template (no HTML escaping)
import "text/template"
tmpl := template.Must(template.New("").Parse("<h1>Hello, {{.Name}}!</h1>"))
tmpl.Execute(w, data)

// VULNERABLE: using template.HTML() cast to bypass escaping
import "html/template"
name := template.HTML(r.URL.Query().Get("name"))   // bypasses auto-escaping

// SECURE: html/template with plain string value
import "html/template"
tmpl := template.Must(template.New("").Parse("<h1>Hello, {{.Name}}!</h1>"))
tmpl.Execute(w, data)   // .Name is a plain string — auto-escaped
```

---

