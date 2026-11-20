<!-- Part of the `sast-ssti` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — Flask / Jinja2

```python
# VULNERABLE: user input rendered as template string
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
    # Payload: ?name={{7*7}} → renders "49"
    # RCE:    ?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# SECURE: user input passed as context variable to a static template
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return render_template("greet.html", name=name)
```

```python
# VULNERABLE: env.from_string with user-controlled template
@app.route('/preview')
def preview():
    tmpl = request.form.get('template')
    return Environment().from_string(tmpl).render()

# SECURE: load template from trusted file, pass user data as context
@app.route('/preview')
def preview():
    data = request.form.get('data')
    return env.get_template("preview.html").render(data=data)
```

### Node.js — EJS

```javascript
// VULNERABLE: user input as template string
app.get('/render', (req, res) => {
  const tmpl = req.query.template;
  res.send(ejs.render(tmpl, { user: req.user }));
  // Payload: ?template=<%- global.process.mainModule.require('child_process').execSync('id') %>
});

// SECURE: user input only in context data
app.get('/render', (req, res) => {
  res.render('report', { content: req.query.content });
});
```

### Node.js — Nunjucks

```javascript
// VULNERABLE: renderString with user-controlled template
app.post('/preview', (req, res) => {
  const output = nunjucks.renderString(req.body.tmpl, { user: req.user });
  res.send(output);
  // Payload: {{ range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")() }}
});

// SECURE: render from a file, user input only as context
app.post('/preview', (req, res) => {
  res.render('preview.html', { content: req.body.content });
});
```

### Node.js — Handlebars

```javascript
// VULNERABLE: compile with user-supplied template string
app.get('/email', (req, res) => {
  const template = Handlebars.compile(req.query.tmpl);
  res.send(template({ user: req.user }));
  // Payload: {{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}...
});

// SECURE: compile static template, user data in context
const template = Handlebars.compile(fs.readFileSync('email.hbs', 'utf8'));
app.get('/email', (req, res) => {
  res.send(template({ name: req.query.name }));
});
```

### Ruby — ERB

```ruby
# VULNERABLE: user input passed to ERB constructor
get '/render' do
  tmpl = params[:template]
  ERB.new(tmpl).result(binding)
  # Payload: <%= `id` %>
end

# SECURE: static ERB file, user data in binding only
get '/render' do
  @name = params[:name]
  erb :profile
end
```

### Java — FreeMarker

```java
// VULNERABLE: template string sourced from user input
@PostMapping("/preview")
public String preview(@RequestParam String tmplStr, Model model) throws Exception {
    Template t = new Template("preview", new StringReader(tmplStr), cfg);
    StringWriter out = new StringWriter();
    t.process(model.asMap(), out);
    return out.toString();
    // Payload: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
}

// SECURE: load template from classpath, user data only in model
@GetMapping("/report")
public String report(@RequestParam String userId, Model model) {
    model.addAttribute("user", userService.findById(userId));
    return "report";  // resolves to templates/report.ftl
}
```

### Java — Velocity

```java
// VULNERABLE: user input evaluated as template
public String render(String userTemplate) {
    VelocityContext ctx = new VelocityContext();
    StringWriter sw = new StringWriter();
    Velocity.evaluate(ctx, sw, "template", userTemplate);
    return sw.toString();
    // Payload: #set($e="")#set($x=$e.class.forName("java.lang.Runtime"))...
}

// SECURE: load template from file
Template t = Velocity.getTemplate("report.vm");
t.merge(ctx, sw);
```

### Java — Thymeleaf (Spring)

```java
// VULNERABLE: user input used as template expression evaluated by Thymeleaf
@GetMapping("/hello")
public String hello(@RequestParam String lang, Model model) {
    return "user/" + lang + "/welcome";  // path traversal + SSTI if lang is e.g. "__${T(java.lang.Runtime).getRuntime().exec('id')}"
}

// SECURE: validate lang against an allowlist
private static final Set<String> ALLOWED_LANGS = Set.of("en", "fr", "de");

@GetMapping("/hello")
public String hello(@RequestParam String lang, Model model) {
    if (!ALLOWED_LANGS.contains(lang)) return "error";
    return "user/" + lang + "/welcome";
}
```

### PHP — Twig

```php
// VULNERABLE: user input as template string
$app->get('/render', function (Request $request) use ($twig) {
    $tmpl = $request->query->get('template');
    return $twig->createTemplate($tmpl)->render([]);
    // Payload: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
});

// SECURE: static template, user data in context array
$app->get('/profile', function (Request $request) use ($twig) {
    return $twig->render('profile.html.twig', ['name' => $request->query->get('name')]);
});
```

### PHP — Smarty

```php
// VULNERABLE: user-controlled template string via fetch("string:...")
$template = $_GET['tmpl'];
$smarty->fetch("string:" . $template);
// Payload: {php}echo shell_exec('id');{/php}

// SECURE: pass user data as template variable
$smarty->assign('name', $_GET['name']);
$smarty->display('profile.tpl');
```

### Go — text/template

```go
// VULNERABLE: user input parsed as template
func handler(w http.ResponseWriter, r *http.Request) {
    tmpl := r.URL.Query().Get("tmpl")
    t, _ := template.New("x").Parse(tmpl)
    t.Execute(w, data)
    // Payload: {{.Func "os/exec" "id"}} — depends on data methods exposed
}

// SECURE: static template string or file; user input only in data
func handler(w http.ResponseWriter, r *http.Request) {
    t := template.Must(template.ParseFiles("tmpl/page.html"))
    t.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}
// Note: Go's html/template auto-escapes output, but text/template does not.
// Even html/template is vulnerable to SSTI if user input reaches .Parse().
```

---

