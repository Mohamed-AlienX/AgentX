<!-- Part of the `sast-rce` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### OS Command Injection — Python

```python
# VULNERABLE: shell=True with f-string
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout
# Payload: ?host=127.0.0.1;id  → executes "id"

# VULNERABLE: os.system with string formatting
def convert_image(filename):
    size = request.form.get('size')
    os.system(f"convert {filename} -resize {size} output.jpg")

# SECURE: list-form subprocess, no shell
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return result.stdout
```

### OS Command Injection — Node.js

```javascript
// VULNERABLE: exec with template literal
app.get('/search', (req, res) => {
  const query = req.query.q;
  exec(`grep -r "${query}" /var/log/app/`, (err, stdout) => {
    res.send(stdout);
  });
});
// Payload: ?q=foo" /etc/passwd "

// VULNERABLE: execSync with concatenation
function runScript(userScript) {
  return execSync('node scripts/' + userScript);
}

// SECURE: spawn with separate args
app.get('/search', (req, res) => {
  const query = req.query.q;
  const proc = spawn('grep', ['-r', query, '/var/log/app/']);
  proc.stdout.on('data', (data) => res.write(data));
  proc.on('close', () => res.end());
});
```

### OS Command Injection — PHP

```php
// VULNERABLE: shell_exec with user input
function generateThumbnail($file) {
    $size = $_GET['size'];
    shell_exec("convert {$file} -resize {$size} thumb.jpg");
}

// VULNERABLE: backtick operator
function checkHost() {
    $host = $_POST['host'];
    $result = `ping -c 1 $host`;
    return $result;
}

// SECURE: escapeshellarg (reduces risk — but prefer removing shell entirely)
function generateThumbnail($file) {
    $size = escapeshellarg($_GET['size']);
    $file = escapeshellarg($file);
    shell_exec("convert $file -resize $size thumb.jpg");
}
```

### OS Command Injection — Ruby

```ruby
# VULNERABLE: string interpolation in system()
get '/convert' do
  format = params[:format]
  system("ffmpeg -i input.mp4 -f #{format} output")
end

# VULNERABLE: backtick with user input
def check_dns
  `nslookup #{params[:host]}`
end

# SECURE: system() with separate args (no shell expansion)
get '/convert' do
  format = params[:format]
  ALLOWED = %w[mp4 avi mkv]
  return 400 unless ALLOWED.include?(format)
  system("ffmpeg", "-i", "input.mp4", "-f", format, "output")
end
```

### Code Injection — Python eval/exec

```python
# VULNERABLE: eval with user input
@app.route('/calculate')
def calculate():
    expr = request.args.get('expr')
    result = eval(expr)  # attacker can run __import__('os').system('id')
    return str(result)

# VULNERABLE: exec with user code
@app.route('/run')
def run_code():
    code = request.json.get('code')
    exec(code)  # full arbitrary code execution
    return "ok"

# SECURE: ast.literal_eval for safe expression parsing (literals only)
from ast import literal_eval
@app.route('/parse')
def parse():
    data = request.args.get('data')
    result = literal_eval(data)  # only parses strings/numbers/lists/dicts/bools
    return str(result)
```

### Code Injection — JavaScript eval / Function

```javascript
// VULNERABLE: eval with user input
app.post('/formula', (req, res) => {
  const formula = req.body.formula;
  const result = eval(formula);  // RCE: process.exit(), require('child_process')...
  res.json({ result });
});

// VULNERABLE: new Function() constructor
function compute(userExpression) {
  const fn = new Function('x', `return ${userExpression}`);
  return fn(42);
}

// VULNERABLE: vm.runInNewContext (sandbox escape via __proto__ pollution)
const vm = require('vm');
app.post('/eval', (req, res) => {
  const result = vm.runInNewContext(req.body.code);
  res.json({ result });
});

// SECURE: use a math expression library (no arbitrary code)
const { evaluate } = require('mathjs');
app.post('/formula', (req, res) => {
  const result = evaluate(req.body.formula);  // sandboxed math expressions only
  res.json({ result });
});
```

### Unsafe Deserialization — Python pickle

```python
# VULNERABLE: deserializing user-supplied pickle data
@app.route('/load', methods=['POST'])
def load_session():
    data = request.get_data()
    session = pickle.loads(data)  # attacker controls __reduce__ → RCE
    return jsonify(session)

# VULNERABLE: base64-encoded pickle from cookie
@app.route('/profile')
def profile():
    session_cookie = request.cookies.get('session')
    data = base64.b64decode(session_cookie)
    user = pickle.loads(data)  # crafted cookie → arbitrary code at deserialization
    return render_template('profile.html', user=user)

# SECURE: use JSON (no code execution semantics)
@app.route('/profile')
def profile():
    session_cookie = request.cookies.get('session')
    user = json.loads(base64.b64decode(session_cookie))
    return render_template('profile.html', user=user)
```

### Unsafe Deserialization — Java

```java
// VULNERABLE: ObjectInputStream.readObject() on user-supplied stream
@PostMapping("/deserialize")
public ResponseEntity<?> deserialize(@RequestBody byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();  // gadget chains (Commons Collections, Spring, etc.) → RCE
    return ResponseEntity.ok(obj);
}

// VULNERABLE: Jackson with enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // attacker specifies arbitrary class type in JSON → RCE
MyData data = mapper.readValue(userJson, MyData.class);

// SECURE: Jackson with concrete type, no enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
MyData data = mapper.readValue(userJson, MyData.class);  // safe with concrete target type
```

### Unsafe Deserialization — PHP

```php
// VULNERABLE: unserialize() with user input
function loadProfile() {
    $data = base64_decode($_COOKIE['profile']);
    $user = unserialize($data);  // PHP object injection → POP chain → RCE
    return $user;
}

// VULNERABLE: unserialize from POST body
$obj = unserialize($_POST['data']);

// SECURE: json_decode instead
function loadProfile() {
    $data = base64_decode($_COOKIE['profile']);
    $user = json_decode($data, true);  // no code execution semantics
    return $user;
}
```

### Unsafe Deserialization — Ruby Marshal

```ruby
# VULNERABLE: Marshal.load with user-supplied data
post '/restore' do
  data = Base64.decode64(params[:state])
  object = Marshal.load(data)  # arbitrary Ruby object graph → RCE via gadgets
  object.process
end

# SECURE: use JSON
post '/restore' do
  data = JSON.parse(Base64.decode64(params[:state]))
  # work with plain data structures only
end
```

### Unsafe Deserialization — Node.js

```javascript
// VULNERABLE: node-serialize (known RCE via IIFE in serialized string)
const serialize = require('node-serialize');
app.post('/restore', (req, res) => {
  const obj = serialize.unserialize(req.body.data);  // IIFE payload → RCE
  res.json(obj);
});

// VULNERABLE: js-yaml v3 yaml.load (executes JS functions in YAML tags)
const yaml = require('js-yaml');
const data = yaml.load(userInput);  // !!js/function payload → RCE

// SECURE: yaml.safeLoad (v3) or FAILSAFE_SCHEMA (v4)
const data = yaml.safeLoad(userInput);  // only loads plain data types
```

### Unsafe YAML — Python

```python
# VULNERABLE: yaml.load without Loader
import yaml
data = yaml.load(user_input)  # !!python/object/apply: payload → RCE

# SECURE: yaml.safe_load
data = yaml.safe_load(user_input)  # only loads basic data types
```

---

