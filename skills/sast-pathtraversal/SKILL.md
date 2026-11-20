---
name: sast-pathtraversal
description: >-
  Find path traversal in source: file read, write, download and include sinks fed by
  request data, missing normalization, and no base-directory confinement. Use when asked
  about directory traversal or arbitrary file disclosure. Do not use for upload validation
  bypass - use sast-fileupload.
mitre_attack: [T1083, T1190, T1005]
---

# Path Traversal Detection

You are performing a focused security assessment to find path traversal vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find file-loading sinks with dynamic paths), **batched verify** (trace user input and check mitigations in parallel batches of 3), and **merge** (consolidate batch results into one report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Path Traversal

Path traversal (also called directory traversal) occurs when user-supplied input is incorporated into a file path that is then used to read, write, or serve files from the filesystem — without properly constraining the resulting path to an intended base directory. An attacker can supply sequences like `../` or encoded variants (`%2e%2e%2f`, `..%2f`, `%2e%2e/`) to escape the intended directory and access arbitrary files such as `/etc/passwd`, application source code, credentials, or private keys.

The core pattern: *unvalidated user input reaches a filesystem operation and the resolved path is not verified to remain within the intended base directory.*

### What Path Traversal IS

- Serving a user-requested filename directly from a base directory without canonicalizing and checking the resulting path:
  `open(os.path.join(BASE_DIR, user_filename))`
- Constructing a file path from a URL parameter and passing it to a file-read function:
  `fs.readFile(path.join(__dirname, req.query.file), ...)`
- Template rendering or include directives driven by user input:
  `include($_GET['page'] . '.php')`
- Archive extraction (`ZipFile`, `tarfile`, `zipslip`) where entry names are used as output paths without stripping `../` components
- Using `send_file()` / `send_from_directory()` / `res.sendFile()` with an unsanitized user-controlled path
- Reading a file whose path is derived from a user-controlled database value that was stored without sanitization

### What Path Traversal is NOT

Do not flag these as path traversal:

- **SSRF**: Fetching a remote URL from user input — that is Server-Side Request Forgery, a separate class
- **RCE via file write**: Writing attacker-controlled content to an arbitrary path — related but a different impact class (flag as RCE or File Upload)
- **Static file serving**: Serving files from a path that is entirely hardcoded with no user influence
- **Safe path joins followed by realpath + prefix check**: The code computes `realpath()` and verifies it starts with the intended base directory
- **basename() before join**: Using only the filename component strips traversal sequences (though note this prevents directory selection, not just traversal)

### Patterns That Prevent Path Traversal

When you see these mitigations applied **before** the file operation, the code is likely **not vulnerable**:

**1. `realpath` / `resolve` followed by a base-directory prefix check (most robust fix)**
```python
# Python
import os
BASE = '/var/www/files'
safe_path = os.path.realpath(os.path.join(BASE, user_input))
if not safe_path.startswith(BASE + os.sep):
    raise PermissionError("Path escape detected")
with open(safe_path) as f:
    ...
```

```javascript
// Node.js
const BASE = path.resolve('/var/www/files');
const resolved = path.resolve(BASE, req.query.file);
if (!resolved.startsWith(BASE + path.sep)) {
    return res.status(403).send('Forbidden');
}
fs.readFile(resolved, ...);
```

```java
// Java
Path base = Paths.get("/var/www/files").toRealPath();
Path resolved = base.resolve(userInput).normalize();
if (!resolved.startsWith(base)) {
    throw new SecurityException("Path escape");
}
Files.readAllBytes(resolved);
```

**2. `basename()` / `path.basename()` to strip directory components**
```python
# Python — strips all directory parts, only the filename remains
filename = os.path.basename(user_input)
with open(os.path.join(BASE, filename)) as f:
    ...
```

```php
// PHP
$filename = basename($_GET['file']);
readfile('/var/www/uploads/' . $filename);
```

**3. Allowlist of permitted filenames or extensions**
```python
ALLOWED = {'report.pdf', 'manual.txt', 'logo.png'}
if user_input not in ALLOWED:
    abort(400)
with open(os.path.join(BASE, user_input)) as f:
    ...
```

**4. Framework-provided safe file serving**
```python
# Flask — send_from_directory validates the path stays within the directory
return send_from_directory('/var/www/files', filename)

# Django — FileResponse with a path that was never user-controlled
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
