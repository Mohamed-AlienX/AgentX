---
name: sast-fileupload
description: >-
  Find insecure file upload handling in source: extension and MIME bypass, missing
  content-type validation, attacker-controlled stored filename, writes into an executable
  or web-served directory, and archive extraction without entry validation. Use when asked
  about unrestricted upload, webshell upload or upload validation bypass. Do not use for
  traversal outside an upload flow - use sast-pathtraversal.
mitre_attack: [T1505.003, T1190]
---

# Insecure File Upload Detection

You are performing a focused security assessment to find insecure file upload vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **discovery** (find all places where uploaded files are received and stored), **batched verify** (check bypass vectors in parallel batches of up to 3 upload sites each), and **merge** (consolidate batch reports into one results file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is an Insecure File Upload

Insecure file upload occurs when an application accepts files from users without properly validating or restricting what can be uploaded, allowing an attacker to upload executable or malicious files. The most critical outcome is **Remote Code Execution (RCE)**: an attacker uploads a web shell (e.g., a `.php` file) and the server executes it when accessed via a direct URL.

The core pattern: *a user-supplied file reaches a storage location without adequate extension validation, and the stored file is accessible or executable.*

### What Insecure File Upload IS

- Accepting any file type with no extension or content check: `file.save(upload_path)` with no validation
- Content-Type-only validation: checking `Content-Type: image/png` without verifying the actual extension or file content — trivially bypassed by setting the header manually
- Extension blocklist with gaps: `.php` is blocked but `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`, `.shtml` are not
- Case-insensitive bypass: blocking `.php` but allowing `.PHP`, `.Php`, `.pHp`
- Double extension bypass: `shell.php.jpg` — code extracts the last `.jpg` and considers it safe, but the server (Apache) serves it as PHP
- Path traversal in filenames: `../../webroot/shell.php` stored via an unsanitized filename
- Incomplete filename sanitization: only stripping `../` but not encoded variants `%2e%2e%2f`
- Serving uploaded files from a web-executable directory without disabling execution

### What Insecure File Upload is NOT

Do not flag these as file upload vulnerabilities:

- **Stored XSS via SVG**: uploading an SVG with embedded `<script>` that is reflected back — that's XSS, not an upload execution issue
- **SSRF via file content**: uploading an XML or SVG that triggers an outbound request — that's XXE/SSRF, not a file upload execution issue
- **DoS via large files**: missing file size limits — a separate availability issue
- **IDOR on download**: accessing another user's uploaded file without authorization — that's IDOR
- **Secure uploads**: files stored outside the web root, or served through a controlled download endpoint that sets `Content-Disposition: attachment`, or stored in an object storage bucket with no public execution capability

### Patterns That Prevent Insecure File Upload

When you see these patterns together, the code is likely **not vulnerable**:

**1. Allowlist of safe extensions (most important)**
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
ext = filename.rsplit('.', 1)[-1].lower()
if ext not in ALLOWED_EXTENSIONS:
    abort(400)
```

**2. Magic byte / file content validation (defense in depth)**
```python
import magic
mime = magic.from_buffer(file.read(2048), mime=True)
ALLOWED_MIMES = {'image/png', 'image/jpeg', 'image/gif'}
if mime not in ALLOWED_MIMES:
    abort(400)
```

**3. Filename sanitization using a trusted library**
```python
from werkzeug.utils import secure_filename
filename = secure_filename(file.filename)  # strips path separators and dangerous chars
```

**4. Storing uploads outside the web root**
```
/var/uploads/  ← not served by the web server
/var/www/html/ ← web root (do NOT store uploads here)
```

**5. Serving uploads through a controlled endpoint with Content-Disposition**
```python
@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename,
                               as_attachment=True)  # forces download, prevents execution
```

**6. Renaming the file to a server-generated UUID**
```python
import uuid
stored_name = str(uuid.uuid4()) + '.jpg'  # extension is server-controlled, not user-controlled
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
