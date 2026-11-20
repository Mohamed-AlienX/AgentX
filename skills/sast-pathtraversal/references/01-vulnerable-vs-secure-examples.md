<!-- Part of the `sast-pathtraversal` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — Flask

```python
# VULNERABLE: user-controlled filename joined without realpath check
@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/files', filename)
    return send_file(filepath)

# SECURE: resolve and verify the path stays within the base directory
@app.route('/download')
def download():
    filename = request.args.get('file')
    base = os.path.realpath('/var/www/files')
    filepath = os.path.realpath(os.path.join(base, filename))
    if not filepath.startswith(base + os.sep):
        abort(403)
    return send_file(filepath)
```

### Python — FastAPI

```python
# VULNERABLE: path parameter used directly in file read
@app.get('/file/{name}')
async def get_file(name: str):
    return FileResponse(f'/app/static/{name}')

# SECURE: basename strips traversal sequences
@app.get('/file/{name}')
async def get_file(name: str):
    safe_name = os.path.basename(name)
    return FileResponse(os.path.join('/app/static', safe_name))
```

### Node.js — Express

```javascript
// VULNERABLE: req.query.file used directly in readFile
app.get('/file', (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.query.file);
  fs.readFile(filePath, (err, data) => res.send(data));
});

// SECURE: resolve and check prefix
app.get('/file', (req, res) => {
  const base = path.resolve(__dirname, 'uploads');
  const filePath = path.resolve(base, req.query.file);
  if (!filePath.startsWith(base + path.sep)) {
    return res.status(403).send('Forbidden');
  }
  fs.readFile(filePath, (err, data) => res.send(data));
});
```

### PHP

```php
// VULNERABLE: direct inclusion of user input
<?php
$page = $_GET['page'];
include($page . '.php');

// VULNERABLE: readfile with unsanitized path
$file = $_GET['file'];
readfile('/var/www/uploads/' . $file);

// SECURE: basename strips directory components
$file = basename($_GET['file']);
readfile('/var/www/uploads/' . $file);

// SECURE: realpath + prefix check
$base = realpath('/var/www/uploads');
$path = realpath($base . '/' . $_GET['file']);
if ($path === false || strpos($path, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    exit;
}
readfile($path);
```

### Ruby on Rails

```ruby
# VULNERABLE: params[:file] used directly in file read
def show
  file_path = Rails.root.join('public', 'reports', params[:file])
  send_file file_path
end

# SECURE: basename only
def show
  safe_name = File.basename(params[:file])
  send_file Rails.root.join('public', 'reports', safe_name)
end
```

### Java — Spring

```java
// VULNERABLE: path variable used directly to read file
@GetMapping("/file/{name}")
public ResponseEntity<Resource> getFile(@PathVariable String name) throws IOException {
    Path filePath = Paths.get("/var/www/files").resolve(name);
    Resource resource = new UrlResource(filePath.toUri());
    return ResponseEntity.ok(resource);
}

// SECURE: normalize and check prefix
@GetMapping("/file/{name}")
public ResponseEntity<Resource> getFile(@PathVariable String name) throws IOException {
    Path base = Paths.get("/var/www/files").toRealPath();
    Path resolved = base.resolve(name).normalize();
    if (!resolved.startsWith(base)) {
        return ResponseEntity.status(403).build();
    }
    Resource resource = new UrlResource(resolved.toUri());
    return ResponseEntity.ok(resource);
}
```

### Go

```go
// VULNERABLE: query param joined directly to base directory
func fileHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    http.ServeFile(w, r, filepath.Join("/var/www/files", name))
}

// SECURE: filepath.Clean + prefix check
func fileHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    base := "/var/www/files"
    clean := filepath.Join(base, filepath.Clean("/"+name))
    if !strings.HasPrefix(clean, base+string(os.PathSeparator)) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, clean)
}
```

### Archive Extraction (ZipSlip)

```python
# VULNERABLE: ZipSlip — zip entry names can contain ../
import zipfile
with zipfile.ZipFile(user_zip) as zf:
    zf.extractall('/var/www/uploads')

# SECURE: validate each entry path stays within the target directory
import zipfile, os
base = os.path.realpath('/var/www/uploads')
with zipfile.ZipFile(user_zip) as zf:
    for member in zf.namelist():
        target = os.path.realpath(os.path.join(base, member))
        if not target.startswith(base + os.sep):
            raise ValueError(f"ZipSlip detected: {member}")
    zf.extractall(base)
```

---

