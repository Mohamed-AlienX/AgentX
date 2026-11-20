<!-- Part of the `sast-fileupload` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — Flask

```python
# VULNERABLE: no extension check, file stored in web-accessible directory
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join('static/uploads', f.filename))
    return 'uploaded'

# VULNERABLE: content-type only check (trivially bypassed with curl -H)
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f.content_type not in ['image/png', 'image/jpeg']:
        abort(400)
    f.save(os.path.join('static/uploads', f.filename))
    return 'uploaded'

# VULNERABLE: blocklist — .phtml/.phar/.php5 not covered
BLOCKED = {'.php', '.sh', '.exe'}
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1].lower()
    if ext in BLOCKED:
        abort(400)
    f.save(os.path.join('static/uploads', f.filename))
    return 'uploaded'

# SECURE: allowlist + sanitized filename + outside web root
ALLOWED = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = '/var/uploads'  # outside web root

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    filename = secure_filename(f.filename)
    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED:
        abort(400)
    f.save(os.path.join(UPLOAD_FOLDER, filename))
    return 'uploaded'
```

### Python — Django

```python
# VULNERABLE: no validation on FileField
class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['upload']

# VULNERABLE: manual save with no extension check
def upload(request):
    f = request.FILES['file']
    with open(f'media/uploads/{f.name}', 'wb+') as dest:
        for chunk in f.chunks():
            dest.write(chunk)

# SECURE: custom validator on FileField
def validate_file_extension(value):
    ext = os.path.splitext(value.name)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
        raise ValidationError('Unsupported file extension.')

class DocumentForm(forms.ModelForm):
    upload = forms.FileField(validators=[validate_file_extension])
```

### Node.js — Multer (Express)

```javascript
// VULNERABLE: no file filter, stored in public directory
const upload = multer({ dest: 'public/uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
    res.send('uploaded');
});

// VULNERABLE: MIME type filter only (can be faked)
const upload = multer({
    dest: 'uploads/',
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) return cb(null, false);
        cb(null, true);
    }
});

// SECURE: allowlist of extensions + storage outside web root
const ALLOWED_EXT = ['.jpg', '.jpeg', '.png', '.gif'];
const storage = multer.diskStorage({
    destination: '/var/uploads',  // not served by Express
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${uuidv4()}${ext}`);
    }
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, ALLOWED_EXT.includes(ext));
    }
});
```

### PHP

```php
// VULNERABLE: no extension check, stored in web root
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// VULNERABLE: checking only content type header
if ($_FILES['file']['type'] !== 'image/jpeg') {
    die('Invalid file type');
}
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// VULNERABLE: blocklist missing phtml/phar
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
$blocked = ['php', 'sh', 'py'];
if (in_array($ext, $blocked)) die('Blocked');
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);

// SECURE: allowlist + rename to UUID + outside web root
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die('Invalid extension');
$stored = '/var/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $stored);
```

### Java — Spring Boot (MultipartFile)

```java
// VULNERABLE: no validation, stored in web-accessible path
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) throws IOException {
    Path path = Paths.get("src/main/resources/static/uploads/" + file.getOriginalFilename());
    Files.write(path, file.getBytes());
    return "uploaded";
}

// VULNERABLE: content type header only
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) throws IOException {
    if (!file.getContentType().startsWith("image/")) throw new BadRequestException();
    Files.write(Paths.get("uploads/" + file.getOriginalFilename()), file.getBytes());
    return "uploaded";
}

// SECURE: allowlist + UUID rename + path outside web root
private static final Set<String> ALLOWED = Set.of("jpg", "jpeg", "png", "gif");

@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) throws IOException {
    String original = StringUtils.cleanPath(file.getOriginalFilename());
    String ext = FilenameUtils.getExtension(original).toLowerCase();
    if (!ALLOWED.contains(ext)) throw new BadRequestException("Invalid extension");
    String stored = UUID.randomUUID() + "." + ext;
    Files.write(Paths.get("/var/uploads/" + stored), file.getBytes());
    return "uploaded";
}
```

### Go

```go
// VULNERABLE: no extension check, stored in static directory
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    defer file.Close()
    dst, _ := os.Create("static/uploads/" + header.Filename)
    defer dst.Close()
    io.Copy(dst, file)
}

// SECURE: allowlist extension + UUID rename + outside web root
var allowed = map[string]bool{"jpg": true, "jpeg": true, "png": true, "gif": true}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    defer file.Close()
    ext := strings.ToLower(filepath.Ext(header.Filename))
    if ext == "" || !allowed[ext[1:]] {
        http.Error(w, "invalid extension", http.StatusBadRequest)
        return
    }
    stored := "/var/uploads/" + uuid.New().String() + ext
    dst, _ := os.Create(stored)
    defer dst.Close()
    io.Copy(dst, file)
}
```

### Ruby on Rails

```ruby
# VULNERABLE: no content type or extension validation
def upload
  file = params[:file]
  File.open(Rails.root.join('public', 'uploads', file.original_filename), 'wb') do |f|
    f.write(file.read)
  end
end

# SECURE: ActiveStorage with content type allowlist (Rails 6+)
has_one_attached :avatar
validates :avatar, content_type: ['image/png', 'image/jpg', 'image/jpeg']
# Note: still validate extension too — content_type is user-supplied in some configurations

# SECURE: CarrierWave with extension and content type allowlist
class AvatarUploader < CarrierWave::Uploader::Base
  def extension_allowlist
    %w[jpg jpeg png gif]
  end

  def content_type_allowlist
    /image\//
  end
end
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: no extension check, stored in wwwroot
[HttpPost]
public async Task<IActionResult> Upload(IFormFile file) {
    var path = Path.Combine("wwwroot/uploads", file.FileName);
    using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok();
}

// SECURE: allowlist + GUID rename + outside web root
private static readonly HashSet<string> _allowed = new() { ".jpg", ".jpeg", ".png", ".gif" };

[HttpPost]
public async Task<IActionResult> Upload(IFormFile file) {
    var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
    if (!_allowed.Contains(ext)) return BadRequest("Invalid extension");
    var stored = Path.Combine("/var/uploads", $"{Guid.NewGuid()}{ext}");
    using var stream = new FileStream(stored, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok();
}
```

---

