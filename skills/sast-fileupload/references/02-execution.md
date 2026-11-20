<!-- Part of the `sast-fileupload` skill. Open with ../SKILL.md for the overview. -->

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find All File Upload Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where files uploaded by users are received and stored. Write results to `sast/fileupload-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the framework, file storage patterns, and whether uploads go to local disk, cloud storage, or a CDN.
>
> **What to search for — file upload handling patterns**:
>
> Look for any code that receives a file from an HTTP request and writes or stores it. Do not yet evaluate whether validation is present — just find all the sites.
>
> 1. **Python / Django**:
>    - `request.FILES` access
>    - `InMemoryUploadedFile`, `TemporaryUploadedFile`
>    - `default_storage.save(...)`, `FileSystemStorage().save(...)`
>    - Model `FileField` / `ImageField` form submissions
>    - `shutil.copyfileobj(f, dest)` or manual `.write(f.read())` on uploaded data
>
> 2. **Python / Flask**:
>    - `request.files.get(...)` or `request.files[...]`
>    - `file.save(...)` calls on a `FileStorage` object
>    - `werkzeug` `FileStorage` handling
>
> 3. **Node.js**:
>    - `multer` middleware: `upload.single(...)`, `upload.array(...)`, `upload.fields(...)`
>    - `busboy`, `formidable`, `multiparty` form parsing
>    - `express-fileupload`: `req.files`
>    - `fs.writeFile` / `fs.createWriteStream` / `pipe()` called with a request stream
>
> 4. **PHP**:
>    - `$_FILES` access
>    - `move_uploaded_file(...)` calls
>    - `copy($_FILES[...]['tmp_name'], ...)`
>
> 5. **Java / Spring**:
>    - `MultipartFile` parameters in controller methods: `@RequestParam MultipartFile`
>    - `CommonsMultipartFile`, `StandardMultipartFile`
>    - `Part.write(...)` (Servlet API)
>    - `file.transferTo(...)`, `Files.write(path, file.getBytes())`
>
> 6. **Go**:
>    - `r.FormFile(...)` or `r.MultipartForm.File`
>    - `io.Copy(dst, file)` where `file` comes from a multipart form
>    - `os.Create(...)` called with a filename derived from `header.Filename`
>
> 7. **Ruby / Rails**:
>    - `params[:file]` with `.read`, `.original_filename`, `.tempfile`
>    - `File.open(..., 'wb')` called with uploaded data
>    - `has_one_attached` / `has_many_attached` (ActiveStorage)
>    - CarrierWave `mount_uploader`, Shrine `include Shrine::Attachment`
>
> 8. **C# / ASP.NET**:
>    - `IFormFile` parameters: `file.CopyToAsync(...)`, `file.OpenReadStream()`
>    - `HttpPostedFileBase.SaveAs(...)`
>    - `Request.Files[...]`
>
> **Output format** — write to `sast/fileupload-recon.md`:
>
> ```markdown
> # File Upload Recon: [Project Name]
>
> ## Summary
> Found [N] file upload sites.
>
> ## Upload Sites
>
> ### 1. [Descriptive name — e.g., "Avatar upload endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Framework / method**: [e.g., Flask request.files / multer / move_uploaded_file]
> - **Storage destination**: [path, variable, or storage abstraction — e.g., "static/uploads/" or "S3 via boto3" or "unknown"]
> - **Validation observed** (preliminary, Phase 2 will analyze in depth): [list any extension checks, content-type checks, or "none visible"]
> - **Code snippet**:
>   ```
>   [the upload receive and save code]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/fileupload-recon.md`. If the recon found **zero upload sites** (the summary reports "Found 0" or the "Upload Sites" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/fileupload-results.md` and stop:

```markdown
# File Upload Analysis Results

No file upload sites found.
```

Only proceed to Phase 2 if Phase 1 found at least one upload site.

### Phase 2: Check for Extension Bypass Vulnerabilities (Batched)

After Phase 1 completes, read `sast/fileupload-recon.md` and split the upload sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/fileupload-recon.md` and count the numbered site sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/fileupload-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Node.js with Multer, include only the "Node.js — Multer (Express)" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned file upload site below, determine whether an attacker can upload a malicious file (e.g., a PHP web shell, a JSP shell, a Python script) by manipulating the filename, extension, or Content-Type header. Write results to `sast/fileupload-batch-[N].md`.
>
> **Your assigned upload sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the framework, storage paths, and how uploads are served.
>
> **Reference — what insecure file upload is and is not**:
>
> Focus on execution or dangerous file types reaching storage without adequate controls. Do **not** flag stored XSS via SVG, SSRF via uploaded XML, DoS via size limits, or IDOR on download as file-upload execution issues (other skills cover those).
>
> **Patterns that reduce risk** — if you see a strong combination (allowlist, sanitization, non-web-root storage, UUID rename), the site is likely **Not Vulnerable** unless bypass still applies.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each upload site, evaluate the following bypass vectors**:
>
> 1. **No extension check**: No validation of any kind on the filename or extension. Any file is accepted. Immediately flag as **Vulnerable**.
>
> 2. **Content-Type / MIME header only**: Validation reads `Content-Type` or `mimetype` from the request headers but does not inspect the actual filename extension or file bytes. Attackers can set `Content-Type: image/png` while uploading `shell.php`. Flag as **Vulnerable**.
>
> 3. **Blocklist-based validation**: An explicit list of forbidden extensions. Check whether the blocklist is exhaustive for the server's technology:
>    - **PHP servers**: Are `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.phar`, `.shtml` also blocked? If any are missing, flag as **Vulnerable**.
>    - **Java servers**: Are `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf` also blocked?
>    - **ASP.NET servers**: Are `.asp`, `.aspx`, `.ashx`, `.asmx`, `.cer`, `.asa` also blocked?
>    - **Node.js**: Is `.js` execution possible via the server config? Check if `.js` files in the upload dir can be required/executed.
>    - Any blocklist is inherently weaker than an allowlist — flag as **Likely Vulnerable** even if seemingly complete.
>
> 4. **Case sensitivity bypass**: Blocking `.php` but not `.PHP`, `.Php`, `.pHp`. Check whether the comparison uses `.toLowerCase()` / `.lower()` / `strtolower()` / case-insensitive matching.
>
> 5. **Double extension / multi-extension**: `shell.php.jpg` — if the code extracts the extension using a method that takes the last segment after the last dot, this should be caught by an allowlist. However, on Apache servers with `AddHandler` misconfig, the leftmost recognized extension may be used for execution. Check how the extension is extracted:
>    - Safe: `filename.rsplit('.', 1)[-1]`, `path.extname(filename)` (takes the last extension)
>    - Risky server config: Apache `AddHandler application/x-httpd-php .php` — even `shell.php.jpg` may be executed as PHP
>
> 6. **Path traversal in filename**: If the original filename is used in the storage path without sanitization, `../../webroot/shell.php` can place files in unintended directories. Check for:
>    - Use of `secure_filename()`, `basename()`, `path.basename()`, `Path.GetFileName()`, or `filepath.Base()` — these strip directory separators and are safe
>    - Direct use of `file.filename`, `header.Filename`, `file.getOriginalFilename()`, `$_FILES['name']` in a path join without sanitization — flag as **Vulnerable**
>
> 7. **File stored in web-executable directory**: Even with a correct extension allowlist, if uploads go to a directory served by the web server (e.g., `static/uploads/`, `public/uploads/`, `wwwroot/uploads/`) and the web server is configured to execute scripts, a bypass in extension validation becomes critical. Note whether the storage path is web-accessible.
>
> 8. **No content-based validation (magic bytes)**: The server trusts the extension without verifying the actual file content. A file named `shell.jpg` with PHP code inside is still dangerous if the extension check can be bypassed and the server executes it. Note absence of magic-byte checking as a contributing weakness.
>
> **Classification**:
> - **Vulnerable**: No validation at all, or a clearly bypassable check (content-type only, missing common extensions in blocklist, missing `.lower()`, path traversal in filename).
> - **Likely Vulnerable**: Blocklist that appears complete but is inherently weaker than an allowlist; or an allowlist with potential edge cases (e.g., does not account for uppercase extensions).
> - **Not Vulnerable**: Strict allowlist of safe extensions (applied case-insensitively), combined with filename sanitization and/or server-generated UUID rename, files stored outside web root or behind a controlled download endpoint.
> - **Needs Manual Review**: Validation logic is in a shared helper or middleware that could not be fully read; or storage path is dynamic and could not be determined.
>
> **Output format** — write to `sast/fileupload-batch-[N].md`:
>
> ```markdown
> # File Upload Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "No extension validation — any file type accepted" or "Content-Type header used as sole check"]
> - **Bypass vector**: [Exact technique — e.g., "Upload shell.php directly" or "Set Content-Type: image/png while uploading a .php file" or "Use .phtml extension not covered by blocklist"]
> - **Storage path**: [Where the file lands — web-accessible or not]
> - **Impact**: [e.g., "Attacker uploads PHP web shell and achieves RCE by accessing /uploads/shell.php"]
> - **Remediation**: [Specific fix — switch to allowlist, add `.lower()`, use secure_filename, move storage outside web root]
> - **Dynamic Test**:
>   ```
>   [curl or HTTP request demonstrating the bypass.
>    Example: curl -X POST https://app.example.com/upload \
>      -F "file=@shell.php;type=image/png" \
>      then access: https://app.example.com/static/uploads/shell.php?cmd=id]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Blocklist-based extension check — inherently incomplete"]
> - **Bypass vector**: [Possible bypass — e.g., "Try .phtml, .phar, .php5 if server is Apache/PHP"]
> - **Storage path**: [Where the file lands]
> - **Concern**: [Why it's still a risk]
> - **Remediation**: [Replace blocklist with allowlist]
> - **Dynamic Test**:
>   ```
>   [payload to attempt bypass]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Strict allowlist of png/jpg/gif with .lower(), UUID rename, stored outside web root"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why validation logic or storage path could not be determined]
> - **Suggestion**: [What to trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/fileupload-batch-*.md` file and merge them into a single `sast/fileupload-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/fileupload-batch-1.md`, `sast/fileupload-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (total sites analyzed equals the number from recon; counts per classification sum across batches).
4. Write the merged report to `sast/fileupload-results.md` using this format:

```markdown
# File Upload Analysis Results: [Project Name]

## Executive Summary
- Upload sites analyzed: [total from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/fileupload-results.md`, **delete all intermediate batch files** (`sast/fileupload-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 upload sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely discovery**: find every place a user-supplied file is received and stored. Do not deeply analyze validation in Phase 1 — just note what is visible. That is Phase 2's job.
- **Phase 2 is purely bypass analysis**: for each assigned upload site, examine the validation logic and determine whether it can be bypassed through extension manipulation, case variation, content-type spoofing, or path traversal.
- **Phase 3 is merge only**: combine batch files into `sast/fileupload-results.md` and remove intermediates; do not re-analyze code in Phase 3.
- An allowlist is always stronger than a blocklist. Any blocklist-based approach should be flagged as at minimum **Likely Vulnerable** because blocklists are almost always incomplete.
- Content-Type (MIME type from the HTTP header) is **fully attacker-controlled** — never treat it as a security control.
- Case sensitivity matters: `.PHP` bypasses a check for `.php` if `.toLowerCase()` is missing. Always check.
- Path traversal in filenames is a separate attack vector from extension bypass — check for both.
- Even a correct extension check is weakened if the file is stored in a web-executable directory. Note storage location in every finding.
- Magic byte checking (reading actual file bytes) is defense-in-depth but does not replace extension allowlisting — a valid image with PHP code appended can still be dangerous.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete `sast/fileupload-recon.md` and all `sast/fileupload-batch-*.md` files after the final `sast/fileupload-results.md` is written.
