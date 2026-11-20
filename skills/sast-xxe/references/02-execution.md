<!-- Part of the `sast-xxe` skill. Open with ../SKILL.md for the overview. -->

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find Vulnerable XML Parsing Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where XML is parsed without external entity resolution being explicitly disabled. Write results to `sast/xxe-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, XML libraries in use, and any XML-accepting endpoints.
>
> **What to search for — vulnerable XML parsing patterns**:
>
> Flag any XML parsing call where there is **no adjacent, paired hardening** (disabling DTD / external entity features). You are not yet tracing whether the input is user-controlled; that is Phase 2's job.
>
> 1. **Python — stdlib parsers (flag unless defusedxml is used as a drop-in)**:
>    - `xml.etree.ElementTree.parse(...)`, `ET.fromstring(...)`, `ET.iterparse(...)`
>    - `xml.dom.minidom.parseString(...)`, `xml.dom.minidom.parse(...)`
>    - `xml.sax.parseString(...)`, `xml.sax.parse(...)`
>    - `xmltodict.parse(...)` (backed by expat — generally safe for entity expansion, but flag for review)
>
> 2. **Python — lxml (flag unless `resolve_entities=False` and `no_network=True` are set)**:
>    - `etree.parse(...)`, `etree.fromstring(...)`, `etree.XML(...)`
>    - `etree.XMLParser(...)` without `resolve_entities=False`
>    - `objectify.parse(...)`, `objectify.fromstring(...)`
>
> 3. **Java — flag any instantiation of these without the matching hardening features set**:
>    - `DocumentBuilderFactory.newInstance()` → `newDocumentBuilder()` → `parse(...)`
>    - `SAXParserFactory.newInstance()` → `newSAXParser()` → `parse(...)`
>    - `XMLInputFactory.newInstance()` → `createXMLStreamReader(...)`
>    - `TransformerFactory.newInstance()` → `newTransformer()` used with XML source
>    - `SchemaFactory.newInstance(...)` → `newSchema(...)`
>    - Spring: `MarshallingHttpMessageConverter` with `Jaxb2Marshaller` if entity expansion not disabled
>
> 4. **PHP — flag any of these without `libxml_disable_entity_loader(true)` immediately before (PHP 7.x), or without `LIBXML_NONET` flag (PHP 8.x)**:
>    - `simplexml_load_string(...)`, `simplexml_load_file(...)`
>    - `DOMDocument::loadXML(...)`, `DOMDocument::load(...)`
>    - `xml_parse(...)` with `xml_parser_create()`
>    - `SimpleXMLElement::__construct(...)` with raw string
>
> 5. **.NET — flag any of these without `DtdProcessing.Prohibit` and `XmlResolver = null`**:
>    - `new XmlDocument()` followed by `.Load(...)` or `.LoadXml(...)`
>    - `new XmlTextReader(...)` (legacy — DTD on by default in older .NET)
>    - `XPathDocument(...)`, `XDocument.Load(...)`, `XElement.Load(...)`
>    - `XmlReader.Create(...)` without `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }`
>
> 6. **Node.js — flag these libraries when parsing untrusted input**:
>    - `libxmljs.parseXmlString(...)`, `libxmljs.parseXml(...)`
>    - `node-expat` parser instantiation
>    - `sax.createStream(...)` / `sax.parser(...)` — check if entity expansion is used
>    - `xml2js.parseString(...)` — generally safe in v0.5+; flag only if `explicitArray` or other options suggest an older version or entity expansion is re-enabled
>
> 7. **Ruby — flag these when used with options that enable entity expansion**:
>    - `Nokogiri::XML(input) { |config| config.noent }` — `noent` enables entity substitution
>    - `REXML::Document.new(input)` — REXML is vulnerable to entity expansion DoS; check for entity expansion usage
>    - `LibXML::XML::Document.string(input)` — check entity options
>
> 8. **Go — flag third-party XML libraries that support entity resolution**:
>    - `github.com/beevik/etree` usage — check if network/entity resolution is configured
>    - Standard `encoding/xml` is generally safe (does not resolve external entities) — flag only if combined with custom entity handling
>
> **What to skip** (these are safe patterns — do not flag):
> - `import defusedxml` used as the XML parser (Python)
> - `etree.XMLParser(resolve_entities=False, no_network=True)` (lxml)
> - Java `DocumentBuilderFactory` with `disallow-doctype-decl` feature set to `true`
> - Java `XMLInputFactory` with `IS_SUPPORTING_EXTERNAL_ENTITIES = false`
> - .NET `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`
> - Nokogiri default usage without `noent` or other entity-expansion options
> - Parsing of fully static, bundled, non-user-influenced XML files (e.g. reading config from disk at startup with no user input involved)
>
> **Output format** — write to `sast/xxe-recon.md`:
>
> ```markdown
> # XXE Recon: [Project Name]
>
> ## Summary
> Found [N] XML parsing sites without explicit external entity hardening.
>
> ## Vulnerable Parsing Sites
>
> ### 1. [Descriptive name — e.g., "lxml.etree.fromstring without resolve_entities=False in upload handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Parser / library**: [e.g., lxml etree / Java DocumentBuilder / PHP DOMDocument]
> - **Missing hardening**: [what protection is absent — e.g., "resolve_entities not set to False", "disallow-doctype-decl feature not set"]
> - **Input variable(s)**: `var_name` — [brief note on what it appears to be, e.g., "HTTP request body" or "file upload content" or "unknown origin"]
> - **Code snippet**:
>   ```
>   [the XML parsing call and surrounding context]
>   ```
>
> [Repeat for each site]
> ```

### Between Phases: Check Recon Results

After Phase 1 completes, read `sast/xxe-recon.md`. If the summary states zero vulnerable parsing sites were found (or the file contains no entries under "Vulnerable Parsing Sites"), **do not launch Phase 2 or Phase 3**. Instead, write the following to `sast/xxe-results.md`, **delete** `sast/xxe-recon.md`, and stop:

```
No vulnerabilities found.
```

Only proceed to Phase 2 if at least one vulnerable parsing site was identified in the recon output.

### Phase 2: Verify — Trace User Input (Batched)

After Phase 1 completes, read `sast/xxe-recon.md` and split the entries under "Vulnerable Parsing Sites" into **batches of up to 3 sites each** (use the numbered `###` sections: ### 1., ### 2., etc.). Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/xxe-recon.md` and count the numbered site sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/xxe-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Java with DocumentBuilder, include only the Java-related examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned vulnerable XML parsing site, determine whether a user-supplied value reaches the XML parser. Our goal is to find XXE vulnerabilities. Write results to `sast/xxe-batch-[N].md`.
>
> **Your assigned parsing sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, file upload handlers, and how data flows through the application.
>
> **XXE reference — What to look for**:
>
> User-controlled XML must not reach a parser that allows external entity resolution without hardening. Trace each site's XML input back to its origin.
>
> **For each parsing site, trace the XML input variable(s) backwards to their origin**:
>
> 1. **Direct user input** — the XML content is assigned directly from a request source:
>    - HTTP request body (especially `Content-Type: application/xml` or `text/xml` endpoints): `request.body`, `req.body`, `request.data`, `php://input`, `HttpContext.Request.Body`
>    - File uploads: `request.FILES`, `req.file`, `multipart/form-data` fields
>    - HTTP query params or form fields containing XML snippets
>    - URL path parameters that reference XML resources
>
> 2. **Indirect user input** — the XML is derived from user input through transformations or intermediate steps:
>    - A file path supplied by the user is used to open and parse a file
>    - A URL supplied by the user is fetched and the response is parsed as XML
>    - User input is embedded into an XML template before parsing (potential injection into the XML structure itself)
>    - Variable passed through helper functions — trace the full call chain
>
> 3. **Second-order input** — the XML content was stored (e.g., in the DB or filesystem) from a prior user-controlled upload or input, and is now being parsed:
>    - Find where the stored content was originally written — was it user-supplied at that point?
>    - Was it validated or sanitized at write time?
>
> 4. **Server-side / hardcoded source** — the XML comes from a bundled resource, config file loaded at startup, or server-generated content with no user influence — this site is NOT exploitable as XXE from user input.
>
> **For each parsing site, also assess exploitability**:
> - Is the response returned to the caller? (Reflected XXE — attacker can read file contents directly)
> - Is the response not returned, but side effects are observable? (Blind XXE — exfiltration via DNS/HTTP OOB or error messages)
> - Is the application behind authentication? (Reduces severity but does not eliminate the vulnerability)
> - Is the parser used in a context where only specific XML schemas are accepted? (e.g., SOAP envelope validation — still exploitable if DTD processing is on)
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the XML parser and the parser has no external entity hardening. Response or out-of-band channel allows exfiltration.
> - **Likely Vulnerable**: User input probably reaches the parser (indirect flow), or the parser is unhardened but the exploitation path is partially obscured.
> - **Not Vulnerable**: The XML source is fully server-controlled, OR the parser has proper hardening in place (DTD disabled, external entities disabled).
> - **Needs Manual Review**: Cannot determine the input source with confidence, or the hardening configuration is complex and requires runtime verification.
>
> **Output format** — write to `sast/xxe-batch-[N].md`:
>
> ```markdown
> # XXE Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP request body flows directly into lxml etree.fromstring without resolve_entities=False"]
> - **Taint trace**: [Step-by-step from entry point to the parsing call — e.g., "request.body → xml_data → etree.fromstring(xml_data)"]
> - **Parser**: [library and version if known]
> - **Exploitability**: [Reflected / Blind OOB / DoS only — describe what the attacker can achieve]
> - **Impact**: [e.g., "Read arbitrary local files via file:// entity", "SSRF to internal services via http:// entity", "DoS via entity expansion"]
> - **Remediation**: [Specific fix — e.g., "Use defusedxml", "Set resolve_entities=False and no_network=True", "Set disallow-doctype-decl feature to true"]
> - **Dynamic Test**:
>   ```
>   [curl command or payload to confirm the finding.
>    Show the exact endpoint, Content-Type header, and XXE payload.
>    Example:
>    curl -X POST https://app.example.com/api/import \
>      -H "Content-Type: application/xml" \
>      -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
>    Look for /etc/passwd content in the response body.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "XML source likely comes from user-uploaded file via helper function" or "Parser unhardened but input path partially unclear"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Concern**: [Why it's still a risk despite uncertainty]
> - **Remediation**: [Apply appropriate parser hardening]
> - **Dynamic Test**:
>   ```
>   [payload to attempt]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "XML is read from a bundled config file at startup with no user influence" or "defusedxml is used as the parser"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the input source or parser configuration could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `load_document()` in xml_utils.py to confirm whether its argument comes from a user request"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/xxe-batch-*.md` file and merge them into a single `sast/xxe-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/xxe-batch-1.md`, `sast/xxe-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/xxe-results.md` using this format:

```markdown
# XXE Analysis Results: [Project Name]

## Executive Summary
- Parsing sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/xxe-results.md`, **delete all intermediate files**: `sast/xxe-recon.md` and `sast/xxe-batch-*.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 parsing sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any XML parsing call that lacks explicit external entity hardening, regardless of where the input comes from. Do not attempt to trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each site found in Phase 1, trace the XML input back to its origin. If it comes from a user-controlled source, the site is a real vulnerability.
- **Parser defaults matter**: Java DOM/SAX, PHP SimpleXML/DOMDocument, and lxml all resolve external entities by default — they require explicit hardening. Python's `defusedxml` and Go's `encoding/xml` are safe by default.
- **Do not confuse `LIBXML_NOENT` with protection**: in PHP, `LIBXML_NOENT` **expands** entities into their values — it does NOT disable entity loading. Only `libxml_disable_entity_loader(true)` or `LIBXML_NONET` provides network-entity protection.
- **XInclude is a separate vector**: if `XIncludeAware` processing is enabled on Java parsers or `xi:include` is processed elsewhere, flag it separately — it can read local files without a classic `ENTITY` declaration.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Taint can flow indirectly: a file upload may be saved to disk in one handler, then parsed in another background job. Trace the full chain including asynchronous processing paths.
- Blind XXE (no output in response) is still exploitable via DNS or HTTP callbacks to attacker-controlled servers. Do not dismiss a finding just because the parsed XML is not echoed back.
- Clean up intermediate files: after the final `sast/xxe-results.md` is written, ensure `sast/xxe-recon.md` and all `sast/xxe-batch-*.md` files are deleted (on the zero-findings early exit, only `sast/xxe-recon.md` is deleted).
