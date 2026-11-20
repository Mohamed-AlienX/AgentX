<!-- Part of the `sast-xxe` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — stdlib xml.etree.ElementTree (vulnerable by default in CPython < 3.8 / expat quirks)

```python
# VULNERABLE: ElementTree parses DTDs; stdlib does NOT protect against all XXE
import xml.etree.ElementTree as ET
def parse_data(request):
    xml_data = request.body
    tree = ET.fromstring(xml_data)   # no hardening — expat may resolve entities
    return process(tree)

# SECURE: use defusedxml drop-in replacement
import defusedxml.ElementTree as ET
def parse_data(request):
    xml_data = request.body
    tree = ET.fromstring(xml_data)   # defusedxml blocks all XXE vectors
    return process(tree)
```

### Python — lxml

```python
# VULNERABLE: lxml resolves external entities by default
from lxml import etree
def parse_upload(request):
    data = request.body
    tree = etree.fromstring(data)    # external entities resolved, network access allowed
    return render(tree)

# SECURE: disable entity resolution and network access
from lxml import etree
def parse_upload(request):
    data = request.body
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    tree = etree.fromstring(data, parser)
    return render(tree)
```

### Java — DocumentBuilder (DOM)

```java
// VULNERABLE: default DocumentBuilder resolves external entities
@PostMapping("/import")
public ResponseEntity<?> importXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    return ResponseEntity.ok(process(doc));
}

// SECURE: disable DTD and external entity features
@PostMapping("/import")
public ResponseEntity<?> importXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setExpandEntityReferences(false);
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    return ResponseEntity.ok(process(doc));
}
```

### Java — SAXParser

```java
// VULNERABLE: default SAXParser allows external entities
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(inputStream, handler);

// SECURE: disable external entities
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
SAXParser parser = factory.newSAXParser();
parser.parse(inputStream, handler);
```

### Java — XMLInputFactory (StAX)

```java
// VULNERABLE: default XMLInputFactory supports external entities
XMLInputFactory xif = XMLInputFactory.newInstance();
XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);

// SECURE: disable external entity support
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
```

### PHP — SimpleXML / DOMDocument

```php
// VULNERABLE: simplexml_load_string with no entity loader disabled
function parseXml($xml) {
    return simplexml_load_string($xml);  // resolves external entities
}

// VULNERABLE: DOMDocument without protection
function parseXml($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);   // external entities enabled by default
    return $doc;
}

// SECURE (PHP 7.x): disable entity loader before parsing
function parseXml($xml) {
    libxml_disable_entity_loader(true);
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NONET);
    return $doc;
}
```

### .NET — XmlDocument / XmlTextReader

```csharp
// VULNERABLE: XmlDocument with default XmlUrlResolver resolves external entities
XmlDocument doc = new XmlDocument();
doc.Load(stream);   // external entities resolved

// VULNERABLE: XmlTextReader (legacy) — DTD processing on by default in old .NET
XmlTextReader reader = new XmlTextReader(stream);

// SECURE: XmlDocument with null resolver and prohibited DTD
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;   // disables external entity resolution
doc.Load(stream);

// SECURE: XmlReader with DtdProcessing.Prohibit
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
XmlReader reader = XmlReader.Create(stream, settings);
```

### Node.js — libxmljs

```javascript
// VULNERABLE: libxmljs parses with entity resolution on by default
const libxml = require('libxmljs');
app.post('/parse', (req, res) => {
    const doc = libxml.parseXmlString(req.body);
    res.send(doc.toString());
});

// SAFER: no built-in safe flag — avoid libxmljs for untrusted input entirely
// Prefer xml2js or a non-libxml2-backed parser
```

### Ruby — Nokogiri

```ruby
# VULNERABLE: Nokogiri with NOENT option enables entity substitution
def parse_xml(xml_input)
  Nokogiri::XML(xml_input) { |config| config.noent }
end

# SECURE: default Nokogiri (no options) — safe for untrusted input
def parse_xml(xml_input)
  Nokogiri::XML(xml_input)
end
```

### Go — encoding/xml

```go
// VULNERABLE: Go's encoding/xml does not resolve external entities
// but if combined with a third-party parser like etree with network enabled:
import "github.com/beevik/etree"

func parseXML(data []byte) {
    doc := etree.NewDocument()
    doc.ReadFromBytes(data)   // check library's entity resolution behaviour
}

// Go's standard encoding/xml: does not resolve external entities — generally safe.
// Flag only if a third-party XML library with entity support is used.
```

---

