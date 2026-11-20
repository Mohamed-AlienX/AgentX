---
name: hunt-access-control
description: >-
  Hunt for broken access control — IDOR/BOLA, horizontal & vertical privilege escalation,
  missing function-level authz, forced browsing. Built from personal BAC + PrivEsc + IDOR
  notes. Use when testing multi-user apps, object references (ids), role-gated features,
  or admin endpoints.
mitre_attack: [T1078, T1530]
---

# Broken Access Control (from your notes + advanced)

> See also (project skills): `hunt-idor` (IDOR/BOLA deep-dive from reports), `hunt-auth-bypass`, `hunt-api-misconfig` (mass assignment, verb tampering), `hunt-graphql` (GID/Relay BOLA). This skill is the umbrella methodology tying them together.

## Golden rules (your notes)
- BAC = **authorization** failure, not authentication.
- "Authentication ≠ Authorization" — logged in ≠ allowed.
- JWT is for authN, not authZ — never trust `role`/`user_id` claims alone.
- IDOR = technique; horizontal escalation = result.
- Always test with **two accounts** (A attacker, B victim) in the same org/workspace.
- Tools assist — thinking finds BAC.

## Core methodology (your notes)

### PrivEsc replay loop
1. Login as **admin (A)** → explore admin features (user mgmt, roles, secrets, billing, org settings).
2. Intercept each admin request → note endpoint, method, params, headers.
3. Login as **normal user (B)** → replay the same request changing **only** cookies/Authorization.
4. Analyze: `200 OK` → privesc; data returned → info disclosure; action executed → Critical.

### IDOR testing (your notes)
- Map every identifier location: URL path, query, JSON body, form body, headers (`X-User-ID`), cookies, hidden fields, GraphQL args.
- Test **all verbs** on the same object: GET / PUT / PATCH / DELETE / POST.
- Identifier types to try: numeric (`/orders/10234`), username/email, filename, encoded (Base64/MD5/hex), UUID v1 (time-based, predictable), Mongo ObjectId.
- GUIDs not guessable? Leak them via search, "share" features, notifications, JS files, emails.
- Multi-tenant: swap `org_id`/`team_id` in path, query, AND body.
- Blind IDOR: DELETE returns 204 but object is gone; measure via timing.
- Parameter pollution: `?id=A&id=B`, JSON duplicate keys, array wrap `{"user_id":[B]}`.
- Method tampering: GET blocked → POST/HEAD/PATCH.
- Content-Type switching: JSON → XML / form / multipart.
- Path traversal in IDs: `../user/124`, `%2e%2e%2f`.
- Mass assignment: add `role`, `isAdmin`, `user_id`, `balance` to create/update bodies.
- JWT vs request mismatch: JWT says user 5, body says 7 — backend must use JWT; if it uses body → IDOR.

### Impact ranking (your notes)
Critical: become admin/owner → High: modify users/secrets/billing → Medium: read internal data → Low: minor info exposure.
CVSS guide from your notes: single PII record ~5.3-6.9, all records one user ~7.1, all users ~8.8, multi-tenant org-scale 8.8-9.5, write/delete escalates to 9.1.

### Report structure (your notes)
Title: "Privilege Escalation allows normal user to [action]".
Steps: 1) login admin, 2) intercept, 3) login normal user, 4) replay, 5) observe success.
Always state the missing server-side check + remediation (deny-by-default routes, object ownership checks, indirect references, rate limiting on enumeration).

## 🚀 Advanced (beyond your notes)

- **GraphQL BOLA**: decode Relay IDs (`base64` of `gid://Type/123`) → numeric IDOR behind opaque IDs. Introspect mutations; test every `node(id:)` resolver cross-account.
- **WebSocket IDOR**: can user A's socket subscribe to B's channel/topic? Test auth on `SUBSCRIBE` frames, not just the HTTP handshake.
- **Hit the backend directly**: apps behind gateways often enforce authz only at the gateway. If you can find/reach the internal origin host (from info disclosure), replay the request there with only your low-priv token.
- **Role matrix fuzzing**: enumerate all endpoints × all roles systematically with Burp **AuthMatrix** or **Autorize** — low-priv token auto-replayed on every request in scope.
- **SCIM endpoints**: `/scim/v2/Users`, `/ServiceProviderConfig` — often exposed with weak authz; direct user provisioning = privesc path.
- **Cache-based privesc**: responses personalized per role but cached without `Vary: Cookie` → request admin-only content, then retrieve it from cache anonymously (see web-cache skill).
- **Destructive-test discipline**: for DELETE/DROP-style privesc PoCs, use a **dry-run pattern** — prove authorization is missing with a harmless variant (e.g., attempt on a resource you own from the other account), then state impact; programs respect restraint.
- **Function-level authz in APIs**: test admin mutations over every version (`/v1`..`/v3`) — new versions add authz, old ones keep working.
- **Header trust tricks**: `X-Original-URL: /admin`, `X-Rewrite-URL`, `X-Forwarded-User: admin` on routes "protected" by front controller.

## Validation checklist
- [ ] Two distinct accounts; cross-account access demonstrated
- [ ] All HTTP verbs tested on the resource
- [ ] Identifier was obtained without relying on a victim-shared secret
- [ ] Action/data proven (not just a 200 on a shell page)
- [ ] Scope check: some programs exclude self-IDOR