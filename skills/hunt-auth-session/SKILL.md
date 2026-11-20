---
name: hunt-auth-session
description: >-
  Hunt for auth & session flaws — password reset abuse (token leaks, host header
  injection, OTP brute), MFA/2FA bypass (cross-account OTP, OAuth path, force browse),
  broken session management (fixation, invalidation gaps), rate-limit bypass, JWT attacks
  (alg confusion, kid/jku/jwk injection, weak secrets). Use on
  login/reset/MFA/session/OAuth/JWT surfaces.
mitre_attack: [T1078, T1539, T1110, T1556]
---

# Authentication & Session Management (from your notes + advanced)

> See also (project skills): `hunt-mfa-bypass`, `hunt-session`, `hunt-oauth`, `hunt-jwt-crypto`, `hunt-auth-bypass`. This skill is the consolidated attack tree; the dedicated skills own the deep dives (esp. JWT crypto → `hunt-jwt-crypto`).

## Recon mindset (your notes — the 6 questions)
Is OTP bound to user? single-use? rate-limited? Is 2FA enforced on EVERY path (password, OAuth, reset, magic link)? Are sessions invalidated on enable-2FA/password change? Does client or server make the final access decision?

---

## Password reset (your notes — highest-value vectors)

**Phase 1 (direct ATO):**
1. **Referer leak**: open reset link → click any external link → token sent in `Referer` to third party.
2. **Host header injection (reset poisoning)** — payload ladder: `Host: attacker.com` / `X-Forwarded-Host` / double Host / `Host: hacker.com?.victim.com` / `%23@` trick / S3 `Host:` bypass.
3. **Email parameter injection**: `email=victim&email=attacker`, `|`, `,`, JSON arrays, `%0a%0dcc:` header injection (CRLF into mail), `user[email][]=`.
4. **Token/OTP in HTTP response** — search full response body after requesting reset.
5. **IDOR on reset confirm**: swap email to victim's with your valid token.
6. **Origin header manipulation** for link building.
7. **Registration-as-reset (upsert ATO)**: POST /register with victim email + your password.
8. **skipOldPwdCheck-style params**: `arjun` the reset endpoint.

**Phase 2 (logic/session):**
- Reset link valid after email change / after password change (must invalidate).
- Password reset doesn't kill sessions (test 2 browsers).
- OTP brute via **session rotation** (get new session after block) + IP Rotate extension.
- Token never expires; **UUID v1 = time-based** → sandwich attack (generate before/after, enumerate range).
- X-Forwarded headers trusted; **use your own token on victim's account** (no token binding); response manipulation (401 → 200).
- Burp **Sequencer** on token entropy first.

**Phase 3/4:** no rate limit → email bombing; token over HTTP; token in JS/Burp history; forced browse past verification; SQLi in reset code field (`sqlmap -r req.txt -p code`).

## MFA / 2FA (your notes — ordered by payoff)

1. **Force browse past 2FA** (fastest win): after valid password, hit `/dashboard`, `/api/profile`, `/api/transactions` directly with the pre-2FA session.
2. **Response/status manipulation**: `{"success":false}` → `true`, 403 → 200 (Match & Replace).
3. **Cross-account OTP**: A's valid OTP accepted on B's pending session → not bound to user.
4. **OAuth/SSO path**: enable 2FA, logout, login via Google/GitHub → land without OTP.
5. **Password-reset path**: complete reset → auto-logged-in without 2FA; check if reset **disables** 2FA.
6. **Brute force OTP** (4-6 digits, Intruder numbers payload) — prove actual success.
7. **Rate-limit bypass**: spoof `X-Forwarded-For` / `X-Originating-IP` / `X-Client-IP` (test one at a time); IP Rotate extension for real-IP rotation.
8. **CSRF / clickjacking on disable-2FA** (no token, no password re-entry).
9. **Session invalidation gaps**: enabling 2FA doesn't kill old sessions.
10. **Backup codes**: reuse, cross-account, brute.
11. **Medium:** OTP in response, reusable OTP, old OTPs stay valid after new issue (build a set of live codes to shrink brute space), array/type-juggling (`{"otp":["0000","1111",...]}`), null/empty bypass.
12. **Sending OTP abuse** — financial/DoS; test minimally, only if in scope.

## Session management (your notes — 20 checks, grouped)

- **Critical**: reset token valid after password change; **fixation** (pre-auth cookie == post-auth cookie); old sessions live after password change; unlimited concurrent sessions with no notification/revocation UI.
- **High**: reset token no expiry; session valid after **logout** (replay in Repeater); pre-2FA session after enabling 2FA; **predictable session IDs** (Sequencer entropy, embedded user data, short length); cookie attributes missing (`Secure`/`HttpOnly`/`SameSite`, `__Host-` prefix); session ID in URL/Referer/logs.
- **Medium**: email change keeps verification (change-email trick); **wrong email verified**; replay after logout; no idle timeout; **session puzzling** (variable overloading across flows); old reset token valid after new request.
- **Low**: cached pages after logout (missing `Cache-Control: no-store`); hidden logout; SSO logout not global; no rotation on privilege change.

## Rate limiting (your notes)

Critical targets: login, OTP, reset, internal password-check APIs, SSH(22). High: report abuse systems. Medium: forms/comments (spam).
Bypass ladder (your sheet): spoofed IP headers (test individually) → double-header → 429→403/status games → endpoint variations (case/version/trailing slash) → blank chars (`%00 %0d%0a %09 %0c %20`) → header rotation (UA/cookies) → gateway param abuse (`?t=1`) → **session/account rotation** → proxy rotation (FireProx/IP Rotate).
Advanced 2023-25: HTTP/2 multiplexing (Turbo Intruder `requestsPerConnection`), **GraphQL aliases batching**, REST bulk endpoints, sliding-window timing, WebSocket/gRPC upgrade, **CDN PoP-sharded counters** (geo-diverse proxies).
Golden rule: test the **correct** credential right after the limit triggers.

## JWT attacks (your notes — 12 attacks)

Recon: decode header; note alg/kid/jku/jwk/x5u/x5c; find authz-driving claims (sub, role, exp, iss, aud).
- 🔴 **Alg confusion RS256→HS256**: sign with server's RSA public key as HMAC secret (jwt_tool `-X k`, Burp JWT Editor symmetric key from base64 PEM).
- 🔴 **alg:none** (+ variants `None/NONE/nOnE`), keep trailing dot.
- 🔴 **JWE-wrapped PlainJWT** (pac4j CVE-2026-29000): encrypt inner `alg:none` JWT with server pubkey via jwcrypto.
- 🟠 **Weak HS256 secret**: `hashcat -m 16500` + rockyou; re-sign with jwt_tool.
- 🟠 **jwk injection (CVE-2018-0114)**: embed your own public key in `jwk` header.
- 🟠 **jku/JWKS spoofing**: host your JWKS, point `jku` at it (whitelist bypass → report as SSRF too).
- 🟠 **x5u/x5c cert injection**.
- 🟠 **ES256 nonce reuse** → private key recovery (needs two same-nonce sigs).
- 🟡 **kid**: path traversal to `/dev/null` (sign with empty secret), `/proc/sys/kernel/randomize_va_space` (secret="2"), **kid SQLi** (`' UNION SELECT 'key'-- -`), command injection in kid.
- 🟡 Missing claim validation (strip `exp`); cross-service relay (aud not checked); JTI replay via counter overflow (uuid → track used JTIs).
Defense checklist for reports: enforce fixed alg, never trust jku/jwk/x5u/x5c/kid from token, 256-bit secret, validate exp/nbf/iat/iss/aud, short lifetimes, key rotation.

## 🚀 Advanced (beyond your notes)

- **WebAuthn/passkeys**: check downgrade paths (passkey optional → fallback to password+OTP weaker path), ceremony issues (origin validation on attestation), and whether "remembered" devices skip verification entirely.
- **Refresh token rotation flaws**: reuse a refresh token twice — some systems only invalidate on the *next* request, enabling token replay races.
- **Cookie tossing (subdomain)**: if any subdomain lets you set a cookie on the parent domain with a throwaway name that shadows the real session cookie, you can fix sessions.
- **OAuth advanced**: `redirect_uri` strictness vs **path** confusion (`https://app/cb/../attacker`), ASVS-style exact match; **scope downgrading** in refresh; DPoP absent → bearer token replay; state=nonce missing → login CSRF.
- **SAML (compact starter)**: test XML signature wrapping (XSW variants — sign the assertion but submit the modified one), no `InResponseTo` validation, and AudienceRestriction mismatch; use `SAML Raider` (Burp).
- **OTP timing side channel**: response time differences (valid code checked earlier/later) can halve brute space — measure with Intruder "response received" times.
- **JWKS cache poisoning**: if the server caches keys by `kid` with no TTL, register a key with a colliding kid or exploit cache invalidation windows after key rotation.
- **JWT EdDSA/PS256**: newer alg confusion classes — try cross-alg (RS→HS still #1, but test ES256→HS256 with the public key too).
- **MFA push hygiene**: report "prompt bombing resistance" gaps (number matching absent) only when combined with a real bypass vector.

## Validation checklist
- [ ] Full ATO demonstrated (logged in / password changed), not a bypass signal
- [ ] Token/cookie weakness proven by actually using the forged value
- [ ] Rate limit bypass: real burst executed and measured
- [ ] JWT attack verified server-side (forged token → 200 on protected route)
- [ ] Session findings shown across two browsers/devices