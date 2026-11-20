---
name: sast-missingauth
description: >-
  Find missing authentication and broken function-level authorization in source: routes
  reachable without a session, admin-only handlers with no role gate, and middleware
  applied inconsistently across routers. Use when asked about unauthenticated access or
  vertical privilege escalation. Do not use for per-object ownership checks - use
  sast-idor.
mitre_attack: [T1078, T1190]
---

# Missing Authentication & Broken Function-Level Authorization Detection

You are performing a focused security assessment to find missing authentication and broken function-level authorization vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (map endpoints and the permission system), **batched verify** (check authentication and authorization in parallel batches of 3 endpoints each), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What This Skill Covers

### Missing Authentication
An endpoint performs a sensitive action but requires **no login at all** — any anonymous HTTP request can trigger it.

### Broken Function-Level Authorization
An endpoint requires authentication (user must be logged in) but **does not check whether the authenticated user has the required role or permission** to invoke that function. The classic example: a regular user calling an admin-only API.

### What This Skill Is NOT

Do not conflate with:
- **IDOR / Horizontal privilege escalation**: Authenticated user A accessing user B's resource by changing an ID. This skill covers **vertical** privilege escalation and unauthenticated access.
- **JWT weaknesses**: Flawed token signing/verification (covered by sast-jwt).
- **Business logic flaws**: Price manipulation, workflow bypass — these are separate.

---

## Vulnerability Classes

### Class 1: Unauthenticated Sensitive Endpoint
The endpoint modifies data, returns private information, or performs an administrative action — with no authentication required.

```
GET /api/admin/users          → returns full user list, no token needed
DELETE /api/admin/users/5     → deletes a user, no token needed
POST /api/settings/smtp       → updates server config, no token needed
```

### Class 2: Authenticated but Missing Role Check
The endpoint requires a valid session/token but performs no role or permission check. Any authenticated user — regardless of role — can invoke admin or privileged functions.

```
Regular user sends:
DELETE /api/admin/users/5
Authorization: Bearer <regular_user_token>
→ Server deletes the user without checking if the caller is an admin
```

### Class 3: Incomplete or Bypassable Authorization
Authorization logic is present but can be bypassed:
- Role check exists in the GET handler but not in the corresponding DELETE/POST handler
- Role check is conditional on a request header or parameter the attacker controls
- Middleware is registered but the route is mounted before the middleware applies

---

## Authorization Patterns That PREVENT Vulnerabilities

When you see these patterns, the endpoint is likely **not vulnerable**:

**1. Authentication + role-check middleware on a route group**
```javascript
// Express: all /admin routes protected
router.use('/admin', auth, requireRole('admin'));
router.delete('/admin/users/:id', deleteUser);   // protected by above

// Flask-Login + custom decorator
@app.route('/admin/users')
@login_required
@admin_required
def list_users(): ...
```

**2. Declarative role annotations (Java / Spring)**
```java
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/api/admin/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) { ... }
```

**3. In-handler role check before sensitive action**
```python
# Django
@login_required
def delete_user(request, user_id):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    User.objects.filter(id=user_id).delete()
    return HttpResponse(status=204)
```

**4. Middleware gate applied to entire prefix**
```go
// Chi router — admin group protected
r.Group(func(r chi.Router) {
    r.Use(AdminOnly)
    r.Delete("/admin/users/{id}", deleteUser)
})
```

**5. Policy/Gate objects**
```php
// Laravel Gate
Gate::define('admin-action', fn($user) => $user->role === 'admin');
// In controller
$this->authorize('admin-action');
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
