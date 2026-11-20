<!-- Part of the `sast-missingauth` skill. Open with ../SKILL.md for the overview. -->

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Map Endpoints and Permission System

Launch a subagent with the following instructions:

> **Goal**: Build a complete map of (1) all application endpoints/routes and their current authentication/authorization posture, and (2) the role/permission system. Write results to `sast/missingauth-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, route definitions, and the auth/authz strategy.
>
> **What to search for**:
>
> 1. **All route/endpoint definitions** — collect every HTTP handler, REST endpoint, GraphQL mutation/query, RPC method, or WebSocket handler:
>    - Express/Koa: `router.get/post/put/delete/patch/use`
>    - Django: `urlpatterns`, `path()`, `re_path()`
>    - Flask: `@app.route`, `@blueprint.route`
>    - Rails: `routes.rb` — `get`, `post`, `resources`, `namespace`
>    - Spring: `@GetMapping`, `@PostMapping`, `@RequestMapping`, `@DeleteMapping`, `@PutMapping`
>    - Go/Chi: `r.Get`, `r.Post`, `r.Delete`, `r.Handle`
>    - Laravel: `Route::get/post/put/delete`
>    - FastAPI: `@router.get/post/put/delete`
>    - ASP.NET: `[HttpGet]`, `[HttpPost]`, `[HttpDelete]`, `[HttpPut]`
>
> 2. **Authentication middleware and decorators** currently applied:
>    - Identify the pattern used: `@login_required`, `auth` middleware, `[Authorize]`, `authenticate_user!`, JWT verification middleware, session checks
>    - Note which routes or route groups they are applied to
>    - Note any routes explicitly excluded from auth (e.g., `except: [:index, :show]`)
>
> 3. **Role/permission system** — identify how roles are defined and checked:
>    - Role constants/enums: `ROLE_ADMIN`, `'admin'`, `UserRole.ADMIN`, `is_staff`, `is_superuser`
>    - Permission decorators: `@admin_required`, `@roles_required`, `@PreAuthorize`, `requireRole()`
>    - Middleware: `AdminOnly`, `requireAdmin`, `role:admin`
>    - Policy/Gate/Ability objects: `Gate::define`, `Policy`, `CanCanCan`, `Pundit`
>    - In-handler checks: `if user.role != 'admin'`, `if not current_user.is_admin`
>
> 4. **Sensitive/privileged endpoints** to flag — any endpoint that:
>    - Has an `/admin`, `/management`, `/internal`, `/api/admin`, `/superadmin`, `/system`, `/ops` path prefix
>    - Performs user management: create/update/delete users, change roles, reset passwords for others
>    - Manages application configuration: settings, feature flags, SMTP, secrets, environment variables
>    - Accesses financial/billing data: invoices, payments, subscriptions for all users
>    - Triggers system actions: sending emails to all users, running background jobs, clearing caches
>    - Returns aggregate or sensitive data: all users, all orders, audit logs, error logs
>
> 5. **For each endpoint, note**:
>    - Whether an auth middleware/decorator is present
>    - Whether a role/permission check is present
>    - The HTTP method(s) it handles
>    - Whether it reads, writes, or deletes data
>
> **What to ignore**:
> - Publicly intended endpoints: login, register, password reset request, public content (blog posts, product listings)
> - Static asset serving, health-check endpoints (`/health`, `/ping`, `/status`)
>
> **Output format** — write to `sast/missingauth-recon.md`:
>
> ```markdown
> # Missing Auth Recon: [Project Name]
>
> ## Permission System Summary
> - Roles identified: [list roles, e.g. admin, moderator, user]
> - Auth mechanism: [JWT / session / API key / OAuth]
> - Auth decorators/middleware: [list names, e.g. @login_required, auth, requireAdmin]
>
> ## Endpoint Inventory
>
> ### 1. [Endpoint name / description]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Operation**: [read / write / delete / admin-action]
> - **Auth present**: [yes / no]
> - **Role check present**: [yes / no / partial]
> - **Code snippet**:
>   ```
>   [route registration + handler signature]
>   ```
>
> [Repeat for each endpoint]
> ```

### Phase 2: Verify — Check Authentication and Authorization (Batched)

After Phase 1 completes, read `sast/missingauth-recon.md` and split the endpoint inventory into **batches of up to 3 endpoints each** (each numbered `### N.` under **Endpoint Inventory**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned endpoints and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/missingauth-recon.md` and count the numbered endpoint sections under **Endpoint Inventory** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 8 endpoints → 3 batches (1–3, 4–6, 7–8).
3. For each batch, extract the full text of those endpoint sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned endpoints.
5. Each subagent writes to `sast/missingauth-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Python/Django, include only the "Python — Django" (and if relevant, Flask) examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: Verify the following endpoints for missing authentication and broken function-level authorization vulnerabilities. Write results to `sast/missingauth-batch-[N].md`.
>
> **Your assigned endpoints** (from the recon phase):
>
> [Paste the full text of the assigned endpoint sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the middleware ordering, role definitions, and auth patterns.
>
> **Missing auth / broken function-level auth — what to look for**:
>
> - **Missing authentication**: Sensitive action with no login/session/token required.
> - **Broken function-level authorization**: Authentication is required but no role/permission check on a privileged endpoint (vertical escalation).
>
> **What this skill is NOT** — do not flag these here:
> - **IDOR / horizontal escalation**: User A accessing user B's resource by changing an ID → covered by the IDOR skill.
> - **JWT crypto/verification bugs** → covered by sast-jwt.
>
> **Authorization patterns that PREVENT issues** — if you see these, the endpoint is likely safe:
> 1. **Authentication + role-check middleware on a route group** (e.g., `router.use('/admin', auth, requireRole('admin'))`)
> 2. **Declarative role annotations** (e.g., `@PreAuthorize("hasRole('ADMIN')")`)
> 3. **In-handler role check** before sensitive action
> 4. **Middleware gate on entire prefix** (e.g., Chi `r.Group` with `AdminOnly`)
> 5. **Policy/Gate** objects enforcing privileged actions
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned endpoint, evaluate**:
>
> 1. **Authentication check** — is a valid login/session/token required?
>    - Is there an auth middleware, decorator, or guard on this route or its parent group?
>    - Trace the middleware chain — confirm the auth middleware runs BEFORE the handler, not after
>    - Check if the route is accidentally mounted outside an auth-protected group
>
> 2. **Role/permission check** — if the endpoint is privileged, is a role or permission verified?
>    - Look for: `is_admin`, `is_staff`, `role == 'admin'`, `hasRole('ADMIN')`, `@PreAuthorize`, `requireRole`, `can?(:manage, ...)`, `Gate::allows`, `authorize('admin-action')`
>    - Verify the check runs on every HTTP method — a DELETE may be unguarded even if GET is protected
>    - Check that the role comparison is not inverted or trivially bypassable
>
> 3. **Edge cases**:
>    - Is the check conditional on a user-controlled header, parameter, or query string?
>    - Does the auth gate apply to the route group but the specific route is excluded via an `except` list?
>    - Is there a secondary unauthenticated path to the same function (e.g., an internal API alias)?
>    - Does the middleware apply only to some environments (e.g., skipped in test mode)?
>
> 4. **Privilege identification**:
>    - Does the endpoint path suggest it is admin/privileged (`/admin/`, `/manage/`, `/internal/`)?
>    - Does the operation affect other users' data, system configuration, or aggregate records?
>    - If yes to either, a role/permission check should be present
>
> **Classification**:
> - **Vulnerable**: No authentication required, or authenticated but role check is entirely absent on a privileged endpoint.
> - **Likely Vulnerable**: Auth and/or role check exists but appears incomplete, bypassable, or misapplied (e.g., wrong role, wrong HTTP method, conditional skip).
> - **Not Vulnerable**: Proper authentication and role/permission checks are in place.
> - **Needs Manual Review**: Cannot determine with confidence (e.g., complex middleware chain, dynamic role loading, authorization delegated to a service layer).
>
> **Output format** — write to `sast/missingauth-batch-[N].md`:
>
> ```markdown
> # Missing Auth Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Issue**: [Missing authentication / Missing role check for privileged action]
> - **Impact**: [What an unauthenticated or low-privilege attacker can do]
> - **Proof**: [Show the route definition and handler — highlight the missing check]
> - **Remediation**: [Specific fix — add auth middleware, add role decorator, etc.]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step to confirm on the live app.
>    For missing auth: show the request with NO token succeeding.
>    For missing role: show the request with a regular user token succeeding on an admin endpoint.
>    Use placeholders like <REGULAR_USER_TOKEN>, <ADMIN_ENDPOINT>.]
>   ```
>
> ### [LIKELY VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Issue**: [What's incomplete about the check]
> - **Concern**: [Why this might still be exploitable]
> - **Proof**: [Show the code path with the weak/partial check]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step instructions to confirm this finding on the live app.]
>   ```
>
> ### [NOT VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Protection**: [How it's protected — auth middleware + role decorator / @PreAuthorize / Gate, etc.]
>
> ### [NEEDS MANUAL REVIEW] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Uncertainty**: [Why automated analysis couldn't determine the status]
> - **Suggestion**: [What to look at manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/missingauth-batch-*.md` file and merge them into a single `sast/missingauth-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/missingauth-batch-1.md`, `sast/missingauth-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/missingauth-results.md` using this format:

```markdown
# Missing Auth/Authz Analysis Results: [Project Name]

## Executive Summary
- Endpoints analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/missingauth-results.md`, **delete all intermediate files**: `sast/missingauth-recon.md` and `sast/missingauth-batch-*.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 endpoints per subagent**. If there are 1–3 endpoints total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned endpoints' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- Focus on **vertical privilege escalation** (user → admin) and **unauthenticated access**. Horizontal escalation (user A → user B's resource) is covered by the IDOR skill.
- Authentication (you are who you say you are) and authorization (you are allowed to do this) are separate concerns — check both.
- Middleware order matters: a middleware registered after the route handler will NOT protect the route.
- A missing auth or role check on one HTTP method (e.g., DELETE) is a full vulnerability even if GET is protected.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Pay attention to route grouping: a `use('/admin', adminRouter)` pattern protects all routes in `adminRouter`, but routes mounted outside that group are not protected.
- Clean up intermediate files: delete `sast/missingauth-recon.md` and all `sast/missingauth-batch-*.md` files after the final `sast/missingauth-results.md` is written.
