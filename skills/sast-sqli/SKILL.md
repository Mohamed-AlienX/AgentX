---
name: sast-sqli
description: >-
  Find SQL injection in source: string concatenation and f-strings building queries,
  unsafe ORM raw and where fragments, dynamic table or column identifiers, and
  unparameterized ORDER BY clauses. Use when asked about SQLi or database injection. Do
  not use for MongoDB or CouchDB operator injection - use hunt-nosqli.
mitre_attack: [T1190, T1078]
---

# SQL Injection (SQLi) Detection

You are performing a focused security assessment to find SQL injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find vulnerable SQL construction sites), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is SQL Injection

SQL injection occurs when user-supplied input is incorporated into SQL queries through string concatenation or interpolation rather than parameterized binding. This allows attackers to alter query logic, bypass authentication, extract sensitive data, modify or delete records, and in some configurations execute OS commands.

The core pattern: *unvalidated, unparameterized user input reaches a SQL query execution call.*

### What SQLi IS

- Concatenating user input directly into a SQL string: `"SELECT * FROM users WHERE name = '" + username + "'"`
- Using string formatting to build queries: `f"SELECT * FROM orders WHERE id = {order_id}"`
- Dynamic `ORDER BY` / `GROUP BY` / table/column names from user input with no allowlist validation
- ORM raw query methods with unsanitized input: `User.objects.raw(f"SELECT * WHERE id={id}")`, `$queryRawUnsafe(input)`
- Second-order injection: input is stored in the DB and later used in a raw query without re-sanitization

### What SQLi is NOT

Do not flag these as SQLi:

- **IDOR**: Changing `?id=1` to `?id=2` to access another user's data — that's Insecure Direct Object Reference, a separate class
- **Mass assignment**: Setting extra ORM model fields from user input — different vulnerability
- **XSS via database**: Storing a `<script>` tag in the DB that's later rendered unescaped — that's XSS, not SQLi
- **NoSQL injection**: Injecting into MongoDB operators — similar concept but a distinct vulnerability class
- **Safe ORM queries**: Parameterized ORM lookups like `User.objects.filter(id=user_id)` or `User.find(params[:id])` — do not flag these

### Patterns That Prevent SQLi

When you see these patterns, the code is likely **not vulnerable**:

**1. Parameterized queries / prepared statements (most common fix)**
```
# Python — cursor.execute with tuple binding
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Node.js — mysql2 / pg placeholder binding
db.query("SELECT * FROM users WHERE id = ?", [userId])
pool.query("SELECT * FROM users WHERE id = $1", [userId])

# Java — PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);

# Go — database/sql placeholder
db.QueryRow("SELECT * FROM users WHERE id = $1", userID)

# PHP — PDO with named params
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);

# C# — SqlCommand with parameters
cmd.CommandText = "SELECT * FROM users WHERE id = @id";
cmd.Parameters.AddWithValue("@id", userId);
```

**2. ORM query builder (safe by default)**
```
# Django ORM
User.objects.filter(id=user_id)

# ActiveRecord (Rails)
User.find(params[:id])
User.where(name: params[:name])

# Prisma (tagged template literal form of $queryRaw)
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`

# Laravel Eloquent (non-raw)
User::find($id)
```

**3. Allowlist validation for dynamic identifiers**
```
# Dynamic ORDER BY — validate column name against a hardcoded set before interpolating
ALLOWED_COLUMNS = {'name', 'created_at', 'price'}
if sort_col not in ALLOWED_COLUMNS:
    raise ValueError("Invalid column")
query = f"SELECT * FROM products ORDER BY {sort_col}"  # safe only after allowlist check
```

---

## Reference index

Deep detail for this skill lives in `references/`; open the file that matches
the task instead of loading everything.

| File | Covers |
|------|--------|
| `references/01-vulnerable-vs-secure-examples.md` | Vulnerable vs. Secure Examples |
| `references/02-execution.md` | Execution; Important Reminders |
