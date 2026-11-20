<!-- Part of the `sast-sqli` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — Django (raw SQL)

```python
# VULNERABLE: f-string interpolation in raw()
def search_users(request):
    username = request.GET.get('username')
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
    return JsonResponse(list(users.values()), safe=False)

# SECURE: parameterized raw()
def search_users(request):
    username = request.GET.get('username')
    users = User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
    return JsonResponse(list(users.values()), safe=False)
```

### Python — Flask / SQLAlchemy

```python
# VULNERABLE: f-string into text()
@app.route('/search')
def search():
    name = request.args.get('name')
    result = db.session.execute(text(f"SELECT * FROM products WHERE name = '{name}'"))
    return jsonify(result.fetchall())

# SECURE: named bound parameter
@app.route('/search')
def search():
    name = request.args.get('name')
    result = db.session.execute(
        text("SELECT * FROM products WHERE name = :name"), {"name": name}
    )
    return jsonify(result.fetchall())
```

### Python — sqlite3 / psycopg2

```python
# VULNERABLE
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()

# SECURE
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
```

### Node.js — mysql2

```javascript
// VULNERABLE: template literal in query string
app.get('/user', async (req, res) => {
  const { id } = req.query;
  const [rows] = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows);
});

// SECURE: placeholder binding
app.get('/user', async (req, res) => {
  const { id } = req.query;
  const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  res.json(rows);
});
```

### Node.js — pg (PostgreSQL)

```javascript
// VULNERABLE
app.get('/orders', async (req, res) => {
  const status = req.query.status;
  const result = await pool.query(`SELECT * FROM orders WHERE status = '${status}'`);
  res.json(result.rows);
});

// SECURE
app.get('/orders', async (req, res) => {
  const status = req.query.status;
  const result = await pool.query('SELECT * FROM orders WHERE status = $1', [status]);
  res.json(result.rows);
});
```

### Ruby on Rails

```ruby
# VULNERABLE: string interpolation in where()
def search
  @users = User.where("name = '#{params[:name]}'")
end

# VULNERABLE: find_by_sql with interpolation
def find_user
  @user = User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
end

# SECURE: parameterized where()
def search
  @users = User.where("name = ?", params[:name])
  # or using hash form: User.where(name: params[:name])
end
```

### Java — Spring JDBC

```java
// VULNERABLE: string concatenation
public User findUser(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, userRowMapper);
}

// SECURE: parameterized query
public User findUser(String username) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM users WHERE username = ?", userRowMapper, username
    );
}
```

### Go — database/sql

```go
// VULNERABLE: fmt.Sprintf to build query
func GetUserByName(name string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    row := db.QueryRow(query)
    // ...
}

// SECURE: parameterized query
func GetUserByName(name string) (*User, error) {
    row := db.QueryRow("SELECT * FROM users WHERE name = $1", name)
    // ...
}
```

### PHP — PDO

```php
// VULNERABLE: string concatenation
function getUser($id) {
    $stmt = $pdo->query("SELECT * FROM users WHERE id = " . $id);
    return $stmt->fetch();
}

// SECURE: prepared statement
function getUser($id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    return $stmt->fetch();
}
```

### C# — ADO.NET

```csharp
// VULNERABLE: string concatenation
public User GetUser(string username) {
    using var cmd = new SqlCommand(
        "SELECT * FROM Users WHERE Username = '" + username + "'", conn);
    return ReadUser(cmd.ExecuteReader());
}

// SECURE: parameterized command
public User GetUser(string username) {
    using var cmd = new SqlCommand(
        "SELECT * FROM Users WHERE Username = @username", conn);
    cmd.Parameters.AddWithValue("@username", username);
    return ReadUser(cmd.ExecuteReader());
}
```

### Dynamic ORDER BY / Column Names (all stacks)

```python
# VULNERABLE: unsanitized user input as column name (parameterization can't help here)
sort_col = request.args.get('sort', 'name')
cursor.execute(f"SELECT * FROM products ORDER BY {sort_col}")

# SECURE: allowlist validation before interpolation
ALLOWED_SORT_COLS = {'name', 'price', 'created_at'}
sort_col = request.args.get('sort', 'name')
if sort_col not in ALLOWED_SORT_COLS:
    return abort(400)
cursor.execute(f"SELECT * FROM products ORDER BY {sort_col}")
```

---

