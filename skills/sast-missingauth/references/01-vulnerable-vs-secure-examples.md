<!-- Part of the `sast-missingauth` skill. Open with ../SKILL.md for the overview. -->

## Vulnerable vs. Secure Examples

### Python — Django

```python
# VULNERABLE: No authentication at all
def list_all_users(request):
    users = User.objects.values('id', 'email', 'is_staff')
    return JsonResponse(list(users), safe=False)

# VULNERABLE: Authenticated but no role check
@login_required
def delete_user(request, user_id):
    User.objects.filter(id=user_id).delete()
    return HttpResponse(status=204)

# SECURE
@login_required
def delete_user(request, user_id):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    User.objects.filter(id=user_id).delete()
    return HttpResponse(status=204)
```

### Python — Flask

```python
# VULNERABLE: No auth decorator
@app.route('/admin/users')
def list_users():
    return jsonify([u.to_dict() for u in User.query.all()])

# VULNERABLE: Login required but no role check
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return '', 204

# SECURE
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return '', 204
```

### Node.js — Express

```javascript
// VULNERABLE: No auth middleware
router.get('/api/admin/users', async (req, res) => {
    const users = await User.find({});
    res.json(users);
});

// VULNERABLE: Auth middleware present but no role check
router.delete('/api/admin/users/:id', auth, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.sendStatus(204);
});

// SECURE
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    next();
};
router.delete('/api/admin/users/:id', auth, requireAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.sendStatus(204);
});
```

### Ruby on Rails

```ruby
# VULNERABLE: No before_action
def destroy
    User.find(params[:id]).destroy
    head :no_content
end

# VULNERABLE: Authenticated but no admin check
before_action :authenticate_user!
def destroy
    User.find(params[:id]).destroy
    head :no_content
end

# SECURE
before_action :authenticate_user!
before_action :require_admin

def destroy
    User.find(params[:id]).destroy
    head :no_content
end

private

def require_admin
    head :forbidden unless current_user.admin?
end
```

### Java — Spring Boot

```java
// VULNERABLE: No security annotation
@DeleteMapping("/api/admin/users/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepo.deleteById(id);
    return ResponseEntity.noContent().build();
}

// VULNERABLE: Authenticated but wrong role
@DeleteMapping("/api/admin/users/{id}")
@Secured("ROLE_USER")  // any user can call this
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepo.deleteById(id);
    return ResponseEntity.noContent().build();
}

// SECURE
@DeleteMapping("/api/admin/users/{id}")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    userRepo.deleteById(id);
    return ResponseEntity.noContent().build();
}
```

### Go

```go
// VULNERABLE: No auth middleware on route
r.Delete("/admin/users/{id}", deleteUser)

// VULNERABLE: Auth middleware but no role check in handler
r.With(AuthMiddleware).Delete("/admin/users/{id}", deleteUser)

func deleteUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    db.DeleteUser(id)  // no role check
    w.WriteHeader(http.StatusNoContent)
}

// SECURE
r.Group(func(r chi.Router) {
    r.Use(AuthMiddleware)
    r.Use(AdminOnlyMiddleware)
    r.Delete("/admin/users/{id}", deleteUser)
})
```

### PHP — Laravel

```php
// VULNERABLE: No auth middleware
Route::delete('/admin/users/{id}', [AdminController::class, 'destroy']);

// VULNERABLE: Auth but no role gate
Route::middleware('auth')->delete('/admin/users/{id}', [AdminController::class, 'destroy']);

// SECURE
Route::middleware(['auth', 'role:admin'])->delete('/admin/users/{id}', [AdminController::class, 'destroy']);

// SECURE (using Gate in controller)
public function destroy($id) {
    Gate::authorize('admin-action');
    User::findOrFail($id)->delete();
    return response()->noContent();
}
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: No authorization attribute
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}

// VULNERABLE: [Authorize] but no role
[Authorize]
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}

// SECURE
[Authorize(Roles = "Admin")]
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}
```

---

