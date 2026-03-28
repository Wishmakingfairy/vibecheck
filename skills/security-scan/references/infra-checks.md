# Infrastructure Checks Reference

6 active checks out of 10 reserved IDs: INF-001, INF-002, INF-003, INF-004, INF-006, INF-010.

---

### INF-001: Debug Endpoint Exposed
- **Severity:** WARNING
- **CWE:** CWE-489 (Active Debug Code)
- **Pattern:** `(?i)(?:app|router)\s*\.\s*(?:get|post|all)\s*\(\s*['"](?:/debug|/test|/__debug|/phpinfo|/server-info|/health-check-internal)['"]`
- **Why:** Debug endpoints expose internal application state, environment variables, database connections, and memory contents. Attackers use them for reconnaissance.
- **Fix:**
```js
// Bad
app.get("/debug", (req, res) => {
  res.json({ env: process.env, memory: process.memoryUsage() });
});

// Good - guard behind environment check
if (process.env.NODE_ENV === "development") {
  app.get("/debug", (req, res) => {
    res.json({ env: process.env });
  });
}

// Better - remove entirely from production code
```
- **False positives:** Fires on any route matching the listed paths, even if the handler is empty or returns harmless data. Also fires on routes that are properly guarded by auth middleware if the guard is not in the same file. The pattern only checks the route definition, not surrounding context beyond the path string.

---

### INF-002: Source Maps in Production Config
- **Severity:** WARNING
- **CWE:** CWE-540 (Inclusion of Sensitive Information in Source Code)
- **Pattern:** `(?i)(?:sourcemap|source-map|devtool)\s*[:=]\s*(?:true|['"](?:source-map|eval-source-map|cheap-module-source-map)['"])`
- **File gate:** Only fires when the file path matches `(?i)(?:prod|production|webpack\.prod|vite\.config)`.
- **Why:** Source maps in production let anyone reconstruct your original source code, including comments, variable names, and business logic.
- **Fix:**
```js
// webpack.prod.js
module.exports = {
  devtool: false, // No source maps in production
};
```
```js
// vite.config.js
export default defineConfig({
  build: {
    sourcemap: false, // Or 'hidden' for error tracking only
  },
});
```
- **False positives:** The file gate is broad; `vite.config` triggers regardless of whether it is used for dev or prod. A unified config file that conditionally enables source maps will fire. Mitigated: most projects use separate prod configs or environment conditionals.

---

### INF-003: .env File in Public Directory
- **Severity:** CRITICAL
- **CWE:** CWE-538 (Insertion of Sensitive Information into Externally-Accessible File or Directory)
- **Pattern:** `(?i)(?:public|static|dist|build|www|htdocs|web)/\.env`
- **Trigger:** Matches against the file path, not file content.
- **Why:** A `.env` file in a publicly served directory is downloadable by anyone. It typically contains database credentials, API keys, and secrets.
- **Fix:**
```bash
# Move .env to project root (outside public directories)
mv public/.env ./.env

# Add to .gitignore
echo ".env" >> .gitignore

# Block dotfiles in your web server
# Nginx
location ~ /\. { deny all; }

# Apache
<FilesMatch "^\.">
  Require all denied
</FilesMatch>
```
- **False positives:** Fires on any file path matching the pattern, including `.env.example` files in public directories (which should not contain real secrets but still match). Also fires on references to `.env` paths in config files if the path string matches.

---

### INF-004: Docker Container Running as Root
- **Severity:** WARNING
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Pattern (FROM):** `^FROM\s+` (multiline) — confirms this is a Dockerfile.
- **Pattern (USER):** `(?i)(?:^USER\s+\w+|user:\s+\w+)` (multiline) — if this is absent, the check fires.
- **File gate:** Only fires on files with `Dockerfile` or `dockerfile` in their path.
- **Why:** Containers default to running as root. If an attacker escapes the application, they have root access to the container and potentially the host via privilege escalation.
- **Fix:**
```dockerfile
FROM node:20-alpine

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory and copy files
WORKDIR /app
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

CMD ["node", "server.js"]
```
- **False positives:** Multi-stage builds may have a `USER` directive only in the final stage. The check searches the entire file content, so a `USER` in any stage suppresses the finding. Also, `user:` in a YAML-like comment within the Dockerfile would suppress it.

---

### INF-006: Admin Panel Without Authentication
- **Severity:** CRITICAL
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Pattern (admin route):** `(?i)(?:app|router)\s*\.(?:use|get|post)\s*\(\s*['"](?:/admin|/dashboard|/cms|/panel|/internal)`
- **Pattern (auth):** `(?i)(?:auth|authenticate|isAdmin|requireRole|protect|middleware|guard|@login_required)` — if present in the same file, the check does not fire.
- **Why:** An unauthenticated admin panel gives attackers full control over your application, data, and users.
- **Fix:**
```js
// Bad
app.use("/admin", adminRouter);

// Good
app.use("/admin", requireAuth, requireRole("admin"), adminRouter);
```
```python
# Django
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_view(request):
    ...
```
- **False positives:** The auth check looks for any auth-related keyword anywhere in the file. A file that imports `auth` for a different route will suppress the finding for the admin route. Conversely, a file where auth middleware is applied in a separate file (e.g., at the router level) will still trigger.

---

### INF-010: CI/CD Write-All Permissions
- **Severity:** WARNING
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Pattern:** `permissions\s*:\s*write-all` (case-insensitive)
- **Why:** `write-all` gives a workflow full write access to repository contents, packages, actions, and more. A compromised workflow or malicious PR can modify code, create releases, or steal secrets.
- **Fix:**
```yaml
# Bad
permissions: write-all

# Good - least privilege
permissions:
  contents: read
  packages: write
  pull-requests: write
```
- **False positives:** May fire on documentation or comments that mention `write-all`. No file-type gate, so it scans all files. The pattern is simple enough that accidental matches are rare outside YAML workflow files.

---

## Reserved IDs (not yet implemented)

| ID | Planned Check |
|----|--------------|
| INF-005 | Secrets in Docker build args |
| INF-007 | Open database port binding (0.0.0.0:5432) |
| INF-008 | Missing health check in container |
| INF-009 | Privileged container mode |
