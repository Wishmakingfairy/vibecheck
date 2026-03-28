# Security Headers Checks Reference

4 active checks. HDR-001 through HDR-011 IDs are reserved; the implemented checks are HDR-006, HDR-007, HDR-008, HDR-010.

---

### HDR-006: Server Version Disclosure
- **Severity:** WARNING
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Pattern:** `(?i)(?:x-powered-by|server\s*:\s*['"](?:Express|Apache|nginx|PHP|ASP\.NET)|app\.disable\s*\(\s*['"]x-powered-by['"]\s*\))`
- **Negated by:** `(?i)(?:app\.disable.*x-powered-by|removeHeader.*server|server_tokens\s+off)` — if removal code is present in the same file, the check does not fire.
- **Why:** Disclosing server software and version helps attackers identify known CVEs for that exact version.
- **Fix:**
```js
// Express
app.disable("x-powered-by");

// Or use helmet
const helmet = require("helmet");
app.use(helmet());
```
```nginx
# Nginx
server_tokens off;
```
```apache
# Apache
ServerTokens Prod
ServerSignature Off
```
- **False positives:** Fires if you reference `x-powered-by` in documentation or comments within a server file. Mitigated: the negation pattern suppresses when the header is being explicitly removed in the same file.

---

### HDR-007: Directory Listing Enabled
- **Severity:** WARNING
- **CWE:** CWE-548 (Exposure of Information Through Directory Listing)
- **Pattern:** `(?i)(?:autoindex\s+on|Options\s+\+?Indexes|directory\s*:\s*true|serveIndex)`
- **Why:** Directory listing exposes file structure, backup files, config files, and other assets that should not be publicly enumerable.
- **Fix:**
```nginx
# Nginx
autoindex off;
```
```apache
# Apache
Options -Indexes
```
```js
// Express: remove serve-index or directory listing middleware
// Don't use: app.use(serveIndex('public'))
```
- **False positives:** May trigger on documentation that describes disabling directory listing, or on test configs that intentionally enable it for development. No file-type restriction, so it scans all files.

---

### HDR-008: Debug Mode in Production
- **Severity:** CRITICAL
- **CWE:** CWE-489 (Active Debug Code)
- **Pattern:** `(?i)(?:DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV\s*[:=]\s*['"]?development['"]?.*(?:prod|deploy|server)|app\.debug\s*=\s*True)`
- **File gate:** Only fires when the file path matches `(?i)(?:prod|production|deploy|server\.(?:js|ts|py)|settings\.py|\.env\.prod)`.
- **Why:** Debug mode in production exposes stack traces, internal variables, SQL queries, and application internals to anyone who triggers an error.
- **Fix:**
```python
# Django settings_prod.py
DEBUG = False
```
```bash
# .env.prod
NODE_ENV=production
DEBUG=false
```
```js
// Express
if (process.env.NODE_ENV !== "production") {
  app.use(errorhandler());
}
```
- **False positives:** Mitigated by the file path gate. Will not fire on development config files. Could still fire on files named `server.js` that legitimately set debug for local dev; the path pattern catches `server.js` regardless of environment intent.

---

### HDR-010: Stack Traces in Error Responses
- **Severity:** WARNING
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Pattern (stack trace):** `(?i)(?:err(?:or)?\.stack|stackTrace|traceback|\.stack\s*\)|stack\s*:\s*err)`
- **Pattern (error response):** `(?i)(?:res\.(?:json|send|status)|return.*(?:json|response))`
- **Both must match** in the same file for the check to fire.
- **Why:** Stack traces reveal internal file paths, library versions, database schemas, and code structure that aid exploitation.
- **Fix:**
```js
// Bad
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// Good
app.use((err, req, res, next) => {
  console.error(err.stack); // Log server-side only
  res.status(500).json({ error: "Internal server error" });
});
```
- **False positives:** Triggers when stack trace access and response sending coexist in the same file, even if they are in separate functions (e.g., stack logged in one handler, unrelated response in another). The dual-pattern requirement reduces noise but does not guarantee the stack trace flows into the response.

---

## Reserved IDs (not yet implemented)

The following IDs are reserved for future checks:

| ID | Planned Check |
|----|--------------|
| HDR-001 | Missing Content-Security-Policy |
| HDR-002 | Missing Strict-Transport-Security (HSTS) |
| HDR-003 | Missing X-Content-Type-Options |
| HDR-004 | Missing X-Frame-Options / frame-ancestors |
| HDR-005 | Missing Referrer-Policy |
| HDR-009 | Missing Permissions-Policy |
| HDR-011 | CORS wildcard (*) origin |
