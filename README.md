# 0xguard

**Stop shipping vulnerabilities. 156 automated security checks for Claude Code.**

0xguard blocks exposed API keys, disabled Supabase RLS, missing rate limiting, open CORS, prompt injection, and 150+ more security issues **before they reach your codebase**.

Unlike audit tools that find problems after the fact, 0xguard intercepts dangerous patterns in real-time via PreToolUse hooks and blocks them before Claude writes them to disk.

## Install

```bash
claude plugin add /path/to/0xguard
```

That's it. 0xguard starts protecting immediately. No configuration needed.

## What It Catches

### Real examples of code AI tools generate that 0xguard blocks:

**Your API keys are in the frontend bundle:**
```javascript
// BLOCKED by SEC-005
const VITE_SECRET_KEY = "sk_live_abc123..."
```
Fix: Move to server-side environment variable.

**Your Supabase has no Row Level Security:**
```sql
-- BLOCKED by DB-001
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
```
Fix: Keep RLS enabled, add policies.

**Anyone can brute-force your login:**
```javascript
// WARNED by AUTH-001
app.post("/api/auth/login", async (req, res) => { ... })
// No rate limiting middleware
```
Fix: Add `rateLimit({ windowMs: 15*60*1000, max: 5 })`.

**Every website can make requests on behalf of your users:**
```javascript
// BLOCKED by NET-001
cors({ origin: "*" })
```
Fix: Set specific allowed origins.

**Your JWT tokens never expire:**
```javascript
// BLOCKED by AUTH-007
jwt.sign(payload, secret)
// No expiresIn
```
Fix: Add `{ expiresIn: "1h" }`.

## 156 Checks Across 15 Categories

| Category | Checks | What It Catches |
|----------|--------|-----------------|
| Secrets & API Keys | 22 | AWS keys, Stripe keys, GitHub tokens, .env without .gitignore, service account JSON |
| Authentication | 20 | JWT without expiry, no rate limiting, OAuth CSRF, weak passwords, localStorage tokens |
| Database Security | 20 | Supabase RLS disabled, SQL injection, mass assignment, NoSQL injection, admin routes |
| Network & CORS | 11 | CORS wildcard, SSRF (incl. IPv6/metadata), open redirects, mixed content |
| Injection | 21 | XSS in React/Vue/Angular/Svelte, command injection, path traversal, prototype pollution |
| Security Headers | 11 | Debug mode in prod, missing CSP/HSTS, stack traces in responses, directory listing |
| Supply Chain | 15 | Typosquatted packages, unpinned GitHub Actions, curl pipe to shell, malicious packages |
| Infrastructure | 10 | .env in public/, Docker as root, admin without auth, source maps in prod |
| AI/LLM Security | 16 | API keys in frontend, system prompt exposure, prompt injection, no token limits |
| Cryptography | 12 | MD5 for passwords, Math.random() for tokens, weak PBKDF2, ECB mode, timing attacks |
| Privacy | 8 | PII in logs, credit cards in code, user data in error responses |
| Business Logic | 6 | Race conditions, missing idempotency, enumeration attacks |
| Logging | 5 | Passwords in logs, log injection, sensitive data logged |
| File System | 5 | Path traversal, zip slip, chmod 777, symlink attacks |
| WebSocket | 4 | No auth, missing origin validation, no message size limits |

**68 unique CWE IDs mapped** for compliance reporting.

## How It Works

0xguard runs as a PreToolUse hook on every Write/Edit/MultiEdit operation:

1. Claude tries to write a file
2. 0xguard intercepts the content
3. Loads only the relevant checker modules (based on file extension)
4. Scans for patterns matching 156 known vulnerabilities
5. **CRITICAL**: Blocks the write, shows the fix
6. **WARNING**: Warns but allows
7. **INFO**: Silent (only in full scan mode)

Average hook latency: **~120ms** per write operation.

## Severity Levels

| Level | Behavior | Example |
|-------|----------|---------|
| CRITICAL | **Blocks** the write | Hardcoded API key, RLS disabled, SQL injection |
| WARNING | Warns, allows write | JWT in localStorage, missing rate limiting |
| INFO | Silent in hook, shows in scan | Missing MFA, no structured logging |

## Smart Features

**Test file awareness**: Files matching `*.test.*`, `*.spec.*`, `__tests__/` automatically downgrade CRITICAL to WARNING. Your test fixtures won't trigger false positives.

**DOMPurify detection**: `dangerouslySetInnerHTML` is only flagged if DOMPurify is not imported in the same file.

**Public API awareness**: CORS wildcard (`*`) is not flagged if public API patterns are detected.

**Inline suppression**: Override any check when you know what you're doing:
```javascript
// 0xguard-disable SEC-001
const testKey = "AKIA1234567890EXAMPLE"; // Test fixture
```

## Configuration

Create `.0xguard.json` in your project root (optional):

```json
{
  "severity_overrides": {
    "NET-001": "WARNING"
  },
  "disabled": [],
  "ignore_paths": ["**/*.test.*", "**/fixtures/**"],
  "inline_suppression": true,
  "framework": "auto"
}
```

## Skills Included

| Skill | Trigger | What It Does |
|-------|---------|-------------|
| `security-scan` | "security scan", "vulnerability check" | Full codebase audit with categorized report |
| `secure-keys` | "secure API keys", "handle secrets" | Teaches framework-specific secret management |
| `secure-auth` | "secure login", "rate limiting" | Authentication hardening patterns |
| `secure-deploy` | "deploy securely", "pre-launch check" | Pre-deployment security checklist |

## Agent

The **security-scanner** agent performs deep codebase analysis including dependency auditing and cross-file middleware verification.

## CWE Mapping

Every check maps to a Common Weakness Enumeration (CWE) ID:

| CWE | Description | Checks |
|-----|-------------|--------|
| CWE-798 | Hardcoded credentials | SEC-001 to SEC-022 |
| CWE-89 | SQL injection | DB-002, DB-003, DB-013 |
| CWE-79 | Cross-site scripting | INJ-001 to INJ-005 |
| CWE-862 | Missing authorization | DB-001, DB-007, DB-010 |
| CWE-918 | SSRF | NET-009, SEC-020 |
| CWE-352 | CSRF | AUTH-010, AUTH-015 |
| ... | [68 total CWEs] | |

## Author

**Haralds Gabrans** ([GitHub](https://github.com/haraldsgabrans))

## License

MIT
