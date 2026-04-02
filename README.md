<p align="center">
  <h1 align="center">vibecheck</h1>
  <p align="center"><strong>Vibe code. Vibe check. 156 security checks for Claude Code.</strong></p>
  <p align="center">Blocks dangerous patterns <em>before</em> Claude writes them to disk.</p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/security_checks-156-blue?style=flat-square" alt="156 checks" />
  <img src="https://img.shields.io/badge/CWE_coverage-68_IDs-orange?style=flat-square" alt="68 CWEs" />
  <img src="https://img.shields.io/badge/avg_latency-88ms-brightgreen?style=flat-square" alt="88ms latency" />
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square" alt="Zero dependencies" />
  <img src="https://img.shields.io/github/license/Wishmakingfairy/vibecheck?style=flat-square" alt="MIT License" />
</p>

---

## The Problem

AI coding tools generate insecure code by default. Supabase schemas without RLS. API keys in frontend bundles. JWT tokens that never expire. CORS open to the world. Passwords hashed with MD5.

Audit tools find these problems **after the fact**. vibecheck finds them **before they exist**.

```
You:        "Create a Stripe integration"
Claude:     const stripe = require("stripe")("sk_live_51H7abc123...");
vibecheck:  BLOCKED. Stripe live key hardcoded. Use process.env.STRIPE_SECRET_KEY.
Claude:     Rewrites with environment variable.
```

The vulnerability never reaches your codebase.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Demo](#demo)
- [156 Checks, 15 Categories](#156-checks-15-categories)
- [How It Works](#how-it-works)
- [Smart Detection](#smart-detection)
- [Configuration](#configuration)
- [Skills and Agent](#skills-and-agent)
- [CWE Mapping](#cwe-mapping)
- [File Structure](#file-structure)
- [Requirements](#requirements)
- [Comparison](#how-vibecheck-compares)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Quick Start

**1. Clone**
```bash
git clone https://github.com/Wishmakingfairy/vibecheck.git ~/.claude/plugins/vibecheck
```

**2. Install**
```bash
claude plugin add ~/.claude/plugins/vibecheck
```

**3. Build with confidence.** Every file Claude writes now goes through 156 security checks. Zero configuration needed.

---

## Demo

Here is what happens when Claude tries to write insecure code with vibecheck installed:

```
$ echo '{"tool_name":"Write","tool_input":{"file_path":"app.js",
  "content":"const stripe = require(\"stripe\")(\"sk_live_abc123\");"}}' | python3 hooks/security_gate.py
```

```
BLOCKED this write. Security vulnerabilities detected:

  [SEC-004] Secrets & API Keys | Stripe live secret key detected.
  Use environment variables: process.env.STRIPE_SECRET_KEY.
  CWE: CWE-798

  Suppress if intentional: // vibecheck-disable SEC-004
```

```
$ echo '{"tool_name":"Write","tool_input":{"file_path":"schema.sql",
  "content":"ALTER TABLE users DISABLE ROW LEVEL SECURITY;"}}' | python3 hooks/security_gate.py
```

```
BLOCKED this write. Security vulnerabilities detected:

  [DB-001] Database Security | Row Level Security (RLS) is being DISABLED.
  Keep RLS enabled. Create policies for granular access control.
  CWE: CWE-862
```

```
$ echo '{"tool_name":"Write","tool_input":{"file_path":"utils.js",
  "content":"crypto.createHash(\"md5\").update(password).digest(\"hex\")"}}' | python3 hooks/security_gate.py
```

```
BLOCKED this write. Security vulnerabilities detected:

  [CRYPTO-001] Cryptography | MD5 used for password hashing.
  Use bcrypt: const hash = await bcrypt.hash(password, 12)
  CWE: CWE-328
```

Every block includes: what is wrong, how to fix it, and the CWE ID.

---

## 156 Checks, 15 Categories

| Category | # | Examples |
|:---------|:-:|:---------|
| **Secrets & API Keys** | 22 | AWS keys, Stripe keys, GitHub tokens, .env without .gitignore, service account JSON, high-entropy strings |
| **Authentication** | 20 | JWT without expiry, no rate limiting, OAuth CSRF, weak passwords, localStorage tokens |
| **Database Security** | 20 | Supabase RLS disabled, SQL injection, mass assignment, NoSQL injection, GraphQL depth |
| **Network & CORS** | 11 | CORS wildcard, SSRF (IPv6/metadata), open redirects, mixed content |
| **Injection** | 21 | XSS in React/Vue/Angular/Svelte, command injection, path traversal, prototype pollution |
| **Security Headers** | 11 | Debug mode in prod, stack traces in responses, directory listing, server version |
| **Supply Chain** | 15 | Typosquatted packages, unpinned GitHub Actions, curl|sh, malicious packages |
| **Infrastructure** | 10 | .env in public/, Docker as root, admin without auth, source maps in prod |
| **AI/LLM Security** | 16 | API keys in frontend, system prompt exposure, prompt injection, streaming as HTML |
| **Cryptography** | 12 | MD5 for passwords, Math.random() for tokens, ECB mode, timing attacks |
| **Privacy** | 8 | PII in logs, credit cards in code, user data in error responses |
| **Business Logic** | 6 | Race conditions, missing idempotency, enumeration attacks |
| **Logging** | 5 | Passwords in logs, log injection, console.log with secrets |
| **File System** | 5 | Path traversal, zip slip, chmod 777, symlink attacks |
| **WebSocket** | 4 | No auth, missing origin validation, no message size limits |

<details>
<summary><strong>Full check reference (all 156 IDs)</strong></summary>

### Secrets & API Keys (SEC)
| ID | What | Severity |
|:---|:-----|:---------|
| SEC-001 | AWS access keys (AKIA pattern) | CRITICAL |
| SEC-002 | AWS secret access keys | CRITICAL |
| SEC-003 | GitHub tokens (ghp/gho/ghu/ghs/ghr) | CRITICAL |
| SEC-004 | Stripe live secret keys (sk_live) | CRITICAL |
| SEC-005 | Frontend env vars exposing secrets (NEXT_PUBLIC/VITE/REACT_APP) | CRITICAL |
| SEC-006 | Hardcoded passwords in assignments | CRITICAL |
| SEC-007 | Private key content (RSA/EC/DSA/SSH) | CRITICAL |
| SEC-008 | JWT secret hardcoded | CRITICAL |
| SEC-009 | Database connection strings with credentials | CRITICAL |
| SEC-010 | Webhook secrets in source | WARNING |
| SEC-011 | API keys in URL query parameters | WARNING |
| SEC-012 | Secrets in Docker ENV directives | CRITICAL |
| SEC-013 | High-entropy strings near assignments (Shannon > 4.5) | WARNING |
| SEC-014 | Secrets in code comments | WARNING |
| SEC-015 | Default credentials (admin:admin, root:root) | CRITICAL |
| SEC-016 | .env file written without .gitignore entry | CRITICAL |
| SEC-017 | Secrets in Terraform/IaC variables | CRITICAL |
| SEC-018 | Secrets in GitHub Actions workflows | CRITICAL |
| SEC-019 | Secrets in Kubernetes manifests | CRITICAL |
| SEC-020 | Cloud metadata endpoint patterns | CRITICAL |
| SEC-021 | Supabase service_role key in frontend | CRITICAL |
| SEC-022 | Google/Firebase service account JSON | CRITICAL |

### Authentication (AUTH)
| ID | What | Severity |
|:---|:-----|:---------|
| AUTH-001 | Login route without rate limiting | WARNING |
| AUTH-002 | Missing brute-force protection | WARNING |
| AUTH-003 | Weak password regex (< 8 chars) | WARNING |
| AUTH-004 | No MFA on sensitive routes | INFO |
| AUTH-005 | Session not regenerated after login | WARNING |
| AUTH-006 | Missing session expiry | WARNING |
| AUTH-007 | JWT.sign without expiresIn | CRITICAL |
| AUTH-008 | JWT algorithm set to "none" | CRITICAL |
| AUTH-009 | JWT stored in localStorage | WARNING |
| AUTH-010 | Forms without CSRF token | WARNING |
| AUTH-011 | Password reset token without expiry | WARNING |
| AUTH-012 | No account lockout | INFO |
| AUTH-013 | Direct object reference without auth | WARNING |
| AUTH-014 | Missing role check on admin routes | INFO |
| AUTH-015 | OAuth missing state parameter | CRITICAL |
| AUTH-016 | Cookies missing Secure/HttpOnly/SameSite | WARNING |
| AUTH-017 | Password in reversible encryption | CRITICAL |
| AUTH-018 | Missing re-auth for sensitive ops | WARNING |
| AUTH-019 | Refresh token rotation missing | WARNING |
| AUTH-020 | Magic link tokens without expiry | WARNING |

### Database (DB)
| ID | What | Severity |
|:---|:-----|:---------|
| DB-001 | Supabase RLS disabled | CRITICAL |
| DB-002 | SQL string concatenation | CRITICAL |
| DB-003 | Missing parameterized queries | WARNING |
| DB-004 | Database credentials in frontend | CRITICAL |
| DB-005 | Missing input validation before query | WARNING |
| DB-006 | GRANT ALL PRIVILEGES | WARNING |
| DB-007 | CREATE TABLE without RLS | WARNING |
| DB-008 | Unencrypted backups | INFO |
| DB-009 | Missing audit logging | INFO |
| DB-010 | GraphQL resolver without auth | WARNING |
| DB-011 | NoSQL injection ($where, $regex) | CRITICAL |
| DB-012 | Missing encryption at rest | INFO |
| DB-013 | Prisma $queryRaw / Drizzle raw SQL | CRITICAL |
| DB-014 | Missing foreign key on user_id | INFO |
| DB-015 | Admin routes without auth | CRITICAL |
| DB-016 | Mass assignment (req.body to ORM) | WARNING |
| DB-017 | Missing pagination (unbounded queries) | WARNING |
| DB-018 | GraphQL without depth limit | WARNING |
| DB-019 | No connection pooling | INFO |
| DB-020 | Supabase Realtime without RLS | WARNING |

### Network & CORS (NET)
| ID | What | Severity |
|:---|:-----|:---------|
| NET-001 | CORS origin: * | CRITICAL |
| NET-002 | CORS credentials with wildcard | CRITICAL |
| NET-003 | Overly permissive CORS methods | WARNING |
| NET-004 | Missing HTTPS redirect | WARNING |
| NET-005 | Missing HSTS | WARNING |
| NET-006 | Mixed content (HTTP on HTTPS) | WARNING |
| NET-007 | Missing cert pinning for mobile | INFO |
| NET-008 | Open redirect | WARNING |
| NET-009 | SSRF (unvalidated URL fetch) | CRITICAL |
| NET-010 | Missing origin validation | WARNING |
| NET-011 | Binding to 0.0.0.0 in prod | WARNING |

### Injection (INJ)
| ID | What | Severity |
|:---|:-----|:---------|
| INJ-001 | dangerouslySetInnerHTML (without DOMPurify) | CRITICAL |
| INJ-002 | innerHTML with variable | CRITICAL |
| INJ-003 | Vue v-html | CRITICAL |
| INJ-004 | Angular [innerHTML] | CRITICAL |
| INJ-005 | Svelte {@html} | CRITICAL |
| INJ-006 | Command injection (exec/spawn) | CRITICAL |
| INJ-007 | Path traversal (../) | CRITICAL |
| INJ-008 | Template literal in SQL/shell | WARNING |
| INJ-009 | LDAP injection | CRITICAL |
| INJ-010 | XXE (XML external entities) | CRITICAL |
| INJ-011 | Unsafe deserialization (pickle, yaml.load) | CRITICAL |
| INJ-012 | Missing Content-Type validation | WARNING |
| INJ-013 | File upload without type whitelist | WARNING |
| INJ-014 | File upload without size limit | WARNING |
| INJ-015 | ReDoS vulnerable regex | WARNING |
| INJ-016 | Header injection | WARNING |
| INJ-017 | Prototype pollution | CRITICAL |
| INJ-018 | CSS injection via user input | WARNING |
| INJ-019 | GraphQL introspection in prod | WARNING |
| INJ-020 | CRLF injection | WARNING |
| INJ-021 | eval() / new Function() / setTimeout(string) | CRITICAL |

### Security Headers (HDR), Supply Chain (SUP), Infrastructure (INF), AI/LLM (AI), Cryptography (CRYPTO), Privacy (PRIV), Business Logic (BIZ), Logging (LOG), File System (FS), WebSocket (WS)

See `skills/security-scan/references/` for complete documentation of all checks with regex patterns, fix examples, and false positive notes.

</details>

---

## How It Works

vibecheck runs as a **PreToolUse hook** on every Write, Edit, and MultiEdit operation:

```
Claude tries to write a file
         |
         v
  vibecheck intercepts
         |
  Detect file extension (.js? .sql? .py? .yaml?)
         |
  Load ONLY relevant checkers (skip DB checks for .css)
         |
  Scan content against matched patterns
         |
    +---------+---------+
    |         |         |
 CRITICAL  WARNING    INFO
 exit(2)   exit(0)   silent
 BLOCKS    warns     scan only
 write     allows
```

| Severity | What Happens | Example |
|:---------|:-------------|:--------|
| `CRITICAL` | **Blocks the write.** Claude must fix and retry. | Hardcoded API key, RLS disabled, SQL injection |
| `WARNING` | Warns in stderr. Write proceeds. | JWT in localStorage, missing rate limiting |
| `INFO` | Silent during hooks. Shown in full scan mode. | Missing MFA, no structured logging |

**Performance:** ~88ms average per write. Only loads checkers relevant to the file type.

---

## Smart Detection

vibecheck is not a dumb regex scanner. It understands context:

| Feature | How It Works |
|:--------|:-------------|
| **Test file awareness** | `*.test.*`, `*.spec.*`, `__tests__/`, `fixtures/` auto-downgrade CRITICAL to WARNING |
| **DOMPurify detection** | `dangerouslySetInnerHTML` only flagged if DOMPurify is NOT imported in the same file |
| **Public API awareness** | CORS wildcard not flagged if public API patterns detected in the same file |
| **Comment context** | Comments with "BAD:", "DON'T", "NEVER", "WRONG" recognized as educational, not vulnerabilities |
| **Entropy analysis** | Catches secrets without known prefixes via Shannon entropy > 4.5 on 20+ char strings |
| **Inline suppression** | `// vibecheck-disable SEC-001` skips a specific check when you know what you are doing |

---

## Configuration

Create `.vibecheck.json` in your project root. Entirely optional.

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

<details>
<summary><strong>Configuration options explained</strong></summary>

| Field | Type | Default | Description |
|:------|:-----|:--------|:------------|
| `severity_overrides` | `object` | `{}` | Change severity for specific checks. `{ "NET-001": "WARNING" }` downgrades CORS wildcard from CRITICAL to WARNING. |
| `disabled` | `string[]` | `[]` | Disable specific checks entirely. `["SEC-013"]` disables entropy analysis. |
| `ignore_paths` | `string[]` | `[]` | Glob patterns for files to skip. Test files are already handled automatically. |
| `inline_suppression` | `boolean` | `true` | Enable/disable `// vibecheck-disable` comments. |
| `framework` | `string` | `"auto"` | Force a framework (`nextjs`, `vite`, `express`, `django`). Auto-detects from package.json. |

</details>

---

## Skills and Agent

### Skills

vibecheck includes 4 skills that activate when you ask about security topics:

| Skill | Trigger Phrases | What It Does |
|:------|:----------------|:-------------|
| **security-scan** | "security scan", "vulnerability check" | Full codebase audit with categorized report |
| **secure-keys** | "secure API keys", "handle secrets" | Framework-specific secret management (Next.js, Vite, Express, Supabase) |
| **secure-auth** | "secure login", "rate limiting" | Auth hardening: rate limiting, JWT, bcrypt, CSRF, OAuth |
| **secure-deploy** | "deploy securely", "pre-launch check" | Pre-deployment security checklist |

### Agent

The **security-scanner** agent performs deep codebase analysis:
- Detects stack from package.json / requirements.txt / go.mod
- Discovers all source files (excludes node_modules, dist, .git)
- Runs `npm audit` or `pip audit` for dependency vulnerabilities
- Cross-file analysis: auth middleware on admin routes, RLS on DB tables
- Outputs categorized report sorted by severity with CWE mappings

---

## CWE Mapping

Every check maps to a [Common Weakness Enumeration](https://cwe.mitre.org/) ID for compliance reporting:

<details>
<summary><strong>68 CWE IDs covered</strong></summary>

| CWE | Description | Checks |
|:----|:------------|:-------|
| CWE-798 | Hardcoded credentials | SEC-001 to SEC-022 |
| CWE-89 | SQL injection | DB-002, DB-003, DB-013 |
| CWE-79 | Cross-site scripting | INJ-001 to INJ-005 |
| CWE-862 | Missing authorization | DB-001, DB-007, DB-010 |
| CWE-918 | SSRF | NET-009, SEC-020 |
| CWE-352 | CSRF | AUTH-010, AUTH-015 |
| CWE-328 | Weak hash | CRYPTO-001 |
| CWE-330 | Weak RNG | CRYPTO-004, BIZ-004 |
| CWE-22 | Path traversal | INJ-007, FS-001, FS-005 |
| CWE-78 | Command injection | INJ-006 |
| CWE-502 | Unsafe deserialization | INJ-011 |
| CWE-306 | Missing authentication | DB-015, AI-014 |
| CWE-613 | Insufficient session expiration | AUTH-007 |
| CWE-942 | Permissive CORS | NET-001, NET-002 |
| CWE-532 | Sensitive data in logs | LOG-002, LOG-005, PRIV-001 |
| CWE-732 | Incorrect permissions | FS-004 |
| CWE-829 | Untrusted functionality | SUP-004, SUP-005, SUP-011 |
| ... | **68 total** | |

</details>

---

## How vibecheck Compares

| | vibecheck | eslint-plugin-security | Snyk Code | Semgrep |
|:---|:---:|:---:|:---:|:---:|
| Runs inside Claude Code | Yes | No | No | No |
| Blocks before write | Yes | No (lint after) | No (scan after) | No (scan after) |
| Zero config | Yes | Needs .eslintrc | Needs account | Needs rules |
| Supabase RLS checks | Yes | No | No | No |
| AI/LLM security | Yes | No | Limited | Limited |
| Vibe-coding aware | Yes | No | No | No |
| Dependencies | 0 (Python stdlib) | npm | Cloud service | Binary |
| Latency per file | ~88ms | N/A | Seconds | Seconds |

vibecheck is purpose-built for AI-assisted development. It catches the specific mistakes that LLMs make when generating code.

---

## File Structure

```
vibecheck/
├── .claude-plugin/plugin.json      # Plugin metadata
├── hooks/
│   ├── hooks.json                  # PreToolUse wiring
│   └── security_gate.py            # Main hook (reads stdin, dispatches, exits 0 or 2)
├── checkers/                       # 15 checker modules, one per category
��   ├── __init__.py                 # Registry + dispatcher + entropy analysis
│   ├── secrets.py                  # SEC-001 to SEC-022
│   ├── auth.py                     # AUTH-001 to AUTH-020
│   ├���─ database.py                 # DB-001 to DB-020
│   ├── network.py                  # NET-001 to NET-011
│   ├── injection.py                # INJ-001 to INJ-021
│   ├── headers.py                  # HDR-001 to HDR-011
│   ├── supply_chain.py             # SUP-001 to SUP-015
│   ├── infrastructure.py           # INF-001 to INF-010
│   ├── ai_llm.py                   # AI-001 to AI-016
│   ├── crypto.py                   # CRYPTO-001 to CRYPTO-012
│   ├── privacy.py                  # PRIV-001 to PRIV-008
│   ├─�� business_logic.py           # BIZ-001 to BIZ-006
│   ├── logging_security.py         # LOG-001 to LOG-005
│   ├── filesystem.py               # FS-001 to FS-005
���   └── websocket.py                # WS-001 to WS-004
├── skills/                         # 4 teaching skills
│   ���── security-scan/SKILL.md      # Full scan orchestrator
│   ├── security-scan/references/   # 15 detailed check docs
│   ├── secure-keys/SKILL.md        # Secret management patterns
│   ├── secure-auth/SKILL.md        # Auth hardening patterns
│   └── secure-deploy/SKILL.md      # Pre-deploy checklist
├── agents/
│   └── security-scanner.md         # Deep codebase scanner
├── LICENSE                         # MIT
└── CHANGELOG.md
```

---

## Requirements

- **Claude Code** with plugin support
- **Python 3.8+** (uses only stdlib; zero pip dependencies)

---

## Troubleshooting

<details>
<summary><strong>Hook not firing</strong></summary>

```bash
# Check plugin is installed
claude plugin list

# Reinstall
claude plugin remove vibecheck
claude plugin add ~/.claude/plugins/vibecheck
```

</details>

<details>
<summary><strong>Too many false positives</strong></summary>

Test files are already auto-downgraded. For additional paths:
```json
{ "ignore_paths": ["**/fixtures/**", "**/mocks/**"] }
```

For a specific instance:
```javascript
// vibecheck-disable SEC-001
const awsKeyForTesting = "AKIA...";
```

To downgrade instead of block:
```json
{ "severity_overrides": { "SEC-001": "WARNING" } }
```

</details>

<details>
<summary><strong>Performance concerns</strong></summary>

The hook only loads checkers relevant to the file extension. A `.css` file skips all checks. Average latency is ~88ms. If you experience slowness, check for large files being written (the hook scans the full content).

</details>

---

## Contributing

Found a false positive? Missing a check? [Open an issue](https://github.com/Wishmakingfairy/vibecheck/issues).

When adding a new check:
1. Add the pattern to the relevant `checkers/*.py` module
2. Add a reference entry in `skills/security-scan/references/`
3. Test with both a vulnerable and clean code sample
4. Map to a CWE ID

---

## Author

Built by **Haralds Gabrans** ([GitHub](https://github.com/Wishmakingfairy))

## License

[MIT](LICENSE)
