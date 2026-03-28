---
name: security-scan
description: "This skill should be used when the user asks to \"run a security scan\", \"check for vulnerabilities\", \"security audit\", \"ship secure\", \"0xguard scan\", or \"pre-deploy security check\". Runs 156 automated security checks across 15 categories and produces a categorized vulnerability report."
version: 1.0.0
allowed-tools: "Bash, Read, Grep, Glob, Write"
triggers:
  - "security.?scan"
  - "vulnerability.?check"
  - "security.?audit"
  - "ship.?secure"
  - "0xguard"
  - "pre.?deploy.?security"
---

# 0xguard Security Scan

Run 156 automated security checks against the current codebase. Produces a categorized report with severity levels and fix suggestions.

## How to Run

1. Detect the project's tech stack from package.json, requirements.txt, or file extensions
2. Glob for all source files: `**/*.{js,jsx,ts,tsx,py,sql,json,yaml,yml,html,vue,svelte,go,rb,php,sh,tf}`
3. Read each file and apply the check patterns from the reference documents
4. Produce a markdown report

## Report Format

```markdown
# 0xguard Security Report

## Summary
| Severity | Count |
|----------|-------|
| CRITICAL | X     |
| WARNING  | Y     |
| INFO     | Z     |

## Findings by Category

### Secrets & API Keys
- [SEC-001] CRITICAL: Hardcoded AWS key in src/config.ts:12
  Fix: Use environment variables...

### Authentication
...
```

## Categories (15)

1. **Secrets & API Keys** (22 checks) - Hardcoded credentials, API keys, private keys
2. **Authentication** (20 checks) - JWT, session, OAuth, CSRF, rate limiting
3. **Database** (20 checks) - SQL injection, Supabase RLS, mass assignment
4. **Network & CORS** (11 checks) - CORS wildcard, SSRF, HTTPS, open redirects
5. **Injection** (21 checks) - XSS, command injection, path traversal, deserialization
6. **Security Headers** (11 checks) - CSP, HSTS, debug mode, stack traces
7. **Supply Chain** (15 checks) - Typosquatting, unpinned deps, SRI
8. **Infrastructure** (10 checks) - Docker, CI/CD, admin panels, source maps
9. **AI/LLM** (16 checks) - API key exposure, prompt injection, system prompt leaks
10. **Cryptography** (12 checks) - Weak hashing, insecure RNG, deprecated crypto
11. **Privacy** (8 checks) - PII logging, data exposure, credit cards
12. **Business Logic** (6 checks) - Race conditions, mass assignment, enumeration
13. **Logging** (5 checks) - Secrets in logs, log injection
14. **File System** (5 checks) - Path traversal, zip slip, permissions
15. **WebSocket** (4 checks) - Auth, origin validation, message limits

## Reference Files

Each category has a detailed reference document with regex patterns, explanations, and fix examples:
- **`references/secrets-checks.md`** - All 22 SEC checks
- **`references/auth-checks.md`** - All 20 AUTH checks
- **`references/database-checks.md`** - All 20 DB checks
- **`references/network-checks.md`** - All 11 NET checks
- **`references/injection-checks.md`** - All 21 INJ checks
- **`references/headers-checks.md`** - All 11 HDR checks
- **`references/supply-chain-checks.md`** - All 15 SUP checks
- **`references/infra-checks.md`** - All 10 INF checks
- **`references/ai-llm-checks.md`** - All 16 AI checks
- **`references/crypto-checks.md`** - All 12 CRYPTO checks
- **`references/privacy-checks.md`** - All 8 PRIV checks
- **`references/business-logic-checks.md`** - All 6 BIZ checks
- **`references/logging-checks.md`** - All 5 LOG checks
- **`references/filesystem-checks.md`** - All 5 FS checks
- **`references/websocket-checks.md`** - All 4 WS checks

## Scan Workflow

1. **Stack detection**: Read package.json or requirements.txt to identify framework
2. **File discovery**: Glob for source files, excluding node_modules, dist, .git
3. **Targeted scanning**: For each file, read content and apply category-relevant checks
4. **Report generation**: Aggregate findings, sort by severity, output markdown report
5. **Auto-fix offer**: For CRITICAL findings, offer to apply the suggested fix

## Configuration

Create `.0xguard.json` in project root to customize:
```json
{
  "severity_overrides": { "NET-001": "WARNING" },
  "disabled": ["HDR-004"],
  "ignore_paths": ["**/*.test.*", "**/fixtures/**"],
  "framework": "auto"
}
```
