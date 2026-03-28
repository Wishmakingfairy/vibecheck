# Changelog

All notable changes to 0xguard will be documented in this file.

## [1.0.0] - 2026-03-27

### Added
- Initial release with 156 security checks across 15 categories
- PreToolUse hook that blocks CRITICAL vulnerabilities before they reach your codebase
- Secrets and API key detection (22 checks) with Shannon entropy analysis
- Authentication hardening checks (20 checks) including JWT, OAuth, session security
- Database security checks (20 checks) with Supabase RLS awareness
- Network and CORS checks (11 checks) with SSRF variant coverage
- Injection prevention (21 checks) covering React, Vue, Angular, Svelte XSS patterns
- Security headers validation (11 checks)
- Supply chain security (15 checks) with typosquatting detection
- Infrastructure security (10 checks)
- AI/LLM security (16 checks) for prompt injection, key exposure, system prompt leaks
- Cryptography misuse detection (12 checks)
- Privacy and data protection (8 checks)
- Business logic security (6 checks)
- Logging security (5 checks)
- File system security (5 checks)
- WebSocket security (4 checks)
- CWE mapping for all 156 checks (68 unique CWEs)
- Inline suppression support (`// 0xguard-disable CHECK-ID`)
- Test file auto-detection (auto-downgrade severity for test/spec/fixture files)
- `.0xguard.json` project configuration
- security-scan skill for full codebase audits
- secure-keys, secure-auth, secure-deploy teaching skills
- security-scanner agent for deep analysis
