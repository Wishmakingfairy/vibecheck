---
name: secure-deploy
description: "This skill should be used when the user asks to \"deploy securely\", \"pre-deploy checklist\", \"production security\", \"ship safely\", or \"security before launch\". Provides a comprehensive pre-deployment security checklist."
version: 1.0.0
triggers:
  - "deploy.*secur"
  - "pre.?deploy.*check"
  - "production.*security"
  - "ship.*safe"
  - "security.*launch"
---

# Secure Deploy: Pre-Launch Checklist

## CRITICAL (Must fix before deploy)

- [ ] No API keys/secrets in source code (run `vibecheck scan`)
- [ ] .env files in .gitignore
- [ ] DEBUG=False / NODE_ENV=production
- [ ] Supabase RLS enabled on ALL tables
- [ ] CORS restricted to your domains (not *)
- [ ] Rate limiting on auth endpoints
- [ ] HTTPS enforced (redirect HTTP to HTTPS)
- [ ] Source maps disabled in production build
- [ ] No default credentials (admin:admin)

## WARNING (Should fix before deploy)

- [ ] Security headers configured (CSP, HSTS, X-Frame-Options)
- [ ] JWT tokens have expiry
- [ ] Session cookies have Secure + HttpOnly + SameSite
- [ ] File uploads validated (type + size)
- [ ] SQL queries use parameterized statements
- [ ] Dependencies audited (npm audit / pip audit)
- [ ] Error responses do not expose stack traces
- [ ] Admin routes require authentication

## INFO (Best practice)

- [ ] Structured logging configured (no PII)
- [ ] Monitoring and alerting set up
- [ ] Backup strategy in place
- [ ] Incident response plan documented
- [ ] MFA available for admin accounts

## Quick Verification

Run: `/security-scan` to check all 156 items automatically.
