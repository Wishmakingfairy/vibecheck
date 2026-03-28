---
name: secure-keys
description: "This skill should be used when the user asks to \"secure my API keys\", \"handle secrets safely\", \"fix exposed key\", \"environment variables setup\", or \"rotate compromised keys\". Teaches secure secret management patterns per framework."
version: 1.0.0
triggers:
  - "secure.*(?:api|key|secret)"
  - "fix.*exposed.*key"
  - "environment.*variable"
  - "rotate.*(?:key|secret)"
---

# Secure Keys: API Key & Secret Management

## The Rule

Never put secrets in code. Never put secrets in frontend bundles. Never commit secrets to git.

## Framework-Specific Patterns

### Next.js
- **Server-only**: `process.env.SECRET_KEY` (no prefix, only accessible in API routes / getServerSideProps)
- **Client-safe**: `NEXT_PUBLIC_` prefix (embedded in bundle, visible to everyone)
- **Never**: `NEXT_PUBLIC_SECRET_KEY`, `NEXT_PUBLIC_DATABASE_URL`

### Vite
- **Server-only**: Not accessible in client code by default
- **Client-safe**: `VITE_` prefix (embedded in bundle)
- **Never**: `VITE_SECRET_KEY`, `VITE_DB_PASSWORD`

### Express / Node.js
- Use `dotenv`: `require('dotenv').config()` then `process.env.KEY`
- Production: Set env vars in hosting platform (Vercel, Railway, Render)

### Supabase
- **Frontend OK**: `SUPABASE_ANON_KEY` (public, limited by RLS)
- **Server ONLY**: `SUPABASE_SERVICE_ROLE_KEY` (bypasses ALL RLS)

## Secret Rotation Checklist

1. Generate new secret on the provider dashboard
2. Update environment variables in production
3. Deploy with new secret
4. Revoke old secret
5. If committed to git: consider the secret permanently compromised

## .gitignore Template

```
.env
.env.local
.env.production
.env.*.local
*.pem
*.key
*-credentials.json
service-account.json
```
