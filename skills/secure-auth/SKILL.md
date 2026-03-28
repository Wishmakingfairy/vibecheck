---
name: secure-auth
description: "This skill should be used when the user asks to \"add authentication\", \"secure login\", \"implement rate limiting\", \"JWT best practices\", \"session security\", or \"OAuth setup\". Teaches authentication hardening patterns."
version: 1.0.0
triggers:
  - "secure.*(?:auth|login)"
  - "rate.?limit"
  - "jwt.*(?:best|secure|practice)"
  - "session.*security"
  - "oauth.*(?:setup|secure)"
---

# Secure Auth: Authentication Hardening

## Rate Limiting (AUTH-001)

```javascript
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // 5 attempts per window
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
});

app.post('/api/auth/login', authLimiter, loginHandler);
```

## JWT Best Practices (AUTH-007, AUTH-008)

```javascript
// Sign with expiry and strong algorithm
const token = jwt.sign(payload, process.env.JWT_SECRET, {
  expiresIn: '15m',    // Short-lived access token
  algorithm: 'RS256',   // Asymmetric for production
});

// Store in httpOnly cookie, NOT localStorage
res.cookie('token', token, {
  httpOnly: true,    // No JS access
  secure: true,      // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 15 * 60 * 1000,
});
```

## Password Hashing (AUTH-017)

```javascript
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);
```

## CSRF Protection (AUTH-010)

Use SameSite cookies (preferred) or CSRF tokens for forms.

## OAuth State Parameter (AUTH-015)

```javascript
const state = crypto.randomUUID();
req.session.oauthState = state;
const authUrl = `https://provider.com/auth?state=${state}&redirect_uri=...`;

// On callback:
if (req.query.state !== req.session.oauthState) throw new Error('CSRF detected');
```
