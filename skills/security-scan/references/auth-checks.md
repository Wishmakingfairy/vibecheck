# Authentication & Authorization Checks (AUTH-001 to AUTH-020)

20 checks for JWT misuse, session security, OAuth, CSRF, rate limiting, and password handling.

---

### AUTH-001: Login Route Without Rate Limiting
- **Severity:** WARNING
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Pattern:** Login/signup route (`app.post("/api/auth/login")` etc.) present without rate limiting middleware (`rateLimit`, `throttle`, `express-rate-limit`, `@nestjs/throttler`, etc.)
- **Why:** Without rate limiting, attackers can brute-force credentials at unlimited speed.
- **Fix:**
```javascript
const rateLimit = require("express-rate-limit");
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
});
app.use("/api/auth", loginLimiter);
```
- **False positives:** Files that import rate limiting in a separate middleware file. If rate limiting is applied globally or in a different file, this triggers on the route file alone. Mitigated by checking the same file for any rate limit reference.

---

### AUTH-003: Weak Password Requirements
- **Severity:** WARNING
- **CWE:** CWE-521 (Weak Password Requirements)
- **Pattern:** `(?i)(?:minlength|min.?length|min.?len)\s*[:=]\s*['"]?([1-7])['"]?`
- **Why:** Password minimums below 8 characters allow trivially brute-forceable passwords. NIST SP 800-63B requires at least 8.
- **Fix:**
```javascript
const schema = Joi.object({
  password: Joi.string().min(12).required(),
});
// Also check against breached password lists
const pwned = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
```
- **False positives:** Non-password fields using minLength (e.g., username). The regex matches any minLength value 1-7 regardless of field context. Low risk since short minimums on any field are worth reviewing.

---

### AUTH-007: JWT Sign Without Expiry
- **Severity:** CRITICAL
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **Pattern:** `jwt.sign()` call present without `expiresIn` or `exp` in the options object
- **Why:** Tokens without expiry grant permanent access. A single leaked token compromises the account forever.
- **Fix:**
```javascript
// Short-lived access token + refresh token pattern
const accessToken = jwt.sign(payload, secret, { expiresIn: "15m" });
const refreshToken = jwt.sign({ userId }, refreshSecret, { expiresIn: "7d" });
```
- **False positives:** When `jwt.sign()` is called with a payload that already contains an `exp` claim set programmatically (e.g., `{ exp: Math.floor(Date.now()/1000) + 3600 }`). The check looks for `expiresIn` or `exp` in the same call context but may miss payload-level exp.

---

### AUTH-008: JWT Algorithm None
- **Severity:** CRITICAL
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Pattern:** `(?i)(?:alg(?:orithm)?|algorithms?)\s*[:=]\s*['"\[]?\s*['"]?none['"]?`
- **Why:** Setting the algorithm to "none" disables signature verification entirely. Attackers can forge any token.
- **Fix:**
```javascript
// Always specify a strong algorithm explicitly
const token = jwt.sign(payload, secret, { algorithm: "RS256" });
// On verify, reject "none"
jwt.verify(token, publicKey, { algorithms: ["RS256"] });
```
- **False positives:** Comments or documentation mentioning the "none" algorithm as a warning. The regex matches assignment context (`=` or `:`) which reduces doc-only matches.

---

### AUTH-009: JWT Stored in localStorage
- **Severity:** WARNING
- **CWE:** CWE-922 (Insecure Storage of Sensitive Information)
- **Pattern:** `localStorage.setItem` with key names: `token`, `jwt`, `access_token`, `auth_token`, `id_token`
- **Why:** Any XSS vulnerability can read localStorage, stealing the token and granting full account access.
- **Fix:**
```javascript
// Server sets httpOnly cookie instead of returning token to JS
res.cookie("access_token", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  maxAge: 15 * 60 * 1000,
});
```
- **False positives:** Clearing tokens (`localStorage.removeItem`) won't trigger since the pattern matches `setItem` specifically. Test code that stores mock tokens will trigger.

---

### AUTH-010: POST Form Without CSRF Protection
- **Severity:** WARNING
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Pattern:** `<form method="post"` present without any CSRF token reference (`csrf`, `_token`, `xsrf`, `anti-forgery`)
- **Why:** Without CSRF protection, malicious sites can submit forms on behalf of authenticated users.
- **Fix:**
```html
<form method="post" action="/transfer">
  <input type="hidden" name="_csrf" value="{{csrfToken}}" />
  <!-- form fields -->
</form>
```
```javascript
// Express middleware
const csrf = require("csurf");
app.use(csrf({ cookie: { sameSite: "strict" } }));
```
- **False positives:** SPA forms that use fetch/axios with SameSite cookies (no traditional CSRF token needed). Also triggers on forms that POST to external services where CSRF is irrelevant.

---

### AUTH-015: OAuth Without State Parameter
- **Severity:** CRITICAL
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Pattern:** OAuth/authorization URL with redirect/callback reference, but no `state` parameter assignment found
- **Why:** Without the state parameter, attackers can initiate an OAuth flow and trick users into linking attacker-controlled accounts.
- **Fix:**
```javascript
const crypto = require("crypto");
const state = crypto.randomBytes(32).toString("hex");
req.session.oauthState = state;
const authUrl = `https://provider.com/authorize?client_id=${id}&state=${state}&redirect_uri=${callback}`;

// On callback:
if (req.query.state !== req.session.oauthState) {
  throw new Error("Invalid state parameter");
}
```
- **False positives:** Files that handle only the callback side (state verification) without the URL construction. The check looks for both oauth-related URLs and state assignment in the same file.

---

### AUTH-016: Session Cookie Missing Security Flags
- **Severity:** WARNING
- **CWE:** CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- **Pattern:** Cookie/session configuration detected, then checks for presence of `Secure`, `HttpOnly`, and `SameSite` flags
- **Why:** Missing Secure allows cookie theft over HTTP. Missing HttpOnly allows XSS to steal cookies. Missing SameSite allows CSRF attacks.
- **Fix:**
```javascript
app.use(session({
  cookie: {
    secure: true,      // Only sent over HTTPS
    httpOnly: true,     // Not accessible to JavaScript
    sameSite: "strict", // Not sent on cross-site requests
    maxAge: 24 * 60 * 60 * 1000,
  },
}));
```
- **False positives:** Files that reference cookies in a non-security context (e.g., cookie consent banners). The pattern matches any cookie/session assignment, so UI cookie references may trigger. The message lists which specific flags are missing.

---

### AUTH-017: Password in Reversible Encryption
- **Severity:** CRITICAL
- **CWE:** CWE-257 (Storing Passwords in a Recoverable Format)
- **Pattern:** `(?i)(?:encrypt|cipher|aes|des|rc4)\s*\(\s*(?:password|passwd|pwd)`
- **Why:** Reversible encryption means if the key is compromised, every password is exposed. Hashing is one-way by design.
- **Fix:**
```javascript
const bcrypt = require("bcrypt");
// Hashing (irreversible)
const hash = await bcrypt.hash(password, 12);
// Verification
const match = await bcrypt.compare(password, hash);
```
- **False positives:** Code that encrypts passwords for transit (not storage), e.g., client-side encryption before sending to server. Rare in practice; passwords should be sent over TLS, not encrypted client-side.

---

### AUTH-018: Sensitive Operation Without Re-authentication
- **Severity:** WARNING
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Pattern:** Sensitive operation keywords (`change_password`, `update_email`, `delete_account`, `disable_mfa`, `update_payment`) present without re-authentication check (`verify_password`, `confirm_password`, `re_auth`, `current_password`)
- **Why:** If a session is hijacked, attackers can perform irreversible actions without proving they know the password.
- **Fix:**
```javascript
app.post("/api/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  // Re-authenticate before allowing the change
  const valid = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid current password" });
  // Proceed with password change
});
```
- **False positives:** Admin endpoints where the admin is acting on another user's account (re-auth may happen at a different layer). Also triggers when re-auth is handled by a separate middleware not in the same file.

---

### AUTH-020: Magic Link Without Token Expiry
- **Severity:** WARNING
- **CWE:** CWE-640 (Weak Password Recovery Mechanism for Forgotten Password)
- **Pattern:** Magic link / passwordless login keywords present without token expiry references (`expir`, `ttl`, `max_age`, `valid_until`)
- **Why:** Non-expiring magic links remain valid forever. If an email is compromised months later, the link still grants access.
- **Fix:**
```javascript
const token = crypto.randomBytes(32).toString("hex");
await db.magicLink.create({
  data: {
    token: await bcrypt.hash(token, 10),
    userId: user.id,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 min
    used: false,
  },
});
// On verification: check expiresAt AND used flag, then mark as used
```
- **False positives:** Files that discuss magic links in comments or documentation without implementing them. The pattern is broad enough to match any mention of "magic link" or "passwordless".
