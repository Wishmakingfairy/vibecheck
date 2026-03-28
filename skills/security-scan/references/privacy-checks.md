# Privacy & Data Protection Checks

8 checks for PII leaks, data exposure, credit card handling, and unsafe storage.

Source: `checkers/privacy.py`

---

### PRIV-001: PII in Logs
- **Severity:** WARNING
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Pattern:** `(?i)(?:console\.log|logger\.|logging\.).*(?:email|ssn|phone|credit.?card|social.?security)`
- **Why:** Logs are often stored unencrypted, shipped to third-party aggregators, and accessible to wide teams. PII in logs creates compliance violations (GDPR, CCPA) and breach risk.
- **Fix:**
```javascript
// Bad
console.log("User signed up", user.email, user.ssn);

// Good
logger.info("User signed up", { email: maskEmail(user.email), ssn: "***" });
```
- **False positives:** Comments or documentation mentioning these fields without actually logging them. Variable names containing "email" in non-logging contexts on the same line as a console.log for something else.

---

### PRIV-002: PII Stored Without Encryption
- **Severity:** INFO
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Pattern:** Triggers when `(?i)(?:save|store|insert|create|update).*(?:ssn|social.?security|passport.?number|national.?id)` matches AND `(?i)(?:encrypt|cipher|aes|pgp|kms|vault|sealed)` is absent from the file.
- **Why:** SSNs, passport numbers, and national IDs stored in plaintext are high-value breach targets. Regulations require encryption at rest for this class of data.
- **Fix:**
```javascript
// Bad
await db.users.insert({ ssn: user.ssn });

// Good
const encryptedSsn = await kms.encrypt(user.ssn);
await db.users.insert({ ssn: encryptedSsn });
```
- **False positives:** Files that handle PII but delegate encryption to a separate service/layer not visible in the same file. The check looks for encryption keywords anywhere in the file as a mitigating signal.

---

### PRIV-003: User Data in Error Response
- **Severity:** WARNING
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Pattern:** `(?i)(?:res\.(?:json|send)|return.*error).*(?:user|email|password|token)`
- **Why:** Error responses containing user data leak information to attackers. Email addresses confirm account existence, tokens enable session hijacking.
- **Fix:**
```javascript
// Bad
res.json({ error: "Invalid password", email: user.email, token });

// Good
res.json({ error: "Invalid credentials" });
logger.warn("Failed login attempt", { userId: user.id });
```
- **False positives:** Error responses that reference "user" or "token" in the error message string itself (e.g., `res.json({ error: "User not found" })`) without actually leaking data values.

---

### PRIV-004: Missing Data Retention Policy
- **Severity:** INFO
- **CWE:** CWE-459 (Incomplete Cleanup)
- **Pattern:** Triggers when `(?i)(?:created.?at|timestamp|date.?added|inserted.?at)` matches AND `(?i)(?:retention|ttl|expir|purge|cleanup|archive|delete.*old|prune)` is absent from the file.
- **Why:** GDPR Article 5(1)(e) requires data minimization. Storing data indefinitely without cleanup increases breach surface and violates regulations.
- **Fix:**
```javascript
// Bad: data sits forever
await db.logs.insert({ action, createdAt: new Date() });

// Good: TTL index or scheduled cleanup
await db.logs.insert({ action, createdAt: new Date(), expiresAt: addDays(new Date(), 90) });
// Plus: cron job that runs DELETE FROM logs WHERE expiresAt < NOW()
```
- **False positives:** Files that only define a schema with timestamp fields. Retention logic is commonly in a separate cleanup service. This is an informational reminder, not a hard finding.

---

### PRIV-005: Geolocation Tracking Without Consent
- **Severity:** INFO
- **CWE:** CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
- **Pattern:** Triggers when `(?i)(?:geolocation|navigator\.geolocation|getCurrentPosition|watchPosition|ip.?location|geoip)` matches AND `(?i)(?:consent|permission|allow|opt.?in|gdpr|accept)` is absent from the file.
- **Why:** GDPR and ePrivacy Directive require explicit consent before tracking user location. Geolocation data is classified as personal data.
- **Fix:**
```javascript
// Bad
navigator.geolocation.getCurrentPosition(callback);

// Good
if (await getUserConsent("location")) {
  navigator.geolocation.getCurrentPosition(callback);
}
```
- **False positives:** Server-side GeoIP lookups for non-tracking purposes (e.g., currency selection, content localization) where consent may not be legally required. The check looks for any consent-related keywords in the file.

---

### PRIV-006: Credit Card Numbers in Code
- **Severity:** CRITICAL
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Pattern:** Triggers when a Visa/Mastercard/Amex number pattern `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b` matches AND `(?i)(?:store|save|log|insert|write|database|db|console|print|file)` is present in the file.
- **Why:** PCI-DSS prohibits storing full card numbers. A single exposed card number is a reportable breach. Fines start at $5,000/month.
- **Fix:**
```javascript
// Bad
console.log("Payment processed", cardNumber);
await db.payments.insert({ cardNumber: req.body.cardNumber });

// Good: use a payment processor that tokenizes
const { paymentMethodId } = await stripe.paymentMethods.create({
  type: "card", card: { token: stripeToken }
});
// Display masked: **** **** **** 4242
```
- **False positives:** Test card numbers in test files (e.g., Stripe test card 4242424242424242). The check requires a storage/logging context keyword in the same file to reduce noise, but test fixtures may still trigger it.

---

### PRIV-007: Analytics on Sensitive Pages
- **Severity:** INFO
- **CWE:** CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
- **Pattern:** `(?i)(?:gtag|analytics|track|pixel|segment).*(?:password|payment|checkout|medical|health)`
- **Why:** Analytics on password reset, payment, or medical pages can leak sensitive data to third-party analytics providers. HIPAA and PCI-DSS have specific restrictions.
- **Fix:**
```javascript
// Bad
gtag("event", "payment_submitted", { amount, cardType });

// Good
// Disable analytics on sensitive pages entirely, or:
gtag("event", "checkout_step", { step: 3 }); // no sensitive data in payload
```
- **False positives:** Analytics calls that mention "payment" in an event name but do not actually send sensitive data in the payload. The regex matches keyword proximity, not actual data flow.

---

### PRIV-008: User Data in localStorage/sessionStorage
- **Severity:** WARNING
- **CWE:** CWE-922 (Insecure Storage of Sensitive Information)
- **Pattern:** `(?i)(?:localStorage|sessionStorage)\.setItem.*(?:user|email|profile|token)`
- **Why:** localStorage has no expiry, no httpOnly flag, and is accessible to any JavaScript on the page (including XSS payloads). Tokens stored here can be stolen.
- **Fix:**
```javascript
// Bad
localStorage.setItem("authToken", token);
localStorage.setItem("userEmail", user.email);

// Good: httpOnly cookie for auth tokens
// Set via server: Set-Cookie: token=abc; HttpOnly; Secure; SameSite=Strict
// If localStorage is unavoidable:
localStorage.setItem("userData", encrypt(JSON.stringify({ data, expiresAt: Date.now() + ttl })));
```
- **False positives:** Storing non-sensitive user preferences (e.g., theme, language) where the key contains "user". The regex matches any setItem with "user" in the arguments.
