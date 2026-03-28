# Cryptography Checks Reference

12 active checks. All IDs CRYPTO-001 through CRYPTO-012 are implemented.

---

### CRYPTO-001: MD5/SHA1 for Password Hashing
- **Severity:** CRITICAL
- **CWE:** CWE-328 (Use of Weak Hash)
- **Pattern:** `(?i)(?:md5|sha1).*(?:password|hash)`
- **Why:** MD5 and SHA1 are fast hashes. Modern GPUs crack billions of MD5 hashes per second. Passwords hashed with them are trivially brute-forced.
- **Fix:**
```js
// Bad
const hash = crypto.createHash("md5").update(password).digest("hex");

// Good - bcrypt
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);
const valid = await bcrypt.compare(password, hash);
```
```python
# Good - argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
ph.verify(hash, password)
```
- **False positives:** Fires when `md5` or `sha1` and `password` or `hash` appear together, even in comments, log messages, or migration code that reads old hashes. Does not distinguish between hashing for passwords vs hashing for checksums/integrity.

---

### CRYPTO-002: ECB Cipher Mode
- **Severity:** CRITICAL
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Pattern:** `(?i)(?:ECB|MODE_ECB|aes-128-ecb|aes-256-ecb)`
- **Why:** ECB encrypts identical plaintext blocks into identical ciphertext blocks. This leaks data patterns (the "ECB penguin" problem) and makes the encryption semantically insecure.
- **Fix:**
```js
// Bad
const cipher = crypto.createCipheriv("aes-256-ecb", key, null);

// Good - AES-GCM (authenticated encryption)
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
```
- **False positives:** Fires on any mention of ECB, including documentation, comments explaining why not to use it, or test code that verifies ECB is not in use. The string `ECB` in a variable name unrelated to crypto would also match.

---

### CRYPTO-003: Hardcoded Initialization Vector
- **Severity:** CRITICAL
- **CWE:** CWE-329 (Generation of Predictable IV with CBC Mode)
- **Pattern (IV):** `(?i)iv\s*[:=]\s*['"][^'"]{8,}['"]`
- **Pattern (crypto context):** `(?i)(?:crypto|cipher|aes|encrypt|decrypt|createCipher)` — both must match.
- **Why:** A reused or predictable IV breaks the semantic security of CBC and enables plaintext recovery attacks. For GCM, IV reuse is catastrophic (key recovery).
- **Fix:**
```js
// Bad
const iv = "1234567890abcdef";
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

// Good
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
// Prepend IV to ciphertext for decryption
const encrypted = Buffer.concat([iv, cipher.update(data), cipher.final()]);
```
- **False positives:** Any string assigned to a variable named `iv` that is 8+ characters triggers, even if it is a default/placeholder in non-crypto context. The crypto context check reduces this, but a file that imports `crypto` for other purposes would still match.

---

### CRYPTO-004: Insecure Random for Security-Sensitive Values
- **Severity:** CRITICAL
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **Pattern:** `(?i)(?:Math\.random|random\.random|random\.randint).*(?:token|nonce|secret|otp|code|session|csrf)`
- **Why:** `Math.random()` and Python's `random` module use predictable PRNGs. An attacker who observes a few outputs can predict future tokens, session IDs, and OTPs.
- **Fix:**
```js
// Bad
const token = Math.random().toString(36).slice(2);

// Good - Node.js
const token = crypto.randomBytes(32).toString("hex");

// Good - Browser
const token = crypto.getRandomValues(new Uint8Array(32));
```
```python
# Bad
import random
otp = random.randint(100000, 999999)

# Good
import secrets
otp = secrets.randbelow(900000) + 100000
token = secrets.token_hex(32)
```
- **False positives:** Fires when `Math.random` and a security keyword appear on the same line. A comment like `// don't use Math.random for token generation` would trigger. Does not fire if the security keyword is on a different line.

---

### CRYPTO-005: Weak RSA Key Size
- **Severity:** WARNING
- **CWE:** CWE-326 (Inadequate Encryption Strength)
- **Pattern:** `(?i)(?:1024|512)\s*(?:bits|keySize|modulusLength)`
- **Why:** RSA keys under 2048 bits can be factored. 512-bit RSA was broken in 1999. 1024-bit is considered deprecated by NIST since 2013.
- **Fix:**
```js
// Bad
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 1024,
});

// Good
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 4096,
});

// Better - use ECDSA for better performance
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "P-256",
});
```
- **False positives:** The numbers 512 and 1024 followed by `bits`, `keySize`, or `modulusLength` could appear in non-RSA contexts (e.g., buffer sizes, chunk sizes). The pattern is loose; a comment about minimum requirements would match.

---

### CRYPTO-006: Deprecated createCipher
- **Severity:** WARNING
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Pattern:** `createCipher\(` — case-sensitive.
- **Negated by:** `createCipheriv\(` present in the same file.
- **Why:** Node.js `createCipher()` derives key and IV from a password using a single MD5 iteration. This is cryptographically weak and deprecated since Node.js v10.
- **Fix:**
```js
// Bad
const cipher = crypto.createCipher("aes-256-cbc", password);

// Good
const key = crypto.scryptSync(password, salt, 32);
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
```
- **False positives:** If a file uses both `createCipher` and `createCipheriv` (e.g., migration code), the check is suppressed entirely. Also, the case-sensitive match means it will not fire on references in comments that use different casing.

---

### CRYPTO-007: Decrypt Without HMAC Verification
- **Severity:** WARNING
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Pattern (decrypt):** `(?i)(?:decrypt|decipher|createDecipheriv)`
- **Negated by:** `(?i)(?:verify|hmac|timingSafeEqual|createHmac)` present in the same file.
- **Why:** Decrypting without verifying integrity enables padding oracle attacks (CBC) and ciphertext manipulation. Attackers can modify encrypted data without knowing the key.
- **Fix:**
```js
// Bad - CBC without MAC
const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
const plaintext = decipher.update(ciphertext) + decipher.final();

// Good - AES-GCM (built-in authentication)
const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
decipher.setAuthTag(authTag);
const plaintext = decipher.update(ciphertext) + decipher.final();

// Good - CBC with HMAC (encrypt-then-MAC)
const hmac = crypto.createHmac("sha256", macKey).update(ciphertext).digest();
if (!crypto.timingSafeEqual(hmac, receivedHmac)) {
  throw new Error("Authentication failed");
}
const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
```
- **False positives:** Any `verify` call in the file suppresses the check, even if unrelated to crypto (e.g., JWT verify, email verification). Files that use AES-GCM (which has built-in authentication via `setAuthTag`) still trigger unless they also use `verify` or `hmac` keywords.

---

### CRYPTO-008: Non-Timing-Safe Token Comparison
- **Severity:** CRITICAL
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Pattern:** `===\s*(?:\w+\.)?(?:token|signature|hash|hmac|digest)` or `(?:token|signature|hash|hmac|digest)\w*\s*===`
- **Negated by:** `(?i)timingSafeEqual` present in the same file.
- **Why:** `===` comparison short-circuits on the first mismatched byte. By measuring response time, an attacker can recover the secret one byte at a time.
- **Fix:**
```js
// Bad
if (providedToken === expectedToken) { ... }

// Good - Node.js
const crypto = require("crypto");
const valid = crypto.timingSafeEqual(
  Buffer.from(providedToken),
  Buffer.from(expectedToken)
);
```
```python
# Good - Python
import hmac
valid = hmac.compare_digest(provided_token, expected_token)
```
- **False positives:** The word `token` in a comparison may refer to JWT tokens (which should use library verification), OAuth tokens, or non-secret identifiers. The check assumes any `=== token` comparison is security-sensitive.

---

### CRYPTO-009: Custom Crypto Implementation
- **Severity:** WARNING
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Pattern:** `(?i)(?:my|custom|diy).*(?:encrypt|decrypt|hash|cipher)`
- **Why:** Custom cryptographic implementations almost always have subtle vulnerabilities. Even expert cryptographers get it wrong. Use audited, battle-tested libraries.
- **Fix:**
```js
// Bad
function myEncrypt(data, key) {
  // XOR-based "encryption"
  return data.split("").map((c, i) => c.charCodeAt(0) ^ key.charCodeAt(i % key.length));
}

// Good - use established libraries
const { createCipheriv, randomBytes } = require("crypto");
// Or: tweetnacl, libsodium-wrappers, Web Crypto API
```
- **False positives:** Variable or function names containing `my` + `encrypt` (e.g., `myEncryptionService` that wraps a standard library) trigger the check. Comments explaining why not to use custom crypto also match.

---

### CRYPTO-010: TLS Version Below 1.2
- **Severity:** WARNING
- **CWE:** CWE-326 (Inadequate Encryption Strength)
- **Pattern:** `(?i)(?:TLSv1_0|TLSv1_1|SSLv3|TLSv1$|ssl_version.*1\.[01])`
- **Why:** TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST, Lucky13). SSLv3 is completely broken. PCI DSS requires TLS 1.2 minimum.
- **Fix:**
```js
// Bad
const server = tls.createServer({
  secureProtocol: "TLSv1_method",
});

// Good
const server = tls.createServer({
  minVersion: "TLSv1.2", // Or TLSv1.3 for maximum security
});
```
```nginx
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;
```
- **False positives:** References to TLS 1.0/1.1 in documentation, changelogs, or comments about disabling them will trigger. The `TLSv1$` pattern (with regex end anchor) may behave differently in multiline content.

---

### CRYPTO-011: Weak PBKDF2 Iterations
- **Severity:** WARNING
- **CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Pattern (context):** `(?i)(?:pbkdf2|deriveKey|key.?deriv)` — must match first.
- **Pattern (iterations):** `(?i)iterations?\s*[:=]\s*(\d+)` — extracted value must be below 600,000.
- **Why:** Low iteration counts make PBKDF2 fast to brute-force. OWASP 2023 recommends 600,000 iterations for SHA-256 and 210,000 for SHA-512.
- **Fix:**
```js
// Bad
crypto.pbkdf2Sync(password, salt, 10000, 32, "sha256");

// Good
crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256");

// Better - use argon2id (GPU-resistant)
const argon2 = require("argon2");
const hash = await argon2.hash(password, { type: argon2.argon2id });
```
- **False positives:** The iteration pattern matches any `iterations = N` near a PBKDF2 context. If a file has both a PBKDF2 call and an unrelated `iterations` variable (e.g., loop iterations), the wrong value may be captured. The first regex match wins.

---

### CRYPTO-012: Static or Reused Nonce
- **Severity:** CRITICAL
- **CWE:** CWE-323 (Reusing a Nonce, Key Pair in Encryption)
- **Pattern:** `(?i)(?:nonce|iv)\s*[:=]\s*['"](?:0+|1234|static|fixed)['"]`
- **Why:** Nonce reuse in GCM mode enables key recovery. In CTR mode, it enables plaintext recovery via XOR of ciphertexts. This completely breaks the encryption.
- **Fix:**
```js
// Bad
const nonce = "000000000000";
const iv = "1234567890abcdef";

// Good - generate unique nonce per encryption
const nonce = crypto.randomBytes(12); // 96-bit for GCM
const iv = crypto.randomBytes(16);    // 128-bit for CBC
```
- **False positives:** Only matches literal strings `0+`, `1234`, `static`, or `fixed` assigned to `nonce` or `iv`. Actual hardcoded hex strings (e.g., `"abcdef1234567890"`) do not trigger unless caught by CRYPTO-003. Test fixtures with placeholder nonces match intentionally.
