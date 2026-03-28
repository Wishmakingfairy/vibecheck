# Secrets & API Keys Checks (SEC-001 to SEC-022)

22 checks for hardcoded secrets, API keys, credentials, and sensitive data exposure.

---

### SEC-001: AWS Access Key
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])`
- **Why:** AWS access keys starting with AKIA grant direct access to AWS services; leaked keys are exploited within minutes by automated scanners.
- **Fix:**
```bash
# Use environment variables
export AWS_ACCESS_KEY_ID=AKIA...
```
```javascript
// In code, use the SDK credential provider chain
const { fromEnv } = require("@aws-sdk/credential-provider-env");
const client = new S3Client({ credentials: fromEnv() });
```
- **False positives:** Strings containing "AKIA" followed by exactly 16 uppercase alphanumeric chars in documentation or test fixtures. Mitigated by the false-positive context filter (checks for "example", "placeholder", "sample", "dummy", "mock", "test_key" etc.).

---

### SEC-002: AWS Secret Access Key
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["'][A-Za-z0-9/+=]{40}["']`
- **Why:** The secret key paired with an access key grants full authenticated access to AWS. A single leaked secret key can compromise an entire cloud account.
- **Fix:**
```bash
# .env (gitignored)
AWS_SECRET_ACCESS_KEY=your-secret-here
```
```javascript
// Never hardcode. Use env vars or AWS Secrets Manager.
const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
```
- **False positives:** Variable names matching the pattern but assigned placeholder values. Filtered by the false-positive context check.

---

### SEC-003: GitHub Token
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,}`
- **Why:** GitHub PATs (ghp_, gho_, ghu_, ghs_, ghr_ prefixes) grant repository access, CI/CD control, and potentially org-wide permissions.
- **Fix:**
```yaml
# GitHub Actions: use built-in secrets
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
```javascript
const token = process.env.GITHUB_TOKEN;
```
- **False positives:** Strings that happen to start with gh[pousr]_ in unrelated contexts. The 36+ character minimum length and word boundary anchor reduce noise.

---

### SEC-004: Stripe Live Secret Key
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `sk_live_[A-Za-z0-9]{24,}`
- **Why:** Stripe live secret keys grant full access to payment processing: charges, refunds, customer data, and payouts.
- **Fix:**
```javascript
// Server-side only, from environment
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
```
- **False positives:** Test keys (sk_test_) are intentionally excluded. Only sk_live_ triggers the check. Documentation examples with real-looking keys may trigger; mitigated by false-positive context filter.

---

### SEC-005: Frontend-Exposed Secret in Env Var
- **Severity:** CRITICAL
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Pattern:** `(?i)(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)[A-Z_]*(SECRET|_KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL)[A-Z_]*\s*[=:]`
- **Why:** Environment variables prefixed with NEXT_PUBLIC_, VITE_, REACT_APP_, NUXT_PUBLIC_, or EXPO_PUBLIC_ are embedded in the client-side bundle and visible to anyone inspecting the page source.
- **Fix:**
```env
# Server-side only (no prefix)
STRIPE_SECRET_KEY=sk_live_...

# Safe for frontend (public/anon keys only)
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
```
```javascript
// Proxy through API route
export async function POST(req) {
  const data = await fetch(apiUrl, {
    headers: { Authorization: `Bearer ${process.env.SECRET_KEY}` }
  });
  return Response.json(data);
}
```
- **False positives:** Public keys that contain "KEY" in the name (e.g., NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY). The pattern specifically requires SECRET, PASSWORD, TOKEN, PRIVATE, or CREDENTIAL in the name.

---

### SEC-006: Hardcoded Password
- **Severity:** CRITICAL
- **CWE:** CWE-259 (Use of Hard-coded Password)
- **Pattern:** `(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['"][^'"]{4,}['"]`
- **Why:** Hardcoded passwords in source code are visible to anyone with repository access and cannot be rotated without a code change and redeploy.
- **Fix:**
```javascript
// From environment
const dbPassword = process.env.DB_PASSWORD;

// For user passwords, hash before storage
const hash = await bcrypt.hash(password, 12);
```
- **False positives:** Password validation schemas (e.g., `password: Joi.string().min(8)`), test fixtures, or configuration documentation. Mitigated by false-positive context filter checking for "example", "sample", "dummy", "mock", "test".

---

### SEC-007: Embedded Private Key
- **Severity:** CRITICAL
- **CWE:** CWE-321 (Use of Hard-coded Cryptographic Key)
- **Pattern:** `-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----`
- **Why:** Private keys embedded in source code compromise all cryptographic operations relying on them: TLS, signing, decryption.
- **Fix:**
```bash
# Store in file, excluded from git
echo "*.pem" >> .gitignore
```
```javascript
// Load from file or secrets manager at runtime
const key = fs.readFileSync(process.env.PRIVATE_KEY_PATH);
// Or use AWS KMS / Hashicorp Vault
```
- **False positives:** Documentation showing key format examples. Rare, because the exact PEM header format is very specific.

---

### SEC-008: Hardcoded JWT Secret
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)jwt[_\-.]?secret\s*[:=]\s*['"][^'"]{8,}['"]`
- **Why:** A compromised JWT signing secret lets attackers forge tokens for any user, gaining full access to the application.
- **Fix:**
```javascript
// From environment variable
const token = jwt.sign(payload, process.env.JWT_SECRET, {
  algorithm: "RS256",
  expiresIn: "1h"
});
```
- **False positives:** Config templates with placeholder values like `jwt_secret: "your-secret-here"`. Filtered by false-positive context check.

---

### SEC-009: Database Connection String with Credentials
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?:mongodb\+srv|postgres(?:ql)?|mysql|mariadb|redis|amqp)://[^:]+:[^@]+@[^\s"']+`
- **Why:** Connection strings contain username, password, host, and database name. A single leaked string gives direct database access.
- **Fix:**
```env
# .env (gitignored)
DATABASE_URL=postgresql://user:pass@host:5432/db
```
```javascript
const db = new Pool({ connectionString: process.env.DATABASE_URL });
```
- **False positives:** Example connection strings in documentation or comments. Mitigated by false-positive context filter.

---

### SEC-010: Hardcoded Webhook Secret
- **Severity:** WARNING
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)webhook[_\-.]?secret\s*[:=]\s*['"][^'"]{8,}['"]`
- **Why:** Webhook secrets verify that incoming payloads come from the expected source. A leaked secret allows forged webhooks.
- **Fix:**
```javascript
const secret = process.env.WEBHOOK_SECRET;
const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");
if (sig !== req.headers["x-hub-signature-256"]) throw new Error("Invalid signature");
```
- **False positives:** Test configurations or webhook setup documentation. Filtered by false-positive context check.

---

### SEC-011: API Key in URL Query Parameter
- **Severity:** WARNING
- **CWE:** CWE-598 (Use of GET Request Method With Sensitive Query Strings)
- **Pattern:** `[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)=[A-Za-z0-9_\-]{16,}`
- **Why:** URLs with secrets are logged in server access logs, browser history, referrer headers, and proxy logs. Anyone with log access gets the key.
- **Fix:**
```javascript
// Pass in headers instead
const res = await fetch("https://api.example.com/data", {
  headers: { Authorization: `Bearer ${apiKey}` }
});
```
- **False positives:** URLs in documentation or test fixtures with fake keys. Requires 16+ character key value to reduce noise from short parameter values.

---

### SEC-012: Secret in Dockerfile ENV
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)ENV\s+(?:\w*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\w*)\s+\S+`
- **Why:** Dockerfile ENV instructions bake values into image layers. Anyone who pulls the image can extract all ENV values.
- **Fix:**
```dockerfile
# Use ARG for build-time, mount secrets at runtime
ARG DB_PASSWORD
# Or use docker-compose env_file / secrets
```
```yaml
# docker-compose.yml
services:
  app:
    env_file: .env
    secrets:
      - db_password
```
- **False positives:** ENV instructions setting non-secret values where the variable name happens to contain KEY or TOKEN (e.g., ENV CACHE_KEY_PREFIX). The pattern requires secret-related naming.

---

### SEC-013: High-Entropy String (Shannon Entropy)
- **Severity:** WARNING
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** Looks for variable assignments with secret-related names (`api_key`, `secret`, `token`, `credential`, `auth`, `password`, `private_key`) where the string value is 20+ characters with Shannon entropy > 4.5.
- **Why:** High-entropy strings near secret-related variable names are almost certainly real secrets rather than human-readable configuration values.
- **Fix:**
```javascript
// Move to environment variable
const apiKey = process.env.SERVICE_API_KEY;
```
- **False positives:** Base64-encoded non-secret configuration values or hash constants. The combination of secret-related variable name + high entropy + minimum length significantly reduces false positives. Also filtered by the false-positive context check.

---

### SEC-014: Secret in Code Comment
- **Severity:** WARNING
- **CWE:** CWE-615 (Inclusion of Sensitive Information in Source Code Comments)
- **Pattern:** `(?:\/\/|#|\/\*)\s*(?:password|secret|token|api[_\-]?key)\s*[:=]\s*['"]?\S{8,}['"]?`
- **Why:** Secrets in comments are just as accessible as secrets in code, but are often overlooked during rotation because they are not functional code.
- **Fix:**
```javascript
// BAD: // api_key = "sk_live_abc123..."
// GOOD: // API key loaded from process.env.API_KEY
```
- **False positives:** Comments warning about insecure patterns (e.g., "// DON'T do this: password = '...'"). Mitigated by checking for negative context words (BAD, DON'T, NEVER, WRONG, INSECURE, VULNERABLE).

---

### SEC-015: Default/Test Credentials
- **Severity:** CRITICAL
- **CWE:** CWE-1392 (Use of Default Credentials)
- **Pattern:** `(?:admin[:/]admin|root[:/]root|password[:/]password|user[:/]pass(?:word)?|test[:/]test123|default[:/]default)`
- **Why:** Default credentials are the first thing attackers try. Automated scanners specifically look for admin/admin, root/root, and similar combinations.
- **Fix:**
```javascript
// Generate unique credentials at deployment
const password = crypto.randomBytes(32).toString("hex");
```
- **False positives:** Documentation explaining why default credentials are dangerous, or test files intentionally using these values. Filtered by false-positive context check.

---

### SEC-016: .env File Not in .gitignore
- **Severity:** CRITICAL
- **CWE:** CWE-538 (Insertion of Sensitive Information into Externally-Accessible File or Directory)
- **Pattern:** File-based check. Triggers when the scanned file starts with `.env` and no `.gitignore` in the directory hierarchy contains `.env`.
- **Why:** .env files contain all application secrets. If not gitignored, they will be committed to version control and visible to anyone with repo access.
- **Fix:**
```bash
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore
# If already committed, rotate ALL secrets and remove from history
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch .env' HEAD
```
- **False positives:** .env.example or .env.template files that intentionally contain no real secrets. The check walks up to 10 parent directories looking for a .gitignore that covers .env.

---

### SEC-017: Secret in Terraform/IaC Variable
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)(?:variable|default)\s*[=:]\s*['"][A-Za-z0-9/+=_\-]{20,}['"]`
- **Why:** Hardcoded secrets in Terraform variables are committed to version control and visible in state files, plan output, and CI logs.
- **Fix:**
```hcl
# terraform.tfvars (gitignored)
db_password = "actual-secret"

# main.tf - no default value for secrets
variable "db_password" {
  type      = string
  sensitive = true
}
```
- **False positives:** Non-secret variable defaults that happen to be 20+ character strings (e.g., region names, resource IDs). The broad pattern matches any long string in variable/default assignments. Context filter helps, but IaC files may need review.

---

### SEC-018: Secret in GitHub Actions Workflow
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)(?:run|env):\s*.*(?:password|secret|token|key)\s*[:=]\s*['"][^$'"]{8,}['"]`
- **Why:** Workflow files are committed to the repo. Hardcoded secrets are visible to all contributors and in the full git history.
- **Fix:**
```yaml
# Use GitHub Actions secrets
env:
  API_KEY: ${{ secrets.API_KEY }}
  DATABASE_URL: ${{ secrets.DATABASE_URL }}
```
- **False positives:** The pattern excludes values starting with `$` to avoid matching `${{ secrets.X }}` references. May still trigger on workflow comments or echo statements.

---

### SEC-019: Plaintext Secret in Kubernetes Manifest
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `(?i)(?:data|stringData):\s*\n\s+\w+:\s*['"]?[A-Za-z0-9/+=]{20,}['"]?` (multiline)
- **Why:** Kubernetes Secret manifests with plaintext data are committed to repos. Base64 encoding (used in `data:`) is not encryption.
- **Fix:**
```yaml
# Use SealedSecrets or External Secrets Operator
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
spec:
  encryptedData:
    password: AgBg7...encrypted...
```
- **False positives:** ConfigMap data fields with long non-secret values. The pattern requires 20+ character alphanumeric values under data/stringData keys.

---

### SEC-020: Cloud Metadata Endpoint Reference
- **Severity:** CRITICAL
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Pattern:** `169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com`
- **Why:** Cloud metadata endpoints return IAM credentials, API tokens, and instance configuration. SSRF vulnerabilities targeting these endpoints can escalate to full cloud account compromise.
- **Fix:**
```javascript
// If legitimate access is needed, validate and restrict
const ALLOWED_URLS = new Set(["https://yourdomain.com"]);
function isAllowed(url) {
  const parsed = new URL(url);
  return ALLOWED_URLS.has(parsed.origin);
}

// Block metadata IPs in SSRF protection
const BLOCKED_IPS = ["169.254.169.254", "metadata.google.internal"];
```
- **False positives:** Security documentation, SSRF protection code that references these endpoints to block them, or cloud SDK configuration. Context should be reviewed manually.

---

### SEC-021: Supabase service_role Key in Frontend
- **Severity:** CRITICAL
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Pattern:** `(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_).*(?:SUPABASE|supabase).*(?:SERVICE[_\-]?ROLE|service[_\-]?role)`
- **Why:** The Supabase service_role key bypasses ALL Row Level Security policies. Exposing it in the frontend gives every user full admin access to every table.
- **Fix:**
```env
# Server-side only (no NEXT_PUBLIC_ prefix)
SUPABASE_SERVICE_ROLE_KEY=eyJ...

# Safe for frontend
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
NEXT_PUBLIC_SUPABASE_URL=https://xxx.supabase.co
```
```javascript
// Use anon key on client, service_role on server only
import { createClient } from "@supabase/supabase-js";
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
```
- **False positives:** Unlikely. The pattern specifically matches frontend-prefixed env vars containing both "supabase" and "service_role".

---

### SEC-022: Google/Firebase Service Account JSON
- **Severity:** CRITICAL
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Pattern:** `"type"\s*:\s*"service_account"`
- **Why:** Service account JSON files contain private keys that grant full access to Google Cloud/Firebase resources. Committed keys cannot be rotated without generating a new key.
- **Fix:**
```bash
# Add to .gitignore
echo "*-credentials.json" >> .gitignore
echo "service-account*.json" >> .gitignore
```
```javascript
// Load from env var (base64-encoded)
const creds = JSON.parse(
  Buffer.from(process.env.GOOGLE_CREDENTIALS_B64, "base64").toString()
);
// Or use workload identity federation (no key file needed)
```
- **False positives:** Documentation or schema files describing the service account JSON format. The literal string `"type": "service_account"` is highly specific to actual credential files.
