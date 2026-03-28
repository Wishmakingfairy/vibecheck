# Supply Chain Checks Reference

9 active checks out of 15 reserved IDs: SUP-001, SUP-002, SUP-004, SUP-005, SUP-006, SUP-011, SUP-012, SUP-013, SUP-015.

---

### SUP-001: Typosquatted Package
- **Severity:** CRITICAL
- **CWE:** CWE-1357 (Reliance on Insufficiently Trustworthy Component)
- **Pattern:** Exact string match against a curated blocklist of ~50 known typosquats (e.g., `lodahs`, `espress`, `reacr`, `axois`, `reqeusts`, `djnago`). Matches `"typo"` or `'typo'` in file content.
- **File gate:** Only fires on files containing `package.json` in their path.
- **Why:** Typosquatted packages impersonate popular libraries and execute malicious code on install (credential theft, cryptominers, backdoors).
- **Fix:**
```json
{
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.2"
  }
}
```
Verify every package name before adding: `npm info <package>` and check the npm page.
- **False positives:** Only fires on exact matches from the curated list. A legitimate package that happens to share a name with a typosquat entry would trigger. The list is conservative and maintained manually.

---

### SUP-002: Suspicious Install Script
- **Severity:** WARNING
- **CWE:** CWE-506 (Embedded Malicious Code)
- **Pattern:** `["'](?:postinstall|preinstall|install)["']\s*:\s*["'](?:.*(?:curl|wget|bash|sh|node\s+-e|python\s+-c|eval))`
- **File gate:** Only fires on `package.json` files.
- **Why:** Install scripts run automatically on `npm install`. Malicious packages use them to download and execute payloads.
- **Fix:**
```bash
# Install with scripts disabled for untrusted packages
npm install --ignore-scripts <package>

# Or globally
npm config set ignore-scripts true

# Then manually run trusted scripts
npm run postinstall
```
- **False positives:** Legitimate build tools (node-gyp, esbuild) use install scripts with shell commands. Review the actual script content before dismissing.

---

### SUP-004: CDN Script Without SRI
- **Severity:** WARNING
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Pattern (CDN):** `<script[^>]*src\s*=\s*["\']https?://(?:cdn|unpkg|jsdelivr|cdnjs|cloudflare)`
- **Pattern (SRI):** `integrity\s*=\s*["\']sha` — if present, check does not fire.
- **File gate:** Only fires on `.html` / `.htm` files.
- **Why:** If a CDN is compromised or serves a modified file, malicious JavaScript runs in your users' browsers. SRI ensures the file hash matches what you expect.
- **Fix:**
```html
<!-- Bad -->
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>

<!-- Good -->
<script
  src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
  integrity="sha384-..."
  crossorigin="anonymous"
></script>
```
Generate hashes at https://www.srihash.org/
- **False positives:** Does not distinguish between `<script>` tags in comments or template literals vs actual HTML. Fires if any CDN script lacks SRI in the same file, even if a different script has it.

---

### SUP-005: Wildcard Dependency Version
- **Severity:** WARNING
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Pattern:** `["'][^"']+["']\s*:\s*["']\*["']`
- **File gate:** Only fires on `package.json` files.
- **Why:** A `*` version accepts any published version, including a malicious one pushed by an attacker who compromises the package.
- **Fix:**
```json
{
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "~4.18.2"
  }
}
```
Use `^` (compatible) or `~` (patch-only) ranges. Pin exact versions for maximum security: `"4.17.21"`.
- **False positives:** Could match non-dependency fields in package.json that use `"*"` as a value (e.g., custom config keys). Rare in practice.

---

### SUP-006: Git URL Dependency
- **Severity:** WARNING
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Pattern:** `["'][^"']+["']\s*:\s*["'](?:git\+|git://|github:|https://github\.com)`
- **File gate:** Only fires on `package.json` files.
- **Why:** Git URL dependencies point to a branch (usually main). The code can change without any version bump or audit trail.
- **Fix:**
```json
{
  "dependencies": {
    "my-lib": "github:user/repo#a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  }
}
```
Pin to a full commit SHA. Better: publish to npm with proper versioning.
- **False positives:** Fires on any git URL dependency, including internal/private repos that are well-controlled. Intentional; even internal repos should pin commits.

---

### SUP-011: Unpinned GitHub Actions
- **Severity:** WARNING
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Pattern:** `uses:\s*[\w-]+/[\w-]+@(?:main|master|latest|dev|HEAD)`
- **File gate:** Only fires on `.yml` / `.yaml` files.
- **Why:** A compromised action maintainer can push malicious code to `main`. If you reference `@main`, your CI immediately runs the compromised code.
- **Fix:**
```yaml
# Bad
- uses: actions/checkout@main

# Good - pinned to full commit SHA with version comment
- uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.1
```
Use [StepSecurity Harden Runner](https://github.com/step-security/harden-runner) to auto-pin.
- **False positives:** Fires on any mutable ref. Actions maintained by your own organization still trigger, which is intentional since the risk exists regardless of trust level.

---

### SUP-012: Docker FROM Without Version Pin
- **Severity:** WARNING
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Pattern:** `FROM\s+\w+(?::\s*latest\s*$|(?![@:]))` (multiline)
- **File gate:** Only fires on files with `Dockerfile` in the path or `docker` in the lowercased path.
- **Why:** `FROM node` or `FROM node:latest` pulls whatever the current latest tag is. A supply chain attack on the base image propagates to your container.
- **Fix:**
```dockerfile
# Bad
FROM node
FROM node:latest

# Good - pinned version
FROM node:20-alpine

# Best - pinned version + digest
FROM node:20-alpine@sha256:abc123...
```
- **False positives:** The regex may miss `FROM` statements with complex multi-stage names. It may also false-positive on `FROM scratch` which has no version, though `scratch` is safe. The `(?![@:])` lookahead prevents firing when a version tag or digest is present.

---

### SUP-013: Curl Pipe to Shell
- **Severity:** CRITICAL
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Pattern:** `(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh|sudo\s+bash|sudo\s+sh)`
- **File gate:** Only fires on Dockerfiles, Makefiles, and `.sh` files.
- **Why:** Piping a URL directly to a shell executes whatever the server returns. A MITM attack, DNS hijack, or compromised server injects arbitrary commands.
- **Fix:**
```bash
# Bad
curl -sSL https://example.com/install.sh | bash

# Good
curl -sSL -o install.sh https://example.com/install.sh
echo "expected_sha256  install.sh" | sha256sum -c -
bash install.sh
```
- **False positives:** Fires on any curl-pipe-shell pattern, including well-known installers (rustup, nvm). Intentional; even trusted sources should be verified.

---

### SUP-015: Known Malicious Package
- **Severity:** CRITICAL
- **CWE:** CWE-506 (Embedded Malicious Code)
- **Pattern:** Exact string match against a blocklist of 12 confirmed malicious packages: `event-stream`, `flatmap-stream`, `ua-parser-js`, `coa`, `rc`, `colors-hierarchical`, `crossenv`, `cross-env.js`, `fabric-js`, `grpc-tools-node`, `discord.js-selfbot-v14`, `http-proxy-agent-v4`.
- **File gate:** Only fires on `package.json` files.
- **Why:** These packages were involved in confirmed supply chain attacks. Some are hijacked versions of legitimate packages; others were created solely to distribute malware.
- **Fix:**
```bash
# Remove immediately
npm uninstall <malicious-package>

# Check npm advisories for safe alternatives
npm audit
```
- **False positives:** Very low. The list contains only confirmed malicious package names. Note: `ua-parser-js`, `coa`, and `rc` were hijacked temporarily; current versions may be safe, but the check flags them for manual review.

---

## Reserved IDs (not yet implemented)

| ID | Planned Check |
|----|--------------|
| SUP-003 | Lockfile tampering (integrity mismatch) |
| SUP-007 | Private registry fallback to public |
| SUP-008 | Dependency confusion (.npmrc missing scope registry) |
| SUP-009 | Abandoned dependency (no updates > 2 years) |
| SUP-010 | Excessive dependency permissions |
| SUP-014 | Unsigned commits in CI |
