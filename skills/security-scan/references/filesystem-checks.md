# File System Security Checks

5 checks for path traversal, unsafe permissions, zip slip, symlink attacks, and temp file safety.

Source: `checkers/filesystem.py`

---

### FS-001: User-Controlled File Path
- **Severity:** CRITICAL
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Pattern:** `(?i)(?:readFile|writeFile|unlink|rmdir|createReadStream)\s*\(.*(?:req\.|query\.|params\.|body\.)` (DOTALL flag enabled)
- **Why:** Passing user input directly to file operations allows path traversal. `../../etc/passwd` reads system files. `../../app/config.js` reads source code. `writeFile` with traversal overwrites arbitrary files.
- **Fix:**
```javascript
// Bad
const filePath = req.query.file;
fs.readFile(filePath, callback);

// Good
const baseDir = path.resolve("/app/uploads");
const requested = path.resolve(baseDir, req.query.file);
if (!requested.startsWith(baseDir)) {
  return res.status(403).json({ error: "Access denied" });
}
fs.readFile(requested, callback);
```
- **False positives:** Files where `req.params.id` is used as a database lookup key that then maps to a safe file path (indirect reference). The regex matches any file operation with request object properties in the arguments, even across multiple lines (DOTALL).

---

### FS-002: Symlink Following Without Check
- **Severity:** WARNING
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **Pattern:** Triggers when `(?i)(?:readFile|writeFile|createReadStream|open|stat)\s*\(` AND `(?i)(?:upload|user.?file|attachment|import|public|static)` both match, AND `(?i)(?:lstat|readlink|isSymbolicLink|followSymlinks\s*[:=]\s*false|no.?follow)` is absent.
- **Why:** An attacker uploads a symlink pointing to `/etc/shadow` or application secrets. When the server reads the "uploaded file," it follows the symlink and serves the target. Requires the file to be in a user-accessible context (uploads, public, static).
- **Fix:**
```javascript
// Bad
const filePath = path.join(uploadDir, filename);
const content = fs.readFileSync(filePath);

// Good
const filePath = path.join(uploadDir, filename);
const stat = fs.lstatSync(filePath);
if (stat.isSymbolicLink()) {
  throw new Error("Symlinks not allowed");
}
const content = fs.readFileSync(filePath);

// Or: use fs.realpath() to resolve and validate
const realPath = fs.realpathSync(filePath);
if (!realPath.startsWith(path.resolve(uploadDir))) {
  throw new Error("Path escape detected");
}
```
- **False positives:** Files that perform file operations on application-internal paths (config loading, template rendering) where "static" or "public" appears as a directory name but symlink attacks are not realistic. The three-pattern AND reduces noise significantly.

---

### FS-003: Predictable Temp File Names
- **Severity:** WARNING
- **CWE:** CWE-377 (Insecure Temporary File)
- **Pattern:** Triggers when `(?i)(?:tmp|temp).*(?:Math\.random|Date\.now|process\.pid)` matches AND `(?i)(?:crypto\.randomBytes|crypto\.randomUUID|uuid|nanoid|secrets\.token)` is absent.
- **Why:** `Math.random()` is not cryptographically random. `Date.now()` is millisecond-precision and guessable. `process.pid` is a small integer. Attackers predict the filename, pre-create a symlink at that path, and hijack the file operation.
- **Fix:**
```javascript
// Bad
const tmpFile = `/tmp/upload-${Date.now()}.txt`;
const tmpFile = `/tmp/data-${Math.random()}.json`;

// Good
import crypto from "crypto";
const tmpFile = path.join(os.tmpdir(), `upload-${crypto.randomBytes(16).toString("hex")}.txt`);

// Better: use a temp file library
import tmp from "tmp-promise";
const { path: tmpFile } = await tmp.file({ postfix: ".txt" });
```
- **False positives:** Test files that create predictable temp names for reproducible test fixtures. The check requires both the tmp/temp context and the weak random source on the same match.

---

### FS-004: chmod 777
- **Severity:** CRITICAL
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Pattern:** `(?:chmod\s+777|0o?777|0777)`
- **Why:** 777 means every user and process on the system can read, write, and execute the file. Malware, other tenants in shared hosting, or compromised services can modify your files. A single `chmod 777` on a config file is a full compromise vector.
- **Fix:**
```bash
# Bad
chmod 777 /app/config.json
fs.chmodSync(filePath, 0o777);

# Good
chmod 644 /app/config.json    # owner read/write, others read-only
chmod 600 /app/.env            # owner read/write only
fs.chmodSync(filePath, 0o644);
```
- **False positives:** Documentation or comments explaining why not to use chmod 777. The regex matches the literal pattern regardless of context. Test files demonstrating bad practices.

---

### FS-005: Zip Slip (Archive Extraction Without Path Validation)
- **Severity:** CRITICAL
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Pattern:** Triggers when `(?i)(?:unzip|extract|decompress|ZipFile|tar\.extract|archiver|yauzl|adm-zip|node-tar)` matches AND `(?i)(?:startsWith|normalize|resolve.*base|\.\.\/|path\.join.*base|sanitize.*path|safe.*path|within)` is absent.
- **Why:** Malicious archives contain entries with names like `../../../etc/cron.d/backdoor`. Without path validation, extraction writes files outside the intended directory. This is a remote code execution vector.
- **Fix:**
```javascript
// Bad
const zip = new AdmZip(uploadedFile);
zip.extractAllTo(destDir);

// Good
const zip = new AdmZip(uploadedFile);
const destResolved = path.resolve(destDir);
for (const entry of zip.getEntries()) {
  const target = path.resolve(destDir, entry.entryName);
  if (!target.startsWith(destResolved + path.sep)) {
    throw new Error(`Zip slip detected: ${entry.entryName}`);
  }
}
zip.extractAllTo(destDir);
```
- **False positives:** Files that import archive libraries for creating archives (not extracting). The path validation check looks for common validation patterns anywhere in the file, so a `startsWith` used for unrelated logic could suppress this finding.
