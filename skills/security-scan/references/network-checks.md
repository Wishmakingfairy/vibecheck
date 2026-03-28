# Network & CORS Checks (NET-001 to NET-011)

11 checks for CORS misconfiguration, SSRF, HTTPS enforcement, and network security.

---

### NET-001: CORS Wildcard Origin
- **Severity:** CRITICAL
- **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- **Pattern:** `Access-Control-Allow-Origin: *`, `cors({ origin: "*" })`, `cors({ origin: true })`, or `.header("Access-Control-Allow-Origin", "*")`
- **Why:** Any website can make authenticated requests to your API. Combined with cookies or auth headers, this lets attacker-controlled sites steal user data.
- **Fix:**
```javascript
const cors = require("cors");
app.use(cors({
  origin: ["https://yourdomain.com", "https://app.yourdomain.com"],
  credentials: true,
}));

// Or dynamic validation
app.use(cors({
  origin: (origin, cb) => {
    const allowed = ["https://yourdomain.com"];
    cb(null, allowed.includes(origin));
  },
}));
```
- **False positives:** Intentionally public APIs (CDNs, open data APIs, static asset servers). Mitigated by checking for `public_api`, `cdn`, `static`, `assets`, `.well-known` indicators in the same file; these are skipped.

---

### NET-002: CORS Credentials With Wildcard
- **Severity:** CRITICAL
- **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- **Pattern:** Both `origin: "*"` (or `Access-Control-Allow-Origin: *`) AND `credentials: true` (or `Access-Control-Allow-Credentials: true`) detected
- **Why:** The single most dangerous CORS misconfiguration. Browsers technically block this combination, but misconfigurations in proxies, or reflecting the Origin header, can bypass the browser's safeguard.
- **Fix:**
```javascript
// NEVER combine wildcard with credentials
app.use(cors({
  origin: "https://yourdomain.com", // Specific origin, not "*"
  credentials: true,
}));
```
- **False positives:** Extremely unlikely. This combination is always wrong. Even if the browser blocks it, the server config reveals a misunderstanding of CORS that likely manifests elsewhere.

---

### NET-006: Mixed Content (HTTP Resources)
- **Severity:** WARNING
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
- **Pattern:** `(?:src|href|action)\s*=\s*["\']http://`
- **Why:** HTTP resources on HTTPS pages are either blocked by the browser (active mixed content) or expose data to network eavesdroppers (passive mixed content).
- **Fix:**
```html
<!-- BAD -->
<script src="http://cdn.example.com/lib.js"></script>
<img src="http://images.example.com/photo.jpg" />

<!-- GOOD -->
<script src="https://cdn.example.com/lib.js"></script>
<img src="https://images.example.com/photo.jpg" />

<!-- ALSO GOOD: protocol-relative (inherits page protocol) -->
<script src="//cdn.example.com/lib.js"></script>
```
- **False positives:** Development-only files referencing localhost over HTTP. HTML email templates where HTTPS may not be available. Documentation examples.

---

### NET-008: Open Redirect
- **Severity:** WARNING
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **Pattern:** Redirect functions (`res.redirect`, `redirect`, `location.href`, `window.location`) receiving user input (`req.query`, `req.params`, `req.body`) without validation (`allowedRedirects`, `validUrls`, `safeRedirect`, `whitelist`, `allowlist`, `startsWith`)
- **Why:** Attackers craft URLs like `yoursite.com/redirect?url=evil.com` to phish users. The trusted domain makes the phishing link look legitimate.
- **Fix:**
```javascript
const ALLOWED_REDIRECTS = ["/dashboard", "/profile", "/settings"];

app.get("/redirect", (req, res) => {
  const target = req.query.url;
  // Option 1: Allowlist of paths
  if (!ALLOWED_REDIRECTS.includes(target)) {
    return res.redirect("/");
  }
  // Option 2: Ensure same-origin
  const url = new URL(target, `https://${req.hostname}`);
  if (url.hostname !== req.hostname) {
    return res.redirect("/");
  }
  res.redirect(target);
});
```
- **False positives:** Internal redirects using server-side constants that happen to be in a variable from req context. The check requires both redirect usage and user input in the same expression.

---

### NET-009: Server-Side Request Forgery (SSRF)
- **Severity:** CRITICAL
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Pattern:** HTTP client functions (`fetch`, `axios`, `request`, `http.get`, `urllib`, `requests.get`, `got`, `ky`) receiving user-controlled input (`req.`, `params.`, `query.`, `body.`, `input`, `url`, `user`, `data`)
- **Why:** Attackers use your server as a proxy to access internal services (databases, admin panels, cloud metadata at 169.254.169.254), bypassing firewalls.
- **Fix:**
```javascript
const { URL } = require("url");
const dns = require("dns").promises;

async function safeFetch(userUrl) {
  const parsed = new URL(userUrl);

  // Block private/internal IPs
  const { address } = await dns.lookup(parsed.hostname);
  const blocked = [/^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^169\.254\./];
  if (blocked.some(r => r.test(address))) {
    throw new Error("Internal addresses blocked");
  }

  // Allowlist domains if possible
  const allowed = ["api.example.com", "cdn.example.com"];
  if (!allowed.includes(parsed.hostname)) {
    throw new Error("Domain not allowed");
  }

  return fetch(userUrl, { redirect: "error" }); // Disable redirects
}
```
- **False positives:** Fetch calls where the "user" variable name matches incidentally (e.g., fetching a user profile from a hardcoded API). The broad input keywords (`url`, `user`, `data`) increase recall at the cost of precision.

---

### NET-011: Binding to 0.0.0.0 in Production
- **Severity:** WARNING
- **CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)
- **Pattern:** `0.0.0.0` or `host: "0.0.0.0"` in files that also contain production context indicators (`production`, `prod`, `deploy`, `server.js`, `app.js`)
- **Why:** Binding to 0.0.0.0 exposes the service on all network interfaces, including public ones. Without a reverse proxy, the raw Node/Python server is directly accessible.
- **Fix:**
```javascript
// Bind to loopback only, use reverse proxy for external access
const host = process.env.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0";
app.listen(3000, host);
```
```nginx
# nginx reverse proxy handles external traffic
server {
    listen 443 ssl;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
```
- **False positives:** Docker containers where 0.0.0.0 is required to accept connections from the Docker network. Files named `server.js` in development-only contexts. The check requires both the bind pattern and production context in the same file.
