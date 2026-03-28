# Logging Security Checks

5 checks for sensitive data in logs, log injection, and production console leaks.

Source: `checkers/logging_security.py`

---

### LOG-001: Missing Structured Logging
- **Severity:** INFO
- **CWE:** CWE-778 (Insufficient Logging)
- **Pattern:** Triggers when `console\.log\s*\(` matches AND `(?i)(?:winston|pino|bunyan|log4j|logging\.getLogger|structlog|serilog|morgan)` is absent from the file.
- **Why:** Unstructured console.log output cannot be searched, filtered by level, or parsed by log aggregators. Incident response becomes guesswork when you cannot query logs.
- **Fix:**
```javascript
// Bad
console.log("User logged in", userId);

// Good
import pino from "pino";
const logger = pino();
logger.info({ userId, action: "login" }, "User logged in");
```
- **False positives:** Small scripts, CLI tools, or frontend code where console.log is appropriate. The check fires on any file with console.log that does not also reference a structured logging library.

---

### LOG-002: Passwords/Secrets in Logs
- **Severity:** CRITICAL
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Pattern:** `(?i)(?:console\.log|logger\.|print\().*(?:password|secret|token|apiKey|api_key|credit)`
- **Why:** Log files are stored in plaintext, shipped to third-party services (Datadog, CloudWatch, ELK), and accessible to operations teams. A leaked token in logs is a leaked token in production.
- **Fix:**
```javascript
// Bad
console.log("Auth token:", token);
logger.debug("API response", { apiKey, secret });

// Good
logger.info("Auth token issued", { tokenId: token.id }); // log ID, not value
// Or use pino redact:
const logger = pino({ redact: ["password", "secret", "token", "apiKey"] });
```
- **False positives:** Logging the word "token" or "password" as a field name in an error message without the actual value (e.g., `logger.error("password field is required")`). The regex matches keyword proximity on the same line.

---

### LOG-003: No Log Level Configuration
- **Severity:** INFO
- **CWE:** CWE-778 (Insufficient Logging)
- **Pattern:** Triggers when `console\.log\s*\(` matches AND `(?i)(?:log.?level|LOG_LEVEL|level\s*[:=]\s*['"](?:debug|info|warn|error)['"])` is absent from the file.
- **Why:** Without configurable log levels, debug logs leak into production. Debug output often contains request bodies, database queries, and internal state that assists attackers.
- **Fix:**
```javascript
// Bad
console.log("Debug: request body", req.body);

// Good
const logger = pino({ level: process.env.LOG_LEVEL || "info" });
logger.debug({ body: req.body }, "Incoming request"); // only visible when LOG_LEVEL=debug
```
- **False positives:** Files that use console.log for build scripts, migrations, or CLI output where log level configuration is irrelevant. Often co-fires with LOG-001 since both detect console.log without a proper logger.

---

### LOG-004: Log Injection
- **Severity:** WARNING
- **CWE:** CWE-117 (Improper Output Neutralization for Logs)
- **Pattern:** Triggers when `(?i)(?:console\.log|logger\.|logging\.).*(?:req\.|params\.|query\.|body\.|input)` matches AND `(?i)(?:sanitize|escape|encode|replace.*[\n\r]|strip|clean)` is absent from the file.
- **Why:** Attackers inject newlines and fake log entries via user input. A crafted username like `admin\n[INFO] Payment approved for order 9999` forges log entries, breaking audit trails and misleading incident responders.
- **Fix:**
```javascript
// Bad
logger.info("User login: " + req.body.username);

// Good: structured logging separates data from message
logger.info({ username: req.body.username.replace(/[\n\r]/g, "") }, "User login");
// Or use structured logging where data is JSON-encoded automatically
logger.info({ username: req.body.username }, "User login"); // pino JSON-encodes values
```
- **False positives:** Files using structured loggers (pino, winston) that automatically JSON-encode values, preventing injection. The sanitization check looks for explicit sanitize/escape/encode keywords but does not detect implicit JSON encoding by the logger.

---

### LOG-005: Sensitive Console.log Without Production Guard
- **Severity:** WARNING
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Pattern:** Triggers when `(?i)console\.log\s*\(.*(?:user|session|auth|credentials|config|database|connection)` matches AND `(?i)(?:process\.env\.NODE_ENV\s*[!=]==?\s*['"]production|if\s*\(\s*__DEV__|isDev|isProduction|NODE_ENV)` is absent from the file.
- **Why:** console.log with user sessions, auth state, or database config that runs unconditionally in production exposes internal state. Browser console is visible to anyone with DevTools. Server logs persist indefinitely.
- **Fix:**
```javascript
// Bad
console.log("DB connection", connectionString);
console.log("User session", session);

// Good
if (process.env.NODE_ENV !== "production") {
  console.log("DB connection", connectionString);
}

// Better: use a logger with level config (eliminates the problem entirely)
logger.debug({ session }, "Session state");
```
- **False positives:** Files that set `NODE_ENV` at the top or in a config import not matched by the regex. Also fires on frontend files where "config" or "user" appear in console.log for non-sensitive display data.
