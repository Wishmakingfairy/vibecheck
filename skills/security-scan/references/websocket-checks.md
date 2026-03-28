# WebSocket Security Checks

4 checks for missing auth, origin validation, message size limits, and heartbeat/timeout.

All checks require a WebSocket server/connection to be detected first via `(?i)(?:WebSocket|ws\.Server|WebSocketServer|socket\.io|ws\()`. If no WebSocket code is found, no checks run.

Source: `checkers/websocket.py`

---

### WS-001: WebSocket Without Authentication
- **Severity:** WARNING
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Pattern:** Triggers when a WebSocket server is detected AND `(?i)(?:auth|token|jwt|verify|middleware|session|authenticate|credentials|cookie)` is absent from the file.
- **Why:** WebSocket connections bypass traditional HTTP middleware. Without explicit auth on the connection handler, anyone can connect, receive real-time data, and send commands. Unlike HTTP, a single open connection persists indefinitely.
- **Fix:**
```javascript
// Bad
wss.on("connection", (ws) => {
  ws.on("message", handleMessage);
});

// Good
wss.on("connection", (ws, req) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const user = jwt.verify(token, SECRET);
    ws.userId = user.id;
  } catch {
    ws.close(4001, "Unauthorized");
    return;
  }
  ws.on("message", handleMessage);
});
```
- **False positives:** Files that handle auth in a separate middleware or upgrade handler imported from another module. The check only looks within the same file for auth-related keywords.

---

### WS-002: Missing Origin Validation
- **Severity:** WARNING
- **CWE:** CWE-346 (Origin Validation Error)
- **Pattern:** Triggers when `(?i)(?:ws\.Server|WebSocketServer|new\s+Server)` matches AND `(?i)(?:verifyClient|origin|allowedOrigins|checkOrigin|handleProtocols)` is absent from the file.
- **Why:** Unlike HTTP with CORS, WebSocket has no built-in origin restriction. A malicious page on evil.com can open a WebSocket to your server, and the browser will send cookies along. This enables cross-site WebSocket hijacking.
- **Fix:**
```javascript
// Bad
const wss = new WebSocketServer({ port: 8080 });

// Good
const allowedOrigins = ["https://myapp.com", "https://staging.myapp.com"];

const wss = new WebSocketServer({
  port: 8080,
  verifyClient: (info) => {
    return allowedOrigins.includes(info.origin);
  }
});
```
- **False positives:** Internal services or microservice-to-microservice WebSocket connections where origin validation is not applicable. Also, socket.io handles some origin checks via its cors config, which may not match the regex.

---

### WS-003: No Message Size Limit
- **Severity:** WARNING
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Pattern:** Triggers when a WebSocket server is detected AND `(?i)(?:maxPayload|maxReceivedFrameSize|maxReceivedMessageSize|maxHttpBufferSize|maxMessageSize)` is absent from the file.
- **Why:** Without a size limit, an attacker sends a single multi-gigabyte message that exhausts server memory. Node.js will buffer the entire message before the `message` event fires. One connection can crash the entire server.
- **Fix:**
```javascript
// Bad
const wss = new WebSocketServer({ port: 8080 });

// Good: ws library
const wss = new WebSocketServer({
  port: 8080,
  maxPayload: 1024 * 1024 // 1MB limit
});

// Good: socket.io
const io = new Server(httpServer, {
  maxHttpBufferSize: 1e6 // 1MB limit
});
```
- **False positives:** Files that set size limits at the reverse proxy level (nginx `client_max_body_size`) rather than in application code. The check only inspects the current file for size-related configuration keywords.

---

### WS-004: Missing Heartbeat/Timeout
- **Severity:** INFO
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Pattern:** Triggers when a WebSocket server is detected AND `(?i)(?:heartbeat|ping|pong|pingInterval|pingTimeout|keepAlive|isAlive|timeout)` is absent from the file.
- **Why:** Clients disconnect without sending a close frame (network drop, browser crash, mobile backgrounding). Without heartbeat detection, these dead connections accumulate. Each holds memory, file descriptors, and potentially database connections. Over hours, this causes resource exhaustion.
- **Fix:**
```javascript
// Bad: no cleanup of dead connections
wss.on("connection", (ws) => { /* ... */ });

// Good: heartbeat with ws library
wss.on("connection", (ws) => {
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });
});

const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on("close", () => clearInterval(interval));

// Good: socket.io (built-in, just configure)
const io = new Server(httpServer, {
  pingInterval: 25000,
  pingTimeout: 20000
});
```
- **False positives:** socket.io has built-in heartbeat enabled by default, so files using socket.io without explicit pingInterval/pingTimeout config are still protected. The check may flag these unless "ping" or "timeout" appears somewhere in the file.
