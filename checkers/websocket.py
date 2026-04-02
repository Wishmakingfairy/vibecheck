"""
vibecheck WebSocket Security Checker
4 checks for missing auth, origin validation, message size limits, and heartbeat/timeout.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'WebSocket Security'

# WS-001: WebSocket without authentication
WS_SERVER = re.compile(
    r'(?i)(?:WebSocket|ws\.Server|WebSocketServer|socket\.io|ws\()',
)
WS_AUTH = re.compile(
    r'(?i)(?:auth|token|jwt|verify|middleware|session|authenticate|credentials|cookie)',
)

# WS-002: Missing origin validation
WS_SERVER_SETUP = re.compile(
    r'(?i)(?:ws\.Server|WebSocketServer|new\s+Server)',
)
ORIGIN_CHECK = re.compile(
    r'(?i)(?:verifyClient|origin|allowedOrigins|checkOrigin|handleProtocols)',
)

# WS-003: No message size limit
WS_INSTANCE = re.compile(
    r'(?i)(?:ws|WebSocket|socket)',
)
MAX_PAYLOAD = re.compile(
    r'(?i)(?:maxPayload|maxReceivedFrameSize|maxReceivedMessageSize|maxHttpBufferSize|maxMessageSize)',
)

# WS-004: Missing heartbeat/timeout
HEARTBEAT = re.compile(
    r'(?i)(?:heartbeat|ping|pong|pingInterval|pingTimeout|keepAlive|isAlive|timeout)',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all WebSocket security checks."""
    results = []

    has_ws = WS_SERVER.search(content)
    if not has_ws:
        return results

    # WS-001: WebSocket without authentication
    if not WS_AUTH.search(content):
        results.append(CheckResult(
            check_id='WS-001',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='WebSocket server/connection without authentication. Anyone can connect and send/receive messages.',
            fix_suggestion='Verify auth on connection: wss.on("connection", (ws, req) => { const token = req.headers.authorization; if (!verify(token)) ws.close(); }).',
            cwe='CWE-306',
        ))

    # WS-002: Missing origin validation
    if WS_SERVER_SETUP.search(content) and not ORIGIN_CHECK.search(content):
        results.append(CheckResult(
            check_id='WS-002',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='WebSocket server without origin validation. Malicious sites can open cross-origin WebSocket connections to your server.',
            fix_suggestion='Add origin check: new WebSocketServer({ verifyClient: (info) => allowedOrigins.includes(info.origin) }). Or check origin in the upgrade handler.',
            cwe='CWE-346',
        ))

    # WS-003: No message size limit
    if not MAX_PAYLOAD.search(content):
        results.append(CheckResult(
            check_id='WS-003',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='WebSocket without message size limit. Attackers can send massive payloads to exhaust server memory.',
            fix_suggestion='Set message size limit: new WebSocketServer({ maxPayload: 1024 * 1024 }) // 1MB. For socket.io: { maxHttpBufferSize: 1e6 }.',
            cwe='CWE-400',
        ))

    # WS-004: Missing heartbeat/timeout
    if not HEARTBEAT.search(content):
        results.append(CheckResult(
            check_id='WS-004',
            severity=Severity.INFO,
            category=CATEGORY,
            message='WebSocket without heartbeat or timeout mechanism. Dead connections accumulate and exhaust server resources.',
            fix_suggestion='Implement heartbeat: setInterval(() => { wss.clients.forEach(ws => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); }); }, 30000).',
            cwe='CWE-400',
        ))

    return results
