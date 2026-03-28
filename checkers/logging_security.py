"""
preflight Logging Security Checker
5 checks for sensitive data in logs, log injection, and production console leaks.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Logging Security'

# LOG-001: Missing structured logging (INFO)
CONSOLE_LOG = re.compile(
    r'console\.log\s*\(',
)
STRUCTURED_LOGGER = re.compile(
    r'(?i)(?:winston|pino|bunyan|log4j|logging\.getLogger|structlog|serilog|morgan)',
)

# LOG-002: Passwords/secrets in logs
PASSWORDS_IN_LOGS = re.compile(
    r'(?i)(?:console\.log|logger\.|print\().*(?:password|secret|token|apiKey|api_key|credit)',
)

# LOG-003: No log level configuration (INFO)
LOG_LEVEL_CONFIG = re.compile(
    r'(?i)(?:log.?level|LOG_LEVEL|level\s*[:=]\s*[\'"](?:debug|info|warn|error)[\'"])',
)

# LOG-004: Log injection (unsanitized user input in logs)
LOG_USER_INPUT = re.compile(
    r'(?i)(?:console\.log|logger\.|logging\.).*(?:req\.|params\.|query\.|body\.|input)',
)
LOG_SANITIZE = re.compile(
    r'(?i)(?:sanitize|escape|encode|replace.*[\n\r]|strip|clean)',
)

# LOG-005: console.log with sensitive vars in production
CONSOLE_LOG_SENSITIVE = re.compile(
    r'(?i)console\.log\s*\(.*(?:user|session|auth|credentials|config|database|connection)',
)
PRODUCTION_GUARD = re.compile(
    r'(?i)(?:process\.env\.NODE_ENV\s*[!=]==?\s*[\'"]production|if\s*\(\s*__DEV__|isDev|isProduction|NODE_ENV)',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all logging security checks."""
    results = []

    # LOG-001: Missing structured logging
    if CONSOLE_LOG.search(content) and not STRUCTURED_LOGGER.search(content):
        results.append(CheckResult(
            check_id='LOG-001',
            severity=Severity.INFO,
            category=CATEGORY,
            message='console.log used without a structured logging library. Unstructured logs are hard to search, filter, and audit.',
            fix_suggestion='Use a structured logger: import pino from "pino"; const logger = pino(); logger.info({ userId, action }, "User logged in").',
            cwe='CWE-778',
        ))

    # LOG-002: Passwords/secrets in logs
    if PASSWORDS_IN_LOGS.search(content):
        results.append(CheckResult(
            check_id='LOG-002',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Password, secret, token, or API key detected in logging statement. Log files are often stored unencrypted and widely accessible.',
            fix_suggestion='Never log sensitive values. Redact: logger.info({ token: "[REDACTED]" }). Use a log redaction library or pino redact option.',
            cwe='CWE-532',
        ))

    # LOG-003: No log level configuration
    if CONSOLE_LOG.search(content) and not LOG_LEVEL_CONFIG.search(content):
        results.append(CheckResult(
            check_id='LOG-003',
            severity=Severity.INFO,
            category=CATEGORY,
            message='No log level configuration detected. Debug logs may leak into production.',
            fix_suggestion='Configure log levels per environment: const logger = pino({ level: process.env.LOG_LEVEL || "info" }). Set to "warn" or "error" in production.',
            cwe='CWE-778',
        ))

    # LOG-004: Log injection
    if LOG_USER_INPUT.search(content) and not LOG_SANITIZE.search(content):
        results.append(CheckResult(
            check_id='LOG-004',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='User input logged without sanitization. Attackers can inject fake log entries or CRLF sequences to forge logs.',
            fix_suggestion='Sanitize user input before logging: logger.info({ input: input.replace(/[\\n\\r]/g, "") }). Use structured logging to separate data from messages.',
            cwe='CWE-117',
        ))

    # LOG-005: console.log with sensitive vars in production
    if CONSOLE_LOG_SENSITIVE.search(content) and not PRODUCTION_GUARD.search(content):
        results.append(CheckResult(
            check_id='LOG-005',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='console.log with sensitive variables (user, session, auth, config) without production environment guard.',
            fix_suggestion='Guard debug logging: if (process.env.NODE_ENV !== "production") console.log(...). Better: use a logger with level config.',
            cwe='CWE-532',
        ))

    return results
