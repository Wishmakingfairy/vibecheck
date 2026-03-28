"""
0xguard Security Headers Checker
11 checks for missing or misconfigured security headers.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Security Headers'

# Debug mode detection
DEBUG_MODE = re.compile(
    r'''(?i)(?:DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV\s*[:=]\s*['"]?development['"]?.*(?:prod|deploy|server)|app\.debug\s*=\s*True)''',
)
# Context: is this in a production config file?
PROD_FILE = re.compile(r'(?i)(?:prod|production|deploy|server\.(?:js|ts|py)|settings\.py|\.env\.prod)')

# Server version disclosure
SERVER_VERSION = re.compile(
    r'''(?i)(?:x-powered-by|server\s*:\s*['"](?:Express|Apache|nginx|PHP|ASP\.NET)|app\.disable\s*\(\s*['"]x-powered-by['"]\s*\))''',
)
SERVER_HIDE = re.compile(r'(?i)(?:app\.disable.*x-powered-by|removeHeader.*server|server_tokens\s+off)')

# Stack traces in errors
STACK_TRACE = re.compile(
    r'''(?i)(?:err(?:or)?\.stack|stackTrace|traceback|\.stack\s*\)|stack\s*:\s*err)''',
)
ERROR_RESPONSE = re.compile(
    r'''(?i)(?:res\.(?:json|send|status)|return.*(?:json|response))''',
)

# Directory listing
DIR_LISTING = re.compile(r'(?i)(?:autoindex\s+on|Options\s+\+?Indexes|directory\s*:\s*true|serveIndex)')


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all security headers checks."""
    results = []

    # HDR-008: Debug mode in production
    if DEBUG_MODE.search(content):
        if file_path and PROD_FILE.search(file_path):
            results.append(CheckResult(
                check_id='HDR-008',
                severity=Severity.CRITICAL,
                category=CATEGORY,
                message='Debug mode enabled in production configuration. Exposes internal errors, stack traces, and sensitive data.',
                fix_suggestion='Set DEBUG=False and NODE_ENV=production for production. Use environment-specific config files.',
                cwe='CWE-489',
            ))

    # HDR-006: Server version disclosure
    if SERVER_VERSION.search(content) and not SERVER_HIDE.search(content):
        results.append(CheckResult(
            check_id='HDR-006',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Server version/framework disclosed in headers. Helps attackers identify known vulnerabilities.',
            fix_suggestion='Express: app.disable("x-powered-by"). Nginx: server_tokens off. Apache: ServerTokens Prod.',
            cwe='CWE-200',
        ))

    # HDR-007: Directory listing
    if DIR_LISTING.search(content):
        results.append(CheckResult(
            check_id='HDR-007',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Directory listing enabled. Exposes file structure to attackers.',
            fix_suggestion='Disable directory listing. Nginx: autoindex off. Apache: Options -Indexes.',
            cwe='CWE-548',
        ))

    # HDR-010: Stack traces in error responses
    if STACK_TRACE.search(content) and ERROR_RESPONSE.search(content):
        results.append(CheckResult(
            check_id='HDR-010',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Stack trace potentially included in error response. Exposes internal code structure.',
            fix_suggestion='Never send stack traces to clients: res.status(500).json({ error: "Internal server error" }). Log full error server-side only.',
            cwe='CWE-209',
        ))

    return results
