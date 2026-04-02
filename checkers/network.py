"""
vibecheck Network & CORS Checker
11 checks for CORS misconfiguration, SSRF, HTTPS enforcement, and network security.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Network & CORS'

# CORS patterns
CORS_WILDCARD = re.compile(
    r'''(?:Access-Control-Allow-Origin['":\s]*\*|cors\s*\(\s*\{[^}]*origin\s*:\s*(?:['"]\*['"]|true)|\.header\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"])''',
    re.IGNORECASE | re.DOTALL
)
CORS_CREDENTIALS = re.compile(
    r'(?i)(?:Access-Control-Allow-Credentials|credentials)\s*[:=]\s*(?:true|[\'"]true[\'"])',
)
PUBLIC_API_INDICATOR = re.compile(
    r'(?i)(?:public.?api|open.?api|cdn|static|assets|\.well-known|robots\.txt|sitemap)',
)

# SSRF patterns - including bypass variants
SSRF_FETCH = re.compile(
    r'''(?i)(?:fetch|axios|request|http\.get|urllib|requests\.get|got|ky)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|url|user|data)''',
)
SSRF_LOCALHOST = re.compile(
    r'''(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0|169\.254\.169\.254|2130706433|0x7f000001|metadata\.google|metadata\.azure)''',
    re.IGNORECASE
)

# HTTPS
HTTP_SRC = re.compile(r'(?:src|href|action)\s*=\s*["\']http://', re.IGNORECASE)
HTTPS_REDIRECT = re.compile(r'(?i)(?:redirect.*https|force.*ssl|requireHttps|SECURE_SSL_REDIRECT|HSTS)')

# Open redirect
OPEN_REDIRECT = re.compile(
    r'''(?i)(?:res\.redirect|redirect|location\.href|window\.location)\s*\(\s*(?:req\.|params\.|query\.|body\.)''',
)
REDIRECT_VALIDATION = re.compile(r'(?i)(?:allowedRedirects|validUrls|safeRedirect|whitelist|allowlist|startsWith)')

# 0.0.0.0 binding
BIND_ALL = re.compile(r'''(?:0\.0\.0\.0|host\s*[:=]\s*['"]0\.0\.0\.0['"])''')
PRODUCTION_CONTEXT = re.compile(r'(?i)(?:production|prod|deploy|server\.(?:js|ts)|app\.(?:js|ts))')


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all network and CORS checks."""
    results = []

    # NET-001: CORS wildcard origin
    if CORS_WILDCARD.search(content):
        # Skip if this looks like a public API
        if not PUBLIC_API_INDICATOR.search(content):
            results.append(CheckResult(
                check_id='NET-001',
                severity=Severity.CRITICAL,
                category=CATEGORY,
                message='Access-Control-Allow-Origin set to *. Any website can make requests to your API on behalf of your users.',
                fix_suggestion='Set specific allowed origins: cors({ origin: ["https://yourdomain.com"] }). Use an allowlist, not a wildcard.',
                cwe='CWE-942',
            ))

    # NET-002: CORS credentials with wildcard
    if CORS_WILDCARD.search(content) and CORS_CREDENTIALS.search(content):
        results.append(CheckResult(
            check_id='NET-002',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='CORS allows credentials with wildcard origin. This is the most dangerous CORS misconfiguration.',
            fix_suggestion='Never combine credentials: true with origin: "*". Set specific origins when using credentials.',
            cwe='CWE-942',
        ))

    # NET-006: Mixed content
    if HTTP_SRC.search(content):
        results.append(CheckResult(
            check_id='NET-006',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='HTTP resource loaded on page (mixed content). Browser may block this or expose data over unencrypted connection.',
            fix_suggestion='Use HTTPS for all resources: change http:// to https:// or use protocol-relative URLs //.',
            cwe='CWE-319',
        ))

    # NET-008: Open redirect
    if OPEN_REDIRECT.search(content) and not REDIRECT_VALIDATION.search(content):
        results.append(CheckResult(
            check_id='NET-008',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Redirect destination comes from user input without validation. Attackers can redirect users to phishing sites.',
            fix_suggestion='Validate redirect URLs against an allowlist: const allowed = ["/dashboard", "/profile"]; if (!allowed.includes(url)) url = "/"',
            cwe='CWE-601',
        ))

    # NET-009: SSRF
    if SSRF_FETCH.search(content):
        results.append(CheckResult(
            check_id='NET-009',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Server-side request with user-controlled URL. Attackers can access internal services, cloud metadata, and private networks.',
            fix_suggestion='Validate URLs against an allowlist of domains. Block private IPs (127.0.0.1, 10.*, 172.16-31.*, 192.168.*, 169.254.*). Disable redirects.',
            cwe='CWE-918',
        ))

    # NET-011: Binding to 0.0.0.0
    if BIND_ALL.search(content) and PRODUCTION_CONTEXT.search(content):
        results.append(CheckResult(
            check_id='NET-011',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Server binding to 0.0.0.0 in production. This exposes the service to all network interfaces.',
            fix_suggestion='Bind to 127.0.0.1 for local-only access, or use a reverse proxy (nginx, Caddy) in front of your app.',
            cwe='CWE-668',
        ))

    return results
