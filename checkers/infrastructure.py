"""
0xguard Infrastructure Security Checker
10 checks for deployment, container, and CI/CD security issues.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Infrastructure'

# .env in public directory
ENV_IN_PUBLIC = re.compile(r'(?i)(?:public|static|dist|build|www|htdocs|web)/\.env')

# Docker as root
DOCKER_USER = re.compile(r'(?i)(?:^USER\s+\w+|user:\s+\w+)', re.MULTILINE)
DOCKER_FROM = re.compile(r'^FROM\s+', re.MULTILINE)

# Debug endpoints
DEBUG_ENDPOINT = re.compile(
    r'''(?i)(?:app|router)\s*\.\s*(?:get|post|all)\s*\(\s*['"](?:/debug|/test|/__debug|/phpinfo|/server-info|/health-check-internal)['"]''',
)

# Source maps in production
SOURCEMAP_PROD = re.compile(
    r'''(?i)(?:sourcemap|source-map|devtool)\s*[:=]\s*(?:true|['"](?:source-map|eval-source-map|cheap-module-source-map)['"])''',
)
PROD_CONFIG = re.compile(r'(?i)(?:prod|production|webpack\.prod|vite\.config)')

# Admin without auth
ADMIN_PANEL = re.compile(
    r'''(?i)(?:app|router)\s*\.(?:use|get|post)\s*\(\s*['"](?:/admin|/dashboard|/cms|/panel|/internal)''',
)
AUTH_CHECK = re.compile(r'(?i)(?:auth|authenticate|isAdmin|requireRole|protect|middleware|guard|@login_required)')

# CI/CD write-all permissions
CI_WRITE_ALL = re.compile(r'permissions\s*:\s*write-all', re.IGNORECASE)
CI_PERMISSIONS_BROAD = re.compile(r'permissions\s*:\s*\n\s+(?:contents|packages|actions)\s*:\s*write', re.MULTILINE)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all infrastructure security checks."""
    results = []

    # INF-003: .env in public directory
    if file_path and ENV_IN_PUBLIC.search(file_path):
        results.append(CheckResult(
            check_id='INF-003',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='.env file located in a publicly served directory. Anyone can download your secrets.',
            fix_suggestion='Move .env to the project root (outside public/). Add .env to .gitignore. Configure your server to block dotfiles.',
            cwe='CWE-538',
        ))

    # INF-004: Docker running as root
    if file_path and ('Dockerfile' in file_path or 'dockerfile' in file_path.lower()):
        if DOCKER_FROM.search(content) and not DOCKER_USER.search(content):
            results.append(CheckResult(
                check_id='INF-004',
                severity=Severity.WARNING,
                category=CATEGORY,
                message='Dockerfile has no USER directive. Container runs as root, increasing attack surface.',
                fix_suggestion='Add USER directive: RUN adduser -D appuser && USER appuser. Run as non-root.',
                cwe='CWE-250',
            ))

    # INF-001: Debug endpoints
    if DEBUG_ENDPOINT.search(content):
        results.append(CheckResult(
            check_id='INF-001',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Debug/test endpoint detected. These can expose internal state and should not exist in production.',
            fix_suggestion='Remove debug endpoints or guard with: if (process.env.NODE_ENV === "development") { app.get("/debug", ...) }',
            cwe='CWE-489',
        ))

    # INF-002: Source maps in production
    if SOURCEMAP_PROD.search(content):
        if file_path and PROD_CONFIG.search(file_path):
            results.append(CheckResult(
                check_id='INF-002',
                severity=Severity.WARNING,
                category=CATEGORY,
                message='Source maps enabled in production config. Exposes original source code to anyone.',
                fix_suggestion='Disable source maps in production: devtool: false (webpack), build: { sourcemap: false } (Vite).',
                cwe='CWE-540',
            ))

    # INF-006: Admin panel without auth
    if ADMIN_PANEL.search(content) and not AUTH_CHECK.search(content):
        results.append(CheckResult(
            check_id='INF-006',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Admin/internal panel route without authentication middleware.',
            fix_suggestion='Add auth middleware: app.use("/admin", requireAuth, requireRole("admin"), adminRouter)',
            cwe='CWE-306',
        ))

    # INF-010: CI/CD write-all permissions
    if CI_WRITE_ALL.search(content):
        results.append(CheckResult(
            check_id='INF-010',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='CI/CD workflow has write-all permissions. If compromised, attackers get full repo access.',
            fix_suggestion='Use least-privilege permissions: permissions: { contents: read, packages: write }',
            cwe='CWE-250',
        ))

    return results
