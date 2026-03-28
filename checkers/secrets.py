"""
preflight Secrets & API Keys Checker
22 checks for hardcoded secrets, API keys, credentials, and sensitive data exposure.

Author: Haralds Gabrans
License: MIT
"""

import os
import re
from typing import List
from checkers import CheckResult, Severity, shannon_entropy

CATEGORY = 'Secrets & API Keys'

# Pre-compiled regex patterns for performance
# Each pattern: (check_id, severity, regex, message, fix, cwe, skip_in_comments)
PATTERNS = [
    # SEC-001: AWS Access Keys
    (
        'SEC-001', Severity.CRITICAL,
        re.compile(r'(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])'),
        'Hardcoded AWS access key detected (AKIA pattern)',
        'Use environment variables: process.env.AWS_ACCESS_KEY_ID or aws-sdk credential provider chain. Never hardcode AWS keys.',
        'CWE-798',
    ),
    # SEC-002: AWS Secret Keys
    (
        'SEC-002', Severity.CRITICAL,
        re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']'),
        'Hardcoded AWS secret access key detected',
        'Use environment variables or AWS credential provider chain. Store in .env (not committed) or AWS Secrets Manager.',
        'CWE-798',
    ),
    # SEC-003: GitHub Tokens
    (
        'SEC-003', Severity.CRITICAL,
        re.compile(r'(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,}'),
        'GitHub personal access token detected',
        'Use GITHUB_TOKEN environment variable. For CI: use GitHub Actions secrets. Never commit tokens.',
        'CWE-798',
    ),
    # SEC-004: Stripe Secret Keys
    (
        'SEC-004', Severity.CRITICAL,
        re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
        'Stripe live secret key detected. This gives full access to your Stripe account.',
        'Use environment variables: process.env.STRIPE_SECRET_KEY. Only use sk_test_ keys in code for testing.',
        'CWE-798',
    ),
    # SEC-005: Frontend env vars exposing secrets
    (
        'SEC-005', Severity.CRITICAL,
        re.compile(r'(?i)(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)[A-Z_]*(SECRET|_KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL)[A-Z_]*\s*[=:]'),
        'Frontend-exposed environment variable contains a secret. These are embedded in the client bundle and visible to anyone.',
        'Move secret to server-side only. Use API routes or server functions to proxy requests. Only expose public/anon keys to the frontend.',
        'CWE-200',
    ),
    # SEC-006: Generic hardcoded passwords
    (
        'SEC-006', Severity.CRITICAL,
        re.compile(r'''(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['"][^'"]{4,}['"]'''),
        'Hardcoded password detected in source code',
        'Use environment variables for credentials. Hash passwords with bcrypt/argon2 before storage. Never store plaintext passwords.',
        'CWE-259',
    ),
    # SEC-007: Private key content
    (
        'SEC-007', Severity.CRITICAL,
        re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----'),
        'Private key embedded in source code',
        'Store private keys in secure key management (AWS KMS, Vault, or .pem files excluded from git). Add *.pem to .gitignore.',
        'CWE-321',
    ),
    # SEC-008: JWT secret hardcoded
    (
        'SEC-008', Severity.CRITICAL,
        re.compile(r'''(?i)jwt[_\-.]?secret\s*[:=]\s*['"][^'"]{8,}['"]'''),
        'JWT signing secret hardcoded in source code',
        'Use environment variable: process.env.JWT_SECRET. Rotate secrets regularly. Use RS256 with key pairs for production.',
        'CWE-798',
    ),
    # SEC-009: Database connection strings with credentials
    (
        'SEC-009', Severity.CRITICAL,
        re.compile(r'(?:mongodb\+srv|postgres(?:ql)?|mysql|mariadb|redis|amqp)://[^:]+:[^@]+@[^\s"\']+'),
        'Database connection string with embedded credentials detected',
        'Use environment variables: process.env.DATABASE_URL. Configure connection via separate host/port/user/password env vars.',
        'CWE-798',
    ),
    # SEC-010: Webhook secrets
    (
        'SEC-010', Severity.WARNING,
        re.compile(r'''(?i)webhook[_\-.]?secret\s*[:=]\s*['"][^'"]{8,}['"]'''),
        'Webhook secret hardcoded in source code',
        'Use environment variable for webhook secrets. Verify webhook signatures using the secret from env vars.',
        'CWE-798',
    ),
    # SEC-011: API keys in URL query parameters
    (
        'SEC-011', Severity.WARNING,
        re.compile(r'[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)=[A-Za-z0-9_\-]{16,}'),
        'API key passed as URL query parameter. URLs are logged in server logs, browser history, and referrer headers.',
        'Pass API keys in request headers (Authorization: Bearer <token>) instead of URL parameters.',
        'CWE-598',
    ),
    # SEC-012: Secrets in Docker ENV
    (
        'SEC-012', Severity.CRITICAL,
        re.compile(r'(?i)ENV\s+(?:\w*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\w*)\s+\S+'),
        'Secret value set directly in Dockerfile ENV instruction. This is baked into the image layers.',
        'Use Docker build args with --build-arg, or better: mount secrets at runtime via docker-compose secrets or env_file.',
        'CWE-798',
    ),
    # SEC-014: Secrets in code comments (context-aware)
    (
        'SEC-014', Severity.WARNING,
        re.compile(r'''(?:\/\/|#|\/\*)\s*(?:password|secret|token|api[_\-]?key)\s*[:=]\s*['"]?\S{8,}['"]?''', re.IGNORECASE),
        'Potential secret found in a code comment',
        'Remove secrets from comments. If documenting API usage, use placeholder values like "your-api-key-here".',
        'CWE-615',
    ),
    # SEC-015: Default/test credentials
    (
        'SEC-015', Severity.CRITICAL,
        re.compile(r'''(?:admin[:/]admin|root[:/]root|password[:/]password|user[:/]pass(?:word)?|test[:/]test123|default[:/]default)''', re.IGNORECASE),
        'Default credentials detected. These are the first thing attackers try.',
        'Remove default credentials. Use strong, unique passwords generated at deployment time.',
        'CWE-1392',
    ),
    # SEC-017: Secrets in Terraform variables
    (
        'SEC-017', Severity.CRITICAL,
        re.compile(r'''(?i)(?:variable|default)\s*[=:]\s*['"][A-Za-z0-9/+=_\-]{20,}['"]'''),
        'Potential secret in Terraform/IaC variable definition',
        'Use terraform.tfvars (gitignored), environment variables (TF_VAR_*), or a secrets manager integration.',
        'CWE-798',
    ),
    # SEC-018: Secrets in GitHub Actions
    (
        'SEC-018', Severity.CRITICAL,
        re.compile(r'''(?i)(?:run|env):\s*.*(?:password|secret|token|key)\s*[:=]\s*['"][^$'"]{8,}['"]'''),
        'Secret value hardcoded in GitHub Actions workflow',
        'Use GitHub Actions secrets: ${{ secrets.MY_SECRET }}. Never hardcode secrets in workflow files.',
        'CWE-798',
    ),
    # SEC-019: Secrets in Kubernetes manifests
    (
        'SEC-019', Severity.CRITICAL,
        re.compile(r'''(?i)(?:data|stringData):\s*\n\s+\w+:\s*['"]?[A-Za-z0-9/+=]{20,}['"]?''', re.MULTILINE),
        'Plaintext secret in Kubernetes manifest',
        'Use SealedSecrets, External Secrets Operator, or reference secrets from a vault. Never commit plain-text K8s secrets.',
        'CWE-798',
    ),
    # SEC-020: Cloud metadata endpoint
    (
        'SEC-020', Severity.CRITICAL,
        re.compile(r'169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com'),
        'Cloud metadata endpoint reference detected. This can be exploited via SSRF to steal cloud credentials.',
        'If legitimate: validate and restrict access. If user input reaches this URL: implement SSRF protections (allowlist, no redirects).',
        'CWE-918',
    ),
    # SEC-021: Supabase service_role key in frontend
    (
        'SEC-021', Severity.CRITICAL,
        re.compile(r'''(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_).*(?:SUPABASE|supabase).*(?:SERVICE[_\-]?ROLE|service[_\-]?role)'''),
        'Supabase service_role key exposed in frontend. This bypasses ALL Row Level Security.',
        'Only expose the SUPABASE_ANON_KEY to the frontend. Keep SERVICE_ROLE_KEY on the server only (API routes, edge functions).',
        'CWE-200',
    ),
    # SEC-022: Google/Firebase service account JSON
    (
        'SEC-022', Severity.CRITICAL,
        re.compile(r'"type"\s*:\s*"service_account"'),
        'Google/Firebase service account JSON detected in source code',
        'Store service account JSON as an environment variable (base64-encoded) or use workload identity federation. Add *-credentials.json to .gitignore.',
        'CWE-798',
    ),
]

# Context patterns that indicate a false positive (example, documentation, etc.)
FALSE_POSITIVE_CONTEXTS = re.compile(
    r'(?i)(?:example|placeholder|your[_\-]?(?:api|secret)|xxx|TODO|FIXME|sample|dummy|fake|mock|test[_\-]?(?:key|token|secret))',
)

# Comment-only line patterns (used for context-aware suppression)
COMMENT_LINE = re.compile(r'^\s*(?://|#|/\*|\*)')
NEGATIVE_COMMENT = re.compile(r'(?i)(?:BAD|DON.T|NEVER|WRONG|INSECURE|VULNERABLE|EXAMPLE OF WHAT NOT)')


def _is_likely_false_positive(line: str, check_id: str) -> bool:
    """Check if a matched line is likely a false positive."""
    # Skip if it contains false-positive indicators
    if FALSE_POSITIVE_CONTEXTS.search(line):
        return True

    # For comment-based secrets (SEC-014), check for negative context
    if check_id == 'SEC-014' and NEGATIVE_COMMENT.search(line):
        return True

    return False


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all secrets checks against the given content."""
    results = []

    # SEC-016: .env file without .gitignore entry (special check)
    if file_path and os.path.basename(file_path).startswith('.env'):
        results.extend(_check_env_gitignore(file_path))

    # SEC-013: High-entropy string detection
    results.extend(_check_entropy(content, file_path))

    # Run regex patterns
    for check_id, severity, pattern, message, fix, cwe in PATTERNS:
        matches = pattern.finditer(content)
        for match in matches:
            # Get the line containing the match for context
            start = content.rfind('\n', 0, match.start()) + 1
            end = content.find('\n', match.end())
            if end == -1:
                end = len(content)
            line = content[start:end]

            # Skip false positives
            if _is_likely_false_positive(line, check_id):
                continue

            results.append(CheckResult(
                check_id=check_id,
                severity=severity,
                category=CATEGORY,
                message=message,
                fix_suggestion=fix,
                cwe=cwe,
                line_hint=line.strip()[:120],
            ))
            break  # One finding per check per file (avoid spam)

    return results


def _check_env_gitignore(file_path: str) -> List[CheckResult]:
    """SEC-016: Check if .env file has a corresponding .gitignore entry."""
    results = []
    env_basename = os.path.basename(file_path)

    # Walk up to find .gitignore
    search_dir = os.path.dirname(os.path.abspath(file_path))
    for _ in range(10):
        gitignore_path = os.path.join(search_dir, '.gitignore')
        if os.path.exists(gitignore_path):
            try:
                with open(gitignore_path, 'r') as f:
                    gitignore_content = f.read()
                # Check if .env is covered
                if '.env' in gitignore_content or env_basename in gitignore_content:
                    return results  # Covered
            except IOError:
                pass
            break
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent

    # No .gitignore or .env not in it
    results.append(CheckResult(
        check_id='SEC-016',
        severity=Severity.CRITICAL,
        category=CATEGORY,
        message=f'{env_basename} file created but .env is not in .gitignore. Your secrets will be committed to git.',
        fix_suggestion='Add .env and .env.* to your .gitignore file immediately. If already committed, rotate all secrets and use git filter-branch to remove from history.',
        cwe='CWE-538',
    ))
    return results


def _check_entropy(content: str, file_path: str) -> List[CheckResult]:
    """SEC-013: Detect high-entropy strings that may be secrets."""
    results = []

    # Pattern: variable assignment with a high-entropy string value
    assignment_pattern = re.compile(
        r'''(?i)(?:api[_\-]?key|secret|token|credential|auth|password|private[_\-]?key)\s*[:=]\s*['"]([A-Za-z0-9/+=_\-]{20,})['"]'''
    )

    for match in assignment_pattern.finditer(content):
        value = match.group(1)
        entropy = shannon_entropy(value)

        if entropy > 4.5 and len(value) >= 20:
            # Get the line for context
            start = content.rfind('\n', 0, match.start()) + 1
            end = content.find('\n', match.end())
            if end == -1:
                end = len(content)
            line = content[start:end]

            # Skip false positives
            if _is_likely_false_positive(line, 'SEC-013'):
                continue

            results.append(CheckResult(
                check_id='SEC-013',
                severity=Severity.WARNING,
                category=CATEGORY,
                message=f'High-entropy string (entropy: {entropy:.1f}) detected near secret-related variable. Likely a hardcoded secret.',
                fix_suggestion='Move this value to an environment variable. Use .env files (gitignored) for local development.',
                cwe='CWE-798',
                line_hint=line.strip()[:120],
            ))
            break  # One entropy finding per file

    return results
