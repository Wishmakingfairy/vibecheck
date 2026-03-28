"""
preflight Authentication & Authorization Checker
20 checks for auth vulnerabilities: JWT misuse, session security, OAuth, CSRF, rate limiting.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Authentication'

# JWT checks
JWT_SIGN_NO_EXPIRY = re.compile(
    r'jwt\.sign\s*\([^)]*\)',
    re.DOTALL
)
JWT_SIGN_WITH_EXPIRY = re.compile(
    r'jwt\.sign\s*\([^)]*(?:expiresIn|exp)\s*:',
    re.DOTALL
)
JWT_ALG_NONE = re.compile(
    r'''(?i)(?:alg(?:orithm)?|algorithms?)\s*[:=]\s*['"\[]?\s*['"]?none['"]?''',
)
JWT_LOCALSTORAGE = re.compile(
    r'''localStorage\.setItem\s*\(\s*['"](?:token|jwt|access_token|auth_token|id_token)['"]''',
    re.IGNORECASE
)

# OAuth
OAUTH_NO_STATE = re.compile(
    r'(?i)(?:oauth|authorize|authorization_url|auth_url).*(?:redirect|callback)',
)
OAUTH_STATE_PRESENT = re.compile(
    r'(?i)state\s*[:=]',
)

# CSRF
FORM_POST = re.compile(r'<form[^>]*method\s*=\s*["\']?post', re.IGNORECASE)
CSRF_TOKEN = re.compile(r'(?i)(?:csrf|_token|xsrf|anti.?forgery)', re.IGNORECASE)

# Rate limiting
LOGIN_ROUTE = re.compile(
    r'''(?:app|router|server)\s*\.\s*(?:post|put)\s*\(\s*['"](?:/(?:api/)?(?:auth/)?(?:login|signin|sign-in|signup|sign-up|register|authenticate))['"]''',
    re.IGNORECASE
)
RATE_LIMIT_MIDDLEWARE = re.compile(
    r'(?i)(?:rateLimit|rate_limit|rateLimiter|throttle|slowDown|express-rate-limit|@nestjs/throttler|limiter)',
)

# Session
SESSION_REGENERATE = re.compile(r'(?i)(?:session\.regenerate|regenerateSession|req\.session\.regenerate)')
SESSION_EXPIRY = re.compile(r'(?i)(?:maxAge|expires|cookie.*(?:max.?age|expir)|session.*(?:timeout|ttl|expir|max.?age))')

# Password
WEAK_PASSWORD_RE = re.compile(r'''(?i)(?:minlength|min.?length|min.?len)\s*[:=]\s*['"]?([1-7])['"]?''')
PASSWORD_REVERSIBLE = re.compile(r'''(?i)(?:encrypt|cipher|aes|des|rc4)\s*\(\s*(?:password|passwd|pwd)''')

# Cookie flags
SET_COOKIE = re.compile(r'''(?i)(?:set-cookie|cookie|session)\s*[:=]''')
COOKIE_SECURE = re.compile(r'(?i)(?:secure\s*:\s*true|Secure)')
COOKIE_HTTPONLY = re.compile(r'(?i)(?:httpOnly\s*:\s*true|HttpOnly)')
COOKIE_SAMESITE = re.compile(r'(?i)(?:sameSite|SameSite)')

# Re-auth
SENSITIVE_OP = re.compile(r'''(?i)(?:change.?password|update.?email|delete.?account|disable.?mfa|update.?payment)''')
REAUTH_CHECK = re.compile(r'(?i)(?:verify.?password|confirm.?password|re.?auth|current.?password)')

# Magic link
MAGIC_LINK = re.compile(r'(?i)(?:magic.?link|passwordless|login.?link|sign.?in.?link)')
TOKEN_EXPIRY = re.compile(r'(?i)(?:expir|ttl|max.?age|valid.?until)')


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all authentication checks."""
    results = []

    # AUTH-001: Login route without rate limiting
    if LOGIN_ROUTE.search(content) and not RATE_LIMIT_MIDDLEWARE.search(content):
        results.append(CheckResult(
            check_id='AUTH-001',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Login/signup route detected without rate limiting middleware. Attackers can brute-force credentials.',
            fix_suggestion='Add rate limiting: app.use("/api/auth", rateLimit({ windowMs: 15*60*1000, max: 5 })). Use express-rate-limit or Upstash ratelimit.',
            cwe='CWE-307',
        ))

    # AUTH-007: JWT sign without expiry
    if JWT_SIGN_NO_EXPIRY.search(content) and not JWT_SIGN_WITH_EXPIRY.search(content):
        results.append(CheckResult(
            check_id='AUTH-007',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='jwt.sign() called without expiresIn/exp. Tokens never expire, giving attackers permanent access.',
            fix_suggestion='Add expiry: jwt.sign(payload, secret, { expiresIn: "1h" }). Use short-lived access tokens (15m-1h) with refresh tokens.',
            cwe='CWE-613',
        ))

    # AUTH-008: JWT algorithm none
    if JWT_ALG_NONE.search(content):
        results.append(CheckResult(
            check_id='AUTH-008',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='JWT algorithm set to "none". This disables signature verification entirely.',
            fix_suggestion='Use a strong algorithm: { algorithm: "RS256" } or { algorithm: "ES256" }. Never allow "none".',
            cwe='CWE-345',
        ))

    # AUTH-009: JWT in localStorage
    if JWT_LOCALSTORAGE.search(content):
        results.append(CheckResult(
            check_id='AUTH-009',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='JWT stored in localStorage. Any XSS vulnerability can steal the token.',
            fix_suggestion='Store tokens in httpOnly, secure, sameSite cookies instead. This makes them inaccessible to JavaScript.',
            cwe='CWE-922',
        ))

    # AUTH-010: Form without CSRF
    if FORM_POST.search(content) and not CSRF_TOKEN.search(content):
        results.append(CheckResult(
            check_id='AUTH-010',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='POST form detected without CSRF token. Attackers can trick users into submitting malicious requests.',
            fix_suggestion='Add CSRF protection: include a hidden _csrf token field in forms. Use csurf middleware or SameSite=Strict cookies.',
            cwe='CWE-352',
        ))

    # AUTH-015: OAuth without state parameter
    if OAUTH_NO_STATE.search(content) and not OAUTH_STATE_PRESENT.search(content):
        results.append(CheckResult(
            check_id='AUTH-015',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='OAuth flow detected without state parameter. Vulnerable to CSRF attacks on the callback.',
            fix_suggestion='Generate a random state parameter, store in session, verify on callback: if (req.query.state !== req.session.oauthState) throw Error()',
            cwe='CWE-352',
        ))

    # AUTH-003: Weak password requirements
    weak_match = WEAK_PASSWORD_RE.search(content)
    if weak_match:
        min_len = int(weak_match.group(1))
        if min_len < 8:
            results.append(CheckResult(
                check_id='AUTH-003',
                severity=Severity.WARNING,
                category=CATEGORY,
                message=f'Password minimum length set to {min_len}. NIST recommends at least 8 characters.',
                fix_suggestion='Set minimum password length to at least 8 (NIST) or 12 (best practice). Check against breached password lists (HaveIBeenPwned API).',
                cwe='CWE-521',
            ))

    # AUTH-016: Session cookies missing security flags
    if SET_COOKIE.search(content):
        has_secure = COOKIE_SECURE.search(content)
        has_httponly = COOKIE_HTTPONLY.search(content)
        has_samesite = COOKIE_SAMESITE.search(content)
        if not (has_secure and has_httponly and has_samesite):
            missing = []
            if not has_secure:
                missing.append('Secure')
            if not has_httponly:
                missing.append('HttpOnly')
            if not has_samesite:
                missing.append('SameSite')
            results.append(CheckResult(
                check_id='AUTH-016',
                severity=Severity.WARNING,
                category=CATEGORY,
                message=f'Session cookie missing flags: {", ".join(missing)}',
                fix_suggestion='Set all cookie security flags: { secure: true, httpOnly: true, sameSite: "strict" }',
                cwe='CWE-614',
            ))

    # AUTH-017: Password stored in reversible encryption
    if PASSWORD_REVERSIBLE.search(content):
        results.append(CheckResult(
            check_id='AUTH-017',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Password encrypted with reversible encryption instead of hashing. If the key is compromised, all passwords are exposed.',
            fix_suggestion='Use bcrypt, argon2, or scrypt for password hashing. Never encrypt passwords: const hash = await bcrypt.hash(password, 12)',
            cwe='CWE-257',
        ))

    # AUTH-018: Sensitive operations without re-authentication
    if SENSITIVE_OP.search(content) and not REAUTH_CHECK.search(content):
        results.append(CheckResult(
            check_id='AUTH-018',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Sensitive operation (password change, account deletion) without re-authentication check.',
            fix_suggestion='Require current password or MFA verification before sensitive operations: verifyPassword(req.body.currentPassword, user.hash)',
            cwe='CWE-306',
        ))

    # AUTH-020: Magic links without expiry
    if MAGIC_LINK.search(content) and not TOKEN_EXPIRY.search(content):
        results.append(CheckResult(
            check_id='AUTH-020',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Magic link / passwordless login detected without token expiry.',
            fix_suggestion='Set magic link tokens to expire in 15 minutes max. Mark as single-use. Store expiry in DB.',
            cwe='CWE-640',
        ))

    return results
