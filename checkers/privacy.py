"""
vibecheck Privacy & Data Protection Checker
8 checks for PII leaks, data exposure, credit card handling, and unsafe storage.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Privacy & Data Protection'

# PRIV-001: PII in logs
PII_IN_LOGS = re.compile(
    r'(?i)(?:console\.log|logger\.|logging\.).*(?:email|ssn|phone|credit.?card|social.?security)',
)

# PRIV-002: Storing PII without encryption (INFO)
PII_STORAGE = re.compile(
    r'(?i)(?:save|store|insert|create|update).*(?:ssn|social.?security|passport.?number|national.?id)',
)
ENCRYPTION_CONTEXT = re.compile(
    r'(?i)(?:encrypt|cipher|aes|pgp|kms|vault|sealed)',
)

# PRIV-003: User data in error response
USER_DATA_IN_ERROR = re.compile(
    r'(?i)(?:res\.(?:json|send)|return.*error).*(?:user|email|password|token)',
)

# PRIV-004: Missing data retention policy (INFO)
DATA_RETENTION = re.compile(
    r'(?i)(?:created.?at|timestamp|date.?added|inserted.?at)',
)
RETENTION_POLICY = re.compile(
    r'(?i)(?:retention|ttl|expir|purge|cleanup|archive|delete.*old|prune)',
)

# PRIV-005: Geolocation tracking without consent (INFO)
GEOLOCATION = re.compile(
    r'(?i)(?:geolocation|navigator\.geolocation|getCurrentPosition|watchPosition|ip.?location|geoip)',
)
CONSENT_CHECK = re.compile(
    r'(?i)(?:consent|permission|allow|opt.?in|gdpr|accept)',
)

# PRIV-006: Credit card number patterns in code (stored/logged)
CREDIT_CARD_PATTERN = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
)
CC_STORAGE_CONTEXT = re.compile(
    r'(?i)(?:store|save|log|insert|write|database|db|console|print|file)',
)

# PRIV-007: Analytics tracking sensitive pages (INFO)
ANALYTICS_SENSITIVE = re.compile(
    r'(?i)(?:gtag|analytics|track|pixel|segment).*(?:password|payment|checkout|medical|health)',
)

# PRIV-008: User data in localStorage/sessionStorage
LOCAL_STORAGE_USER_DATA = re.compile(
    r'(?i)(?:localStorage|sessionStorage)\.setItem.*(?:user|email|profile|token)',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all privacy checks."""
    results = []

    # PRIV-001: PII in logs
    if PII_IN_LOGS.search(content):
        results.append(CheckResult(
            check_id='PRIV-001',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='PII (email, SSN, phone, credit card) detected in logging statement. Logs are often stored unencrypted and widely accessible.',
            fix_suggestion='Mask PII before logging: logger.info("User login", { email: maskEmail(user.email) }). Use structured logging with PII redaction.',
            cwe='CWE-532',
        ))

    # PRIV-002: PII stored without encryption
    if PII_STORAGE.search(content) and not ENCRYPTION_CONTEXT.search(content):
        results.append(CheckResult(
            check_id='PRIV-002',
            severity=Severity.INFO,
            category=CATEGORY,
            message='Sensitive PII (SSN, passport, national ID) stored without apparent encryption.',
            fix_suggestion='Encrypt PII at rest using field-level encryption or application-layer encryption. Use a KMS for key management.',
            cwe='CWE-312',
        ))

    # PRIV-003: User data in error response
    if USER_DATA_IN_ERROR.search(content):
        results.append(CheckResult(
            check_id='PRIV-003',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='User data (email, password, token) included in error response. Attackers can extract sensitive info from error messages.',
            fix_suggestion='Return generic error messages to clients: res.json({ error: "Invalid credentials" }). Log details server-side only.',
            cwe='CWE-209',
        ))

    # PRIV-004: No data retention policy
    if DATA_RETENTION.search(content) and not RETENTION_POLICY.search(content):
        results.append(CheckResult(
            check_id='PRIV-004',
            severity=Severity.INFO,
            category=CATEGORY,
            message='Data with timestamps stored without apparent retention/cleanup policy. GDPR requires data minimization.',
            fix_suggestion='Implement data retention policies: schedule regular cleanup of old records. Add TTL indexes or cron jobs for data purging.',
            cwe='CWE-459',
        ))

    # PRIV-005: Geolocation without consent
    if GEOLOCATION.search(content) and not CONSENT_CHECK.search(content):
        results.append(CheckResult(
            check_id='PRIV-005',
            severity=Severity.INFO,
            category=CATEGORY,
            message='Geolocation tracking detected without apparent consent check. GDPR and ePrivacy require user consent.',
            fix_suggestion='Request explicit user consent before accessing geolocation. Show a clear consent dialog explaining why location is needed.',
            cwe='CWE-359',
        ))

    # PRIV-006: Credit card numbers in code
    if CREDIT_CARD_PATTERN.search(content) and CC_STORAGE_CONTEXT.search(content):
        results.append(CheckResult(
            check_id='PRIV-006',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Credit card number pattern detected in code with storage/logging context. PCI-DSS prohibits storing full card numbers.',
            fix_suggestion='Never store full card numbers. Use a payment processor (Stripe, Braintree) that tokenizes cards. Mask for display: **** **** **** 4242.',
            cwe='CWE-312',
        ))

    # PRIV-007: Analytics on sensitive pages
    if ANALYTICS_SENSITIVE.search(content):
        results.append(CheckResult(
            check_id='PRIV-007',
            severity=Severity.INFO,
            category=CATEGORY,
            message='Analytics tracking detected on sensitive page (payment, medical, password). May violate privacy regulations.',
            fix_suggestion='Disable or limit analytics on sensitive pages. Exclude PII from analytics events. Review GDPR/HIPAA compliance for tracking.',
            cwe='CWE-359',
        ))

    # PRIV-008: User data in localStorage/sessionStorage
    if LOCAL_STORAGE_USER_DATA.search(content):
        results.append(CheckResult(
            check_id='PRIV-008',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='User data stored in localStorage/sessionStorage. This data persists indefinitely and is accessible to any script on the page.',
            fix_suggestion='Use httpOnly cookies for tokens. If localStorage is required, encrypt values and set manual expiry: { data, expiresAt: Date.now() + ttl }.',
            cwe='CWE-922',
        ))

    return results
