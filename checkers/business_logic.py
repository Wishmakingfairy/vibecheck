"""
preflight Business Logic Checker
6 checks for race conditions, missing idempotency, negative values, sequential IDs, and rate limits.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Business Logic'

# BIZ-001: Race condition in payment/transaction
TRANSACTION_PAYMENT = re.compile(
    r'(?i)(?:payment|charge|transfer|transaction|balance|withdraw|deposit|debit|credit)',
)
MUTEX_LOCK = re.compile(
    r'(?i)(?:mutex|lock|semaphore|synchronized|atomic|serializable|FOR\s+UPDATE|LOCK\s+IN|advisory.?lock|redlock|bullmq)',
)

# BIZ-002: Missing idempotency key on payment routes
PAYMENT_ROUTE = re.compile(
    r'(?i)(?:payment|charge|transfer|order)',
)
IDEMPOTENCY = re.compile(
    r'(?i)idempotency',
)

# BIZ-003: Negative quantity without validation
QUANTITY_FIELD = re.compile(
    r'(?i)(?:quantity|amount|price|qty)',
)
NEGATIVE_VALIDATION = re.compile(
    r'(?i)(?:Math\.abs|Math\.max|>= *0|> *0|positive|unsigned|min\s*[:=]\s*0|min\s*[:=]\s*1|negative|isNegative)',
)

# BIZ-004: Sequential IDs in URLs
SEQUENTIAL_ID_ROUTE = re.compile(
    r'''(?i)(?:app|router|server)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"].*/:id['"]''',
)
AUTO_INCREMENT = re.compile(
    r'(?i)(?:autoIncrement|auto_increment|SERIAL|BIGSERIAL|IDENTITY|nextval)',
)

# BIZ-005: Resource creation without rate limit
RESOURCE_CREATION = re.compile(
    r'''(?i)\.post\s*\(\s*['"].*(?:create|new|register)['"]''',
)
RATE_LIMIT = re.compile(
    r'(?i)(?:rateLimit|rate_limit|rateLimiter|throttle|slowDown|express-rate-limit|@nestjs/throttler|limiter)',
)

# BIZ-006: Coupon/discount without usage limit
COUPON_DISCOUNT = re.compile(
    r'(?i)(?:coupon|discount|promo)',
)
USAGE_LIMIT = re.compile(
    r'(?i)(?:limit|max|used|count|remaining|quota|cap|exhausted)',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all business logic checks."""
    results = []

    # BIZ-001: Race condition in transactions
    if TRANSACTION_PAYMENT.search(content) and not MUTEX_LOCK.search(content):
        results.append(CheckResult(
            check_id='BIZ-001',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Payment/transaction logic without locking mechanism. Race conditions can cause double-spending or balance corruption.',
            fix_suggestion='Use database-level locking: SELECT ... FOR UPDATE, or distributed locks (Redlock). Wrap financial operations in serializable transactions.',
            cwe='CWE-362',
        ))

    # BIZ-002: Missing idempotency key
    if PAYMENT_ROUTE.search(content) and not IDEMPOTENCY.search(content):
        results.append(CheckResult(
            check_id='BIZ-002',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Payment/order route without idempotency key. Network retries can cause duplicate charges.',
            fix_suggestion='Require an Idempotency-Key header: const key = req.headers["idempotency-key"]. Check if already processed before executing.',
            cwe='CWE-362',
        ))

    # BIZ-003: Negative quantity/amount without validation
    if QUANTITY_FIELD.search(content) and not NEGATIVE_VALIDATION.search(content):
        results.append(CheckResult(
            check_id='BIZ-003',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Quantity/amount/price field without negative value validation. Attackers can submit negative values to get credits or free items.',
            fix_suggestion='Validate all numeric inputs: if (quantity < 0) throw new Error("Invalid quantity"). Use Zod: z.number().positive() or z.number().min(0).',
            cwe='CWE-20',
        ))

    # BIZ-004: Sequential IDs exposing resources
    if SEQUENTIAL_ID_ROUTE.search(content) and AUTO_INCREMENT.search(content):
        results.append(CheckResult(
            check_id='BIZ-004',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Sequential/auto-increment IDs used in URL routes. Attackers can enumerate all resources by incrementing the ID.',
            fix_suggestion='Use UUIDs (crypto.randomUUID()) or NanoID instead of sequential IDs for public-facing resources. Add authorization checks per resource.',
            cwe='CWE-330',
        ))

    # BIZ-005: Resource creation without rate limit
    if RESOURCE_CREATION.search(content) and not RATE_LIMIT.search(content):
        results.append(CheckResult(
            check_id='BIZ-005',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Resource creation endpoint without rate limiting. Attackers can flood the system with spam accounts or objects.',
            fix_suggestion='Add rate limiting: app.use("/api/create", rateLimit({ windowMs: 60*1000, max: 10 })). Consider CAPTCHA for registration.',
            cwe='CWE-770',
        ))

    # BIZ-006: Coupon without usage limit
    if COUPON_DISCOUNT.search(content) and not USAGE_LIMIT.search(content):
        results.append(CheckResult(
            check_id='BIZ-006',
            severity=Severity.INFO,
            category=CATEGORY,
            message='Coupon/discount/promo code logic without apparent usage limit. Codes may be reused indefinitely.',
            fix_suggestion='Track coupon usage: { code, maxUses, currentUses, expiresAt }. Validate: if (coupon.currentUses >= coupon.maxUses) reject().',
            cwe='CWE-799',
        ))

    return results
