"""
vibecheck Cryptography Checker
12 checks for weak crypto, insecure random, deprecated algorithms, and key management.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Cryptography'

# CRYPTO-001: MD5/SHA1 for password hashing
WEAK_HASH_PASSWORD = re.compile(
    r'(?i)(?:md5|sha1).*(?:password|hash)',
)

# CRYPTO-002: ECB mode
ECB_MODE = re.compile(
    r'(?i)(?:ECB|MODE_ECB|aes-128-ecb|aes-256-ecb)',
)

# CRYPTO-003: Hardcoded IVs near crypto context
HARDCODED_IV = re.compile(
    r'''(?i)iv\s*[:=]\s*['"][^'"]{8,}['"]''',
)
CRYPTO_CONTEXT = re.compile(
    r'(?i)(?:crypto|cipher|aes|encrypt|decrypt|createCipher)',
)

# CRYPTO-004: Insecure random for security-sensitive values
INSECURE_RANDOM_SECURITY = re.compile(
    r'(?i)(?:Math\.random|random\.random|random\.randint).*(?:token|nonce|secret|otp|code|session|csrf)',
)

# CRYPTO-005: RSA key < 2048 bits
WEAK_RSA_KEY = re.compile(
    r'(?i)(?:1024|512)\s*(?:bits|keySize|modulusLength)',
)

# CRYPTO-006: Deprecated createCipher (not createCipheriv)
DEPRECATED_CREATE_CIPHER = re.compile(
    r'createCipher\(',
)
CREATE_CIPHERIV = re.compile(
    r'createCipheriv\(',
)

# CRYPTO-007: Decrypt without HMAC verification
DECRYPT_CALL = re.compile(
    r'(?i)(?:decrypt|decipher|createDecipheriv)',
)
HMAC_VERIFY = re.compile(
    r'(?i)(?:verify|hmac|timingSafeEqual|createHmac)',
)

# CRYPTO-008: Non-timing-safe comparison of tokens/signatures
NON_TIMING_SAFE_COMPARE = re.compile(
    r'===\s*(?:\w+\.)?(?:token|signature|hash|hmac|digest)',
)
NON_TIMING_SAFE_COMPARE_REV = re.compile(
    r'(?:token|signature|hash|hmac|digest)\w*\s*===',
)
TIMING_SAFE = re.compile(
    r'(?i)timingSafeEqual',
)

# CRYPTO-009: Custom crypto implementation
CUSTOM_CRYPTO = re.compile(
    r'(?i)(?:my|custom|diy).*(?:encrypt|decrypt|hash|cipher)',
)

# CRYPTO-010: TLS below 1.2
WEAK_TLS = re.compile(
    r'(?i)(?:TLSv1_0|TLSv1_1|SSLv3|TLSv1$|ssl_version.*1\.[01])',
)

# CRYPTO-011: Weak PBKDF2 iterations
PBKDF2_ITERATIONS = re.compile(
    r'(?i)iterations?\s*[:=]\s*(\d+)',
)
PBKDF2_CONTEXT = re.compile(
    r'(?i)(?:pbkdf2|deriveKey|key.?deriv)',
)

# CRYPTO-012: Nonce reuse / static nonce
STATIC_NONCE = re.compile(
    r'''(?i)(?:nonce|iv)\s*[:=]\s*['"](?:0+|1234|static|fixed)['"]''',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all cryptography checks."""
    results = []

    # CRYPTO-001: MD5/SHA1 for password hashing
    if WEAK_HASH_PASSWORD.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-001',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='MD5 or SHA1 used for password hashing. These are fast hashes trivially brute-forced with modern GPUs.',
            fix_suggestion='Use bcrypt, argon2, or scrypt for password hashing: const hash = await bcrypt.hash(password, 12). Never use MD5/SHA1 for passwords.',
            cwe='CWE-328',
        ))

    # CRYPTO-002: ECB mode
    if ECB_MODE.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-002',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='ECB cipher mode detected. ECB encrypts identical plaintext blocks to identical ciphertext, leaking data patterns.',
            fix_suggestion='Use AES-GCM (authenticated encryption) or AES-CBC with HMAC. Example: createCipheriv("aes-256-gcm", key, iv)',
            cwe='CWE-327',
        ))

    # CRYPTO-003: Hardcoded IVs
    if HARDCODED_IV.search(content) and CRYPTO_CONTEXT.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-003',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Hardcoded initialization vector (IV) detected near crypto operations. Reusing IVs breaks encryption security.',
            fix_suggestion='Generate a random IV for each encryption: const iv = crypto.randomBytes(16). Prepend IV to ciphertext for decryption.',
            cwe='CWE-329',
        ))

    # CRYPTO-004: Insecure random for security values
    if INSECURE_RANDOM_SECURITY.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-004',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Math.random() or random.random() used for security-sensitive value (token, nonce, OTP). These are predictable.',
            fix_suggestion='Use crypto.randomBytes(32).toString("hex") (Node.js) or secrets.token_hex(32) (Python) for security-sensitive random values.',
            cwe='CWE-330',
        ))

    # CRYPTO-005: RSA key < 2048 bits
    if WEAK_RSA_KEY.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-005',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='RSA key size below 2048 bits detected. Keys under 2048 bits can be factored with modern hardware.',
            fix_suggestion='Use RSA 2048-bit minimum (4096 recommended) or switch to ECDSA P-256/Ed25519 for better performance.',
            cwe='CWE-326',
        ))

    # CRYPTO-006: Deprecated createCipher
    if DEPRECATED_CREATE_CIPHER.search(content) and not CREATE_CIPHERIV.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-006',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='createCipher() is deprecated. It derives key and IV from password using MD5, which is insecure.',
            fix_suggestion='Use createCipheriv() with an explicit key and random IV: crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(16))',
            cwe='CWE-327',
        ))

    # CRYPTO-007: Decrypt without HMAC verification
    if DECRYPT_CALL.search(content) and not HMAC_VERIFY.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-007',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Decryption without HMAC/signature verification detected. Ciphertext may be tampered with (padding oracle attacks).',
            fix_suggestion='Use authenticated encryption (AES-GCM) or verify HMAC before decrypting: verify(hmac, ciphertext) then decrypt.',
            cwe='CWE-347',
        ))

    # CRYPTO-008: Non-timing-safe comparison
    has_comparison = NON_TIMING_SAFE_COMPARE.search(content) or NON_TIMING_SAFE_COMPARE_REV.search(content)
    if has_comparison and not TIMING_SAFE.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-008',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Token/signature compared with === instead of timing-safe comparison. Timing attacks can recover the secret byte by byte.',
            fix_suggestion='Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) in Node.js or hmac.compare_digest(a, b) in Python.',
            cwe='CWE-208',
        ))

    # CRYPTO-009: Custom crypto implementation
    if CUSTOM_CRYPTO.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-009',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Custom cryptographic implementation detected. Rolling your own crypto almost always introduces vulnerabilities.',
            fix_suggestion='Use established libraries: Web Crypto API, node:crypto, libsodium, or tweetnacl. Never implement your own encryption.',
            cwe='CWE-327',
        ))

    # CRYPTO-010: TLS below 1.2
    if WEAK_TLS.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-010',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='TLS version below 1.2 detected. TLS 1.0/1.1 and SSLv3 have known vulnerabilities (POODLE, BEAST).',
            fix_suggestion='Enforce TLS 1.2 minimum: tls.createServer({ minVersion: "TLSv1.2" }). Prefer TLS 1.3 where supported.',
            cwe='CWE-326',
        ))

    # CRYPTO-011: Weak PBKDF2 iterations
    if PBKDF2_CONTEXT.search(content):
        iter_match = PBKDF2_ITERATIONS.search(content)
        if iter_match:
            iterations = int(iter_match.group(1))
            if iterations < 600000:
                results.append(CheckResult(
                    check_id='CRYPTO-011',
                    severity=Severity.WARNING,
                    category=CATEGORY,
                    message=f'PBKDF2 iteration count set to {iterations}. OWASP recommends at least 600,000 iterations for SHA-256.',
                    fix_suggestion='Increase iterations to 600,000+ for SHA-256 or 210,000+ for SHA-512. Or switch to argon2id which is GPU-resistant.',
                    cwe='CWE-916',
                ))

    # CRYPTO-012: Static/reused nonce
    if STATIC_NONCE.search(content):
        results.append(CheckResult(
            check_id='CRYPTO-012',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Static or predictable nonce/IV detected. Nonce reuse completely breaks the security of stream ciphers and GCM.',
            fix_suggestion='Generate a unique random nonce per encryption: crypto.randomBytes(12) for GCM, crypto.randomBytes(16) for CBC.',
            cwe='CWE-323',
        ))

    return results
