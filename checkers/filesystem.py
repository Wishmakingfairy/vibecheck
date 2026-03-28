"""
preflight File System Security Checker
5 checks for path traversal, unsafe permissions, zip slip, symlink attacks, and temp file safety.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'File System Security'

# FS-001: User-controlled file path
USER_CONTROLLED_FILE = re.compile(
    r'(?i)(?:readFile|writeFile|unlink|rmdir|createReadStream)\s*\(.*(?:req\.|query\.|params\.|body\.)',
    re.DOTALL
)

# FS-002: Symlink following without check
SYMLINK_OPERATIONS = re.compile(
    r'(?i)(?:readFile|writeFile|createReadStream|open|stat)\s*\(',
)
SYMLINK_CHECK = re.compile(
    r'(?i)(?:lstat|readlink|isSymbolicLink|followSymlinks\s*[:=]\s*false|no.?follow)',
)
SYMLINK_CONTEXT = re.compile(
    r'(?i)(?:upload|user.?file|attachment|import|public|static)',
)

# FS-003: Predictable temp file names
PREDICTABLE_TEMP = re.compile(
    r'(?i)(?:tmp|temp).*(?:Math\.random|Date\.now|process\.pid)',
)
CRYPTO_RANDOM = re.compile(
    r'(?i)(?:crypto\.randomBytes|crypto\.randomUUID|uuid|nanoid|secrets\.token)',
)

# FS-004: chmod 777
CHMOD_777 = re.compile(
    r'(?:chmod\s+777|0o?777|0777)',
)

# FS-005: Zip slip (archive extraction without path validation)
ZIP_EXTRACT = re.compile(
    r'(?i)(?:unzip|extract|decompress|ZipFile|tar\.extract|archiver|yauzl|adm-zip|node-tar)',
)
ZIP_PATH_VALIDATION = re.compile(
    r'(?i)(?:startsWith|normalize|resolve.*base|\.\.\/|path\.join.*base|sanitize.*path|safe.*path|within)',
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all file system security checks."""
    results = []

    # FS-001: User-controlled file path
    if USER_CONTROLLED_FILE.search(content):
        results.append(CheckResult(
            check_id='FS-001',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='File operation with user-controlled path. Attackers can read/write/delete arbitrary files via path traversal (../../etc/passwd).',
            fix_suggestion='Validate paths: const safe = path.resolve(baseDir, userInput); if (!safe.startsWith(path.resolve(baseDir))) throw Error("Path traversal blocked").',
            cwe='CWE-22',
        ))

    # FS-002: Symlink following
    if SYMLINK_OPERATIONS.search(content) and SYMLINK_CONTEXT.search(content) and not SYMLINK_CHECK.search(content):
        results.append(CheckResult(
            check_id='FS-002',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='File operations in user-accessible context without symlink check. Attackers can create symlinks pointing to sensitive files.',
            fix_suggestion='Use fs.lstat() to check for symlinks before reading. Set followSymlinks: false where available. Validate real path with fs.realpath().',
            cwe='CWE-59',
        ))

    # FS-003: Predictable temp file names
    if PREDICTABLE_TEMP.search(content) and not CRYPTO_RANDOM.search(content):
        results.append(CheckResult(
            check_id='FS-003',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Temporary file created with predictable name (Math.random, Date.now, PID). Attackers can predict and pre-create symlinks.',
            fix_suggestion='Use crypto.randomBytes(16).toString("hex") for temp file names, or use os.tmpdir() + crypto-random suffix. Better: use tmp or tmp-promise library.',
            cwe='CWE-377',
        ))

    # FS-004: chmod 777
    if CHMOD_777.search(content):
        results.append(CheckResult(
            check_id='FS-004',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='chmod 777 gives read/write/execute to all users. Any process on the system can read, modify, or execute the file.',
            fix_suggestion='Use minimal permissions: chmod 644 for files (owner write, others read), chmod 755 for directories. Never use 777 in production.',
            cwe='CWE-732',
        ))

    # FS-005: Zip slip
    if ZIP_EXTRACT.search(content) and not ZIP_PATH_VALIDATION.search(content):
        results.append(CheckResult(
            check_id='FS-005',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Archive extraction without path validation. Zip slip attacks use "../" in filenames to write files outside the target directory.',
            fix_suggestion='Validate extracted paths: const target = path.resolve(destDir, entry.fileName); if (!target.startsWith(path.resolve(destDir))) skip entry.',
            cwe='CWE-22',
        ))

    return results
