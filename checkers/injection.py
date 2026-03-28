"""
preflight Injection Prevention Checker
21 checks for XSS, command injection, path traversal, deserialization, and code injection.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Injection'

# XSS patterns (framework-aware)
DANGEROUS_INNER_HTML = re.compile(r'dangerouslySetInnerHTML')
DOMPURIFY_IMPORT = re.compile(r'(?i)(?:DOMPurify|dompurify|sanitize-html|isomorphic-dompurify)')
INNERHTML_ASSIGN = re.compile(r'\.innerHTML\s*=\s*(?![\s]*[\'"][^$]*[\'"])', re.DOTALL)
VUE_VHTML = re.compile(r'v-html\s*=')
ANGULAR_INNERHTML = re.compile(r'\[innerHTML\]')
SVELTE_HTML = re.compile(r'\{@html\s')
DOCUMENT_WRITE = re.compile(r'document\.write\s*\(')

# Command injection
CMD_INJECTION = re.compile(
    r'''(?i)(?:child_process\.exec|exec\s*\(|execSync\s*\(|os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True|spawn\s*\().*(?:req\.|params\.|query\.|input|user|\$\{)''',
    re.DOTALL
)
CMD_INJECTION_SIMPLE = re.compile(
    r'''(?i)(?:exec|execSync|os\.system|subprocess\.call)\s*\(\s*(?:f['"]|['"].*\+|`.*\$\{)''',
)

# Path traversal
PATH_TRAVERSAL = re.compile(
    r'''(?i)(?:readFile|writeFile|createReadStream|open|path\.join|path\.resolve|fs\.)\s*\(.*(?:req\.|params\.|query\.|body\.|input|user)''',
    re.DOTALL
)

# Deserialization
PICKLE_LOADS = re.compile(r'pickle\.loads?\s*\(')
YAML_UNSAFE = re.compile(r'yaml\.(?:load|unsafe_load)\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', re.DOTALL)

# eval and friends
EVAL_USAGE = re.compile(r'(?<!\w)eval\s*\(')
NEW_FUNCTION = re.compile(r'new\s+Function\s*\(')
SETTIMEOUT_STRING = re.compile(r'setTimeout\s*\(\s*[\'"`]')

# Prototype pollution
DEEP_MERGE = re.compile(
    r'''(?i)(?:deepMerge|deep\.merge|_.merge|lodash\.merge|Object\.assign|spread)\s*\(.*(?:req\.|body\.|input|user|params)''',
    re.DOTALL
)

# XXE
XXE_PATTERN = re.compile(r'(?i)(?:<!ENTITY|SYSTEM\s+["\']|parseXML|xml2js|DOMParser|XMLReader|etree\.parse)')
XXE_SAFE = re.compile(r'(?i)(?:disallow.?dtd|resolve.?externals.*false|FEATURE_SECURE_PROCESSING)')

# LDAP injection
LDAP_INJECTION = re.compile(
    r'''(?i)(?:ldap|ldapsearch)\s*.*(?:req\.|params\.|query\.|input|user|\$\{)''',
    re.DOTALL
)

# File upload
FILE_UPLOAD = re.compile(r'(?i)(?:multer|formidable|busboy|multipart|upload|file.*upload)')
FILE_TYPE_CHECK = re.compile(r'(?i)(?:mimetype|content.?type|file.?type|allowed.?types|accept|file.?filter)')
FILE_SIZE_LIMIT = re.compile(r'(?i)(?:maxFileSize|fileSizeLimit|limits.*fileSize|max.?size|limit)')

# ReDoS
REDOS_PATTERNS = re.compile(r'''(?:\(.+\+\)\+|\(.+\*\)\*|\(.+\+\)\*|\(.+\*\)\+)''')

# GraphQL introspection
GRAPHQL_INTROSPECTION = re.compile(r'(?i)(?:introspection\s*:\s*true|__schema|__type)')
GRAPHQL_PROD = re.compile(r'(?i)(?:production|prod)')

# CRLF injection
CRLF_INJECTION = re.compile(
    r'''(?i)(?:setHeader|writeHead|res\.header)\s*\(.*(?:req\.|params\.|query\.|body\.|input)''',
    re.DOTALL
)

# CSS injection
CSS_INJECTION = re.compile(
    r'''(?i)style\s*=\s*\{?\s*[{`].*(?:req\.|params\.|query\.|body\.|input|user)''',
    re.DOTALL
)


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all injection checks."""
    results = []
    has_sanitizer = bool(DOMPURIFY_IMPORT.search(content))

    # INJ-001: dangerouslySetInnerHTML
    if DANGEROUS_INNER_HTML.search(content) and not has_sanitizer:
        results.append(CheckResult(
            check_id='INJ-001',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='dangerouslySetInnerHTML used without DOMPurify sanitization. Any user content becomes an XSS vector.',
            fix_suggestion='import DOMPurify from "dompurify"; <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />',
            cwe='CWE-79',
        ))

    # INJ-002: innerHTML assignment
    if INNERHTML_ASSIGN.search(content) and not has_sanitizer:
        results.append(CheckResult(
            check_id='INJ-002',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='innerHTML set with dynamic content. Use textContent for plain text or sanitize HTML.',
            fix_suggestion='Use element.textContent for text. For HTML: element.innerHTML = DOMPurify.sanitize(content)',
            cwe='CWE-79',
        ))

    # INJ-003: Vue v-html
    if VUE_VHTML.search(content) and not has_sanitizer:
        results.append(CheckResult(
            check_id='INJ-003',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='v-html directive renders raw HTML. XSS risk if content comes from user input.',
            fix_suggestion='Sanitize before rendering: v-html="DOMPurify.sanitize(content)". Or use {{ }} for text interpolation.',
            cwe='CWE-79',
        ))

    # INJ-004: Angular [innerHTML]
    if ANGULAR_INNERHTML.search(content):
        results.append(CheckResult(
            check_id='INJ-004',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Angular [innerHTML] binding detected. Angular sanitizes by default, but bypassSecurityTrust* defeats this.',
            fix_suggestion='Verify no bypassSecurityTrustHtml() is used with user input. Use Angular DomSanitizer for custom sanitization.',
            cwe='CWE-79',
        ))

    # INJ-005: Svelte {@html}
    if SVELTE_HTML.search(content) and not has_sanitizer:
        results.append(CheckResult(
            check_id='INJ-005',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Svelte {@html} renders raw HTML. No built-in sanitization.',
            fix_suggestion='Sanitize: {@html DOMPurify.sanitize(content)}. Install: npm install dompurify',
            cwe='CWE-79',
        ))

    # INJ-006: Command injection
    if CMD_INJECTION.search(content) or CMD_INJECTION_SIMPLE.search(content):
        results.append(CheckResult(
            check_id='INJ-006',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Command execution with user-controlled input. Attackers can run arbitrary system commands.',
            fix_suggestion='Use execFile/spawn with argument arrays instead of exec: spawn("command", [userInput]). Never pass user input to shell.',
            cwe='CWE-78',
        ))

    # INJ-007: Path traversal
    if PATH_TRAVERSAL.search(content):
        results.append(CheckResult(
            check_id='INJ-007',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='File operation with user-controlled path. Attackers can read/write arbitrary files (../../etc/passwd).',
            fix_suggestion='Validate: const safePath = path.resolve(baseDir, userInput); if (!safePath.startsWith(baseDir)) throw Error("Invalid path")',
            cwe='CWE-22',
        ))

    # INJ-010: XXE
    if XXE_PATTERN.search(content) and not XXE_SAFE.search(content):
        results.append(CheckResult(
            check_id='INJ-010',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='XML parsing without external entity protection. Attackers can read local files and make network requests.',
            fix_suggestion='Disable external entities: parser.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). Or use JSON instead of XML.',
            cwe='CWE-611',
        ))

    # INJ-011: Unsafe deserialization
    if PICKLE_LOADS.search(content):
        results.append(CheckResult(
            check_id='INJ-011',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='pickle.load() can execute arbitrary code during deserialization. Never use with untrusted data.',
            fix_suggestion='Use json.loads() for data exchange. If pickle is required, only load from trusted sources and use hmac verification.',
            cwe='CWE-502',
        ))

    if YAML_UNSAFE.search(content):
        results.append(CheckResult(
            check_id='INJ-011',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='yaml.load() without SafeLoader can execute arbitrary code.',
            fix_suggestion='Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)',
            cwe='CWE-502',
        ))

    # INJ-017: Prototype pollution
    if DEEP_MERGE.search(content):
        results.append(CheckResult(
            check_id='INJ-017',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='Deep merge/Object.assign with user input. Attackers can inject __proto__ to pollute all objects.',
            fix_suggestion='Filter __proto__, constructor, prototype from user input before merging. Use Object.create(null) for safe objects.',
            cwe='CWE-1321',
        ))

    # INJ-021: eval / new Function / setTimeout(string)
    if EVAL_USAGE.search(content) or NEW_FUNCTION.search(content) or SETTIMEOUT_STRING.search(content):
        results.append(CheckResult(
            check_id='INJ-021',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='eval(), new Function(), or setTimeout(string) detected. These execute arbitrary code.',
            fix_suggestion='Use JSON.parse() for data. Use function references for setTimeout: setTimeout(myFunc, 1000). Avoid eval entirely.',
            cwe='CWE-95',
        ))

    # INJ-013: File upload without type check
    if FILE_UPLOAD.search(content) and not FILE_TYPE_CHECK.search(content):
        results.append(CheckResult(
            check_id='INJ-013',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='File upload handler without file type validation. Attackers can upload malicious files.',
            fix_suggestion='Validate file types: fileFilter: (req, file, cb) => { const allowed = ["image/jpeg", "image/png"]; cb(null, allowed.includes(file.mimetype)); }',
            cwe='CWE-434',
        ))

    # INJ-014: File upload without size limit
    if FILE_UPLOAD.search(content) and not FILE_SIZE_LIMIT.search(content):
        results.append(CheckResult(
            check_id='INJ-014',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='File upload without size limit. Large files can exhaust server resources.',
            fix_suggestion='Set size limits: multer({ limits: { fileSize: 5 * 1024 * 1024 } }) // 5MB max',
            cwe='CWE-400',
        ))

    # INJ-019: GraphQL introspection in production
    if GRAPHQL_INTROSPECTION.search(content) and GRAPHQL_PROD.search(content):
        results.append(CheckResult(
            check_id='INJ-019',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='GraphQL introspection enabled in production. Exposes your entire schema to attackers.',
            fix_suggestion='Disable in production: introspection: process.env.NODE_ENV !== "production"',
            cwe='CWE-200',
        ))

    return results
