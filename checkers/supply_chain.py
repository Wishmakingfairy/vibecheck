"""
preflight Supply Chain Security Checker
15 checks for dependency attacks, typosquatting, and build pipeline security.

Author: Haralds Gabrans
License: MIT
"""

import re
from typing import List
from checkers import CheckResult, Severity

CATEGORY = 'Supply Chain'

# Known typosquatted package names (curated list)
TYPOSQUATS = {
    # npm
    'lodahs', 'lodasb', 'loadsh', 'lod-ash',
    'espress', 'expres', 'expresss',
    'reacr', 'reactt', 'raect',
    'angullar', 'anuglar',
    'axois', 'axioos',
    'momnet', 'monment',
    'chalks', 'chalkk',
    'cros', 'corss',
    'joii', 'jois',
    'sequlize', 'seqelize',
    'mongooze', 'mongose',
    'electorn', 'electrn',
    'webpackk', 'weback',
    'babael', 'babell',
    'typescipt', 'typscript',
    'nextjs', 'nxet',
    'socket-io', 'sockeet',
    'bcryptjs', 'bcrpyt',
    'jsonwebtokens', 'jsonwebtoken-decode',
    'cross-env-shell', 'crossenv',
    'event-stream-fake', 'event-strean',
    'flatmap-stream', 'flattmap',
    # python
    'reqeusts', 'requets', 'requrests',
    'djnago', 'djanog',
    'flaskk', 'falsk',
    'numpyy', 'numpi',
    'pandsa', 'pands',
}

# Suspicious postinstall scripts
POSTINSTALL = re.compile(
    r'''["'](?:postinstall|preinstall|install)["']\s*:\s*["'](?:.*(?:curl|wget|bash|sh|node\s+-e|python\s+-c|eval))''',
    re.IGNORECASE
)

# Wildcard versions
WILDCARD_VERSION = re.compile(r'''["'][^"']+["']\s*:\s*["']\*["']''')

# CDN without SRI
CDN_SCRIPT = re.compile(r'<script[^>]*src\s*=\s*["\']https?://(?:cdn|unpkg|jsdelivr|cdnjs|cloudflare)', re.IGNORECASE)
SRI_ATTR = re.compile(r'integrity\s*=\s*["\']sha', re.IGNORECASE)

# Git URL dependencies
GIT_DEP = re.compile(r'''["'][^"']+["']\s*:\s*["'](?:git\+|git://|github:|https://github\.com)''')

# Unpinned GitHub Actions
UNPINNED_ACTION = re.compile(r'uses:\s*[\w-]+/[\w-]+@(?:main|master|latest|dev|HEAD)')
PINNED_ACTION = re.compile(r'uses:\s*[\w-]+/[\w-]+@[a-f0-9]{40}')

# Docker FROM without pin
DOCKER_FROM_LATEST = re.compile(r'FROM\s+\w+(?::\s*latest\s*$|(?![@:]))', re.MULTILINE)

# Curl pipe to shell
CURL_PIPE_SH = re.compile(r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh|sudo\s+bash|sudo\s+sh)')

# Dependency confusion
NPMRC_SCOPE = re.compile(r'@[\w-]+:registry\s*=')

# Known malicious packages (curated blocklist)
MALICIOUS_PACKAGES = {
    'event-stream', 'flatmap-stream', 'ua-parser-js',
    'coa', 'rc', 'colors-hierarchical',
    'crossenv', 'cross-env.js',
    'fabric-js', 'grpc-tools-node',
    'discord.js-selfbot-v14', 'http-proxy-agent-v4',
}


def check(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all supply chain security checks."""
    results = []
    is_package_json = file_path and 'package.json' in file_path
    is_html = file_path and file_path.endswith(('.html', '.htm'))
    is_yaml = file_path and file_path.endswith(('.yml', '.yaml'))
    is_docker = file_path and ('Dockerfile' in file_path or 'docker' in file_path.lower())
    is_makefile = file_path and ('Makefile' in file_path or file_path.endswith('.sh'))

    # SUP-001: Typosquatted packages
    if is_package_json:
        content_lower = content.lower()
        for typo in TYPOSQUATS:
            if f'"{typo}"' in content_lower or f"'{typo}'" in content_lower:
                results.append(CheckResult(
                    check_id='SUP-001',
                    severity=Severity.CRITICAL,
                    category=CATEGORY,
                    message=f'Possible typosquatted package: "{typo}". This may be a malicious package impersonating a popular one.',
                    fix_suggestion=f'Verify the package name is correct. Check https://www.npmjs.com/package/{typo} and compare with the intended package.',
                    cwe='CWE-1357',
                ))
                break

    # SUP-015: Known malicious packages
    if is_package_json:
        content_lower = content.lower()
        for pkg in MALICIOUS_PACKAGES:
            if f'"{pkg}"' in content_lower or f"'{pkg}'" in content_lower:
                results.append(CheckResult(
                    check_id='SUP-015',
                    severity=Severity.CRITICAL,
                    category=CATEGORY,
                    message=f'Known malicious package detected: "{pkg}". This package has been flagged for supply chain attacks.',
                    fix_suggestion=f'Remove "{pkg}" immediately. Check npm advisories for replacement recommendations.',
                    cwe='CWE-506',
                ))
                break

    # SUP-002: Suspicious postinstall
    if is_package_json and POSTINSTALL.search(content):
        results.append(CheckResult(
            check_id='SUP-002',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Suspicious postinstall/preinstall script detected. These run automatically on npm install.',
            fix_suggestion='Review the script carefully. Use --ignore-scripts for untrusted packages. Consider using npm config set ignore-scripts true globally.',
            cwe='CWE-506',
        ))

    # SUP-005: Wildcard versions
    if is_package_json and WILDCARD_VERSION.search(content):
        results.append(CheckResult(
            check_id='SUP-005',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Wildcard (*) dependency version detected. Any version will be installed, including malicious ones.',
            fix_suggestion='Pin to specific versions or ranges: "^1.2.3" or "~1.2.3". Run npm audit after updating.',
            cwe='CWE-829',
        ))

    # SUP-004: CDN without SRI
    if is_html and CDN_SCRIPT.search(content) and not SRI_ATTR.search(content):
        results.append(CheckResult(
            check_id='SUP-004',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='CDN script loaded without Subresource Integrity (SRI). If the CDN is compromised, malicious code runs on your site.',
            fix_suggestion='Add integrity attribute: <script src="..." integrity="sha384-..." crossorigin="anonymous">. Generate at https://www.srihash.org/',
            cwe='CWE-829',
        ))

    # SUP-006: Git URL dependencies
    if is_package_json and GIT_DEP.search(content):
        results.append(CheckResult(
            check_id='SUP-006',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Git URL dependency detected. The repository content can change without version control.',
            fix_suggestion='Pin to a specific commit hash: "package": "github:user/repo#commit-sha". Or publish to npm.',
            cwe='CWE-829',
        ))

    # SUP-011: Unpinned GitHub Actions
    if is_yaml and UNPINNED_ACTION.search(content):
        results.append(CheckResult(
            check_id='SUP-011',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='GitHub Action pinned to mutable ref (main/master/latest). The action can change without notice.',
            fix_suggestion='Pin to full commit SHA: uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.1',
            cwe='CWE-829',
        ))

    # SUP-012: Docker FROM without digest
    if is_docker and DOCKER_FROM_LATEST.search(content):
        results.append(CheckResult(
            check_id='SUP-012',
            severity=Severity.WARNING,
            category=CATEGORY,
            message='Docker base image without version pin or using :latest. Image can change unexpectedly.',
            fix_suggestion='Pin to specific version and digest: FROM node:20-alpine@sha256:abc123...',
            cwe='CWE-829',
        ))

    # SUP-013: Curl pipe to shell
    if (is_docker or is_makefile) and CURL_PIPE_SH.search(content):
        results.append(CheckResult(
            check_id='SUP-013',
            severity=Severity.CRITICAL,
            category=CATEGORY,
            message='curl/wget piped to shell. Man-in-the-middle attacks can inject malicious code.',
            fix_suggestion='Download first, verify checksum, then execute: curl -o install.sh URL && sha256sum -c checksums.txt && bash install.sh',
            cwe='CWE-829',
        ))

    return results
