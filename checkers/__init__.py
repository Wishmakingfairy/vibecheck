"""
0xguard Checker Registry
Central registry for all 15 security checker modules.
Dispatches checks based on file extension, aggregates results.

Author: Haralds Gabrans
License: MIT
"""

import math
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = 'CRITICAL'
    WARNING = 'WARNING'
    INFO = 'INFO'


@dataclass
class CheckResult:
    """A single security finding."""
    check_id: str          # e.g. "SEC-001"
    severity: Severity
    category: str          # e.g. "Secrets & API Keys"
    message: str           # What was found
    fix_suggestion: str    # How to fix it (shown to Claude for rewrite)
    cwe: str = ''          # e.g. "CWE-798"
    line_hint: str = ''    # Optional line reference


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Used to detect high-entropy strings that may be secrets.
    Entropy > 4.5 with length > 16 is suspicious near assignments.
    """
    if not data:
        return 0.0
    frequency = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in frequency.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


# File extension to checker module mapping
# Each extension maps to a list of checker module names to load
EXTENSION_MAP = {
    # JavaScript/TypeScript
    '.js': ['secrets', 'injection', 'auth', 'network', 'ai_llm', 'crypto', 'logging_security', 'business_logic', 'websocket'],
    '.jsx': ['secrets', 'injection', 'auth', 'network', 'headers', 'ai_llm', 'crypto', 'privacy', 'logging_security'],
    '.ts': ['secrets', 'injection', 'auth', 'network', 'ai_llm', 'crypto', 'logging_security', 'business_logic', 'websocket'],
    '.tsx': ['secrets', 'injection', 'auth', 'network', 'headers', 'ai_llm', 'crypto', 'privacy', 'logging_security'],
    '.mjs': ['secrets', 'injection', 'auth', 'network', 'ai_llm', 'crypto'],
    '.cjs': ['secrets', 'injection', 'auth', 'network', 'ai_llm', 'crypto'],
    '.mts': ['secrets', 'injection', 'auth', 'network', 'ai_llm', 'crypto'],
    '.cts': ['secrets', 'injection', 'auth', 'network', 'ai_llm', 'crypto'],

    # Frontend frameworks
    '.vue': ['secrets', 'injection', 'headers', 'ai_llm', 'privacy'],
    '.svelte': ['secrets', 'injection', 'headers', 'ai_llm', 'privacy'],
    '.astro': ['secrets', 'injection', 'headers', 'ai_llm'],

    # Python
    '.py': ['secrets', 'injection', 'database', 'auth', 'ai_llm', 'crypto', 'logging_security', 'filesystem', 'privacy'],

    # SQL
    '.sql': ['database', 'secrets'],

    # Config / Env
    '.env': ['secrets'],
    '.env.local': ['secrets'],
    '.env.production': ['secrets'],
    '.env.development': ['secrets'],

    # JSON (package.json, tsconfig, etc.)
    '.json': ['secrets', 'supply_chain'],

    # YAML / TOML / INI
    '.yaml': ['secrets', 'infrastructure', 'supply_chain'],
    '.yml': ['secrets', 'infrastructure', 'supply_chain'],
    '.toml': ['secrets'],
    '.ini': ['secrets'],

    # Docker
    '.dockerfile': ['infrastructure', 'secrets', 'supply_chain'],

    # HTML
    '.html': ['injection', 'headers', 'supply_chain', 'privacy'],
    '.htm': ['injection', 'headers', 'supply_chain'],

    # Go
    '.go': ['secrets', 'injection', 'auth', 'crypto', 'database', 'network'],

    # Ruby
    '.rb': ['secrets', 'injection', 'auth', 'database', 'crypto'],
    '.erb': ['injection', 'secrets'],

    # PHP
    '.php': ['secrets', 'injection', 'auth', 'database', 'crypto', 'filesystem'],

    # Shell
    '.sh': ['secrets', 'injection', 'infrastructure', 'filesystem'],
    '.bash': ['secrets', 'injection', 'infrastructure', 'filesystem'],
    '.zsh': ['secrets', 'injection', 'infrastructure'],

    # Rust
    '.rs': ['secrets', 'crypto', 'injection'],

    # Terraform / IaC
    '.tf': ['secrets', 'infrastructure'],
    '.hcl': ['secrets', 'infrastructure'],

    # Kubernetes
    '.k8s.yaml': ['secrets', 'infrastructure'],
    '.k8s.yml': ['secrets', 'infrastructure'],

    # GraphQL
    '.graphql': ['database', 'injection'],
    '.gql': ['database', 'injection'],

    # Markdown (only check for accidental secrets)
    '.md': ['secrets'],

    # CSS (only check for injection)
    '.css': ['injection'],
    '.scss': ['injection'],
}

# Special filename handling (overrides extension)
FILENAME_MAP = {
    'Dockerfile': ['infrastructure', 'secrets', 'supply_chain'],
    'docker-compose.yml': ['infrastructure', 'secrets'],
    'docker-compose.yaml': ['infrastructure', 'secrets'],
    '.gitignore': [],  # No checks needed
    'package.json': ['secrets', 'supply_chain'],
    'package-lock.json': ['supply_chain'],
    'yarn.lock': ['supply_chain'],
    'pnpm-lock.yaml': ['supply_chain'],
    'requirements.txt': ['supply_chain'],
    'Pipfile': ['supply_chain'],
    'Gemfile': ['supply_chain'],
    'go.mod': ['supply_chain'],
    'Cargo.toml': ['supply_chain'],
    '.npmrc': ['secrets', 'supply_chain'],
    '.yarnrc': ['secrets', 'supply_chain'],
    'netlify.toml': ['secrets', 'infrastructure'],
    'vercel.json': ['secrets', 'infrastructure'],
    'next.config.js': ['secrets', 'headers', 'network', 'infrastructure'],
    'next.config.mjs': ['secrets', 'headers', 'network', 'infrastructure'],
    'next.config.ts': ['secrets', 'headers', 'network', 'infrastructure'],
    'vite.config.ts': ['secrets', 'network'],
    'vite.config.js': ['secrets', 'network'],
    'nginx.conf': ['headers', 'network', 'infrastructure'],
    'Makefile': ['secrets', 'supply_chain', 'infrastructure'],
}


# Cache for loaded checker modules
_checker_cache = {}


def _get_checker_modules(file_path: str) -> list:
    """Determine which checker modules to load for a given file path."""
    if not file_path:
        return []

    basename = os.path.basename(file_path)

    # Check filename-specific mapping first
    if basename in FILENAME_MAP:
        return FILENAME_MAP[basename]

    # Check extension
    _, ext = os.path.splitext(file_path.lower())
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]

    # Default: just check for secrets in unknown files
    return ['secrets']


def _load_checker(module_name: str):
    """Dynamically import a checker module. Cache on first load."""
    if module_name in _checker_cache:
        return _checker_cache[module_name]

    try:
        mod = __import__(f'checkers.{module_name}', fromlist=['check'])
        _checker_cache[module_name] = mod
        return mod
    except ImportError:
        _checker_cache[module_name] = None
        return None


def run_checks(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run all relevant security checks on the given content.

    Args:
        content: The file content or diff to check
        file_path: The path of the file being written
        config: Optional .0xguard.json config dict

    Returns:
        List of CheckResult findings, sorted by severity (CRITICAL first)
    """
    if not content:
        return []

    if config is None:
        config = {}

    module_names = _get_checker_modules(file_path)
    if not module_names:
        return []

    results = []
    for module_name in module_names:
        checker = _load_checker(module_name)
        if checker and hasattr(checker, 'check'):
            try:
                findings = checker.check(content, file_path, config)
                if findings:
                    results.extend(findings)
            except Exception:
                # Never let a checker crash block the developer
                pass

    # Sort: CRITICAL first, then WARNING, then INFO
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    results.sort(key=lambda r: severity_order.get(r.severity, 3))

    return results


def run_all_checks(content: str, file_path: str, config: dict = None) -> List[CheckResult]:
    """Run ALL checker modules regardless of file extension.

    Used by the full scan skill and security-scanner agent.
    """
    if not content:
        return []

    if config is None:
        config = {}

    all_modules = [
        'secrets', 'auth', 'database', 'network', 'injection',
        'headers', 'supply_chain', 'infrastructure', 'ai_llm',
        'crypto', 'privacy', 'business_logic', 'logging_security',
        'filesystem', 'websocket',
    ]

    results = []
    for module_name in all_modules:
        checker = _load_checker(module_name)
        if checker and hasattr(checker, 'check'):
            try:
                findings = checker.check(content, file_path, config)
                if findings:
                    results.extend(findings)
            except Exception:
                pass

    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    results.sort(key=lambda r: severity_order.get(r.severity, 3))

    return results
