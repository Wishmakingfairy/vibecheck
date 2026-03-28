#!/usr/bin/env python3
"""
preflight Security Gate - PreToolUse Hook
Intercepts Write/Edit/MultiEdit operations and scans content for 156 security vulnerabilities.
Blocks CRITICAL findings, warns on WARNING findings, passes INFO silently.

Author: Haralds Gabrans
License: MIT
"""

import json
import os
import sys
import re

# Resolve paths relative to this script's location
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKERS_DIR = os.path.join(PLUGIN_ROOT, "checkers")

# Add checkers directory to Python path
if CHECKERS_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_ROOT)

# Inline suppression pattern: // preflight-disable CHECK-ID or # preflight-disable CHECK-ID
SUPPRESSION_PATTERN = re.compile(
    r'(?://|#|/\*)\s*preflight-disable\s+([\w,-]+)', re.IGNORECASE
)

# Test file patterns that trigger auto-downgrade from CRITICAL to WARNING
TEST_FILE_PATTERNS = [
    r'\.test\.',
    r'\.spec\.',
    r'__tests__/',
    r'__mocks__/',
    r'/tests?/',
    r'/fixtures?/',
    r'\.stories\.',
    r'\.mock\.',
    r'/mock/',
    r'test_.*\.py$',
    r'.*_test\.py$',
    r'.*_test\.go$',
]
TEST_FILE_RE = re.compile('|'.join(TEST_FILE_PATTERNS))

# Config file name
CONFIG_FILENAME = '.preflight.json'


def load_config(file_path):
    """Load project-level .preflight.json config.

    Walks up from the file being written to find the nearest config file.
    Returns default config if none found.
    """
    default_config = {
        'severity_overrides': {},
        'disabled': [],
        'ignore_paths': [],
        'baseline_mode': False,
        'inline_suppression': True,
        'framework': 'auto',
    }

    if not file_path:
        return default_config

    # Walk up directories to find config
    search_dir = os.path.dirname(os.path.abspath(file_path))
    for _ in range(20):  # Max depth to prevent infinite loop
        config_path = os.path.join(search_dir, CONFIG_FILENAME)
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                # Merge with defaults
                for key in default_config:
                    if key not in user_config:
                        user_config[key] = default_config[key]
                return user_config
            except (json.JSONDecodeError, IOError):
                return default_config
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent

    return default_config


def extract_content(tool_name, tool_input):
    """Extract content to scan from tool input based on tool type."""
    if tool_name == 'Write':
        return tool_input.get('content', '')
    elif tool_name == 'Edit':
        return tool_input.get('new_string', '')
    elif tool_name == 'MultiEdit':
        edits = tool_input.get('edits', [])
        if edits:
            return '\n'.join(edit.get('new_string', '') for edit in edits)
        return ''
    return ''


def extract_suppressed_checks(content):
    """Find all check IDs suppressed via inline comments."""
    suppressed = set()
    for match in SUPPRESSION_PATTERN.finditer(content):
        ids = match.group(1).split(',')
        for check_id in ids:
            suppressed.add(check_id.strip().upper())
    return suppressed


def is_test_file(file_path):
    """Check if the file is a test/spec/fixture file."""
    if not file_path:
        return False
    return bool(TEST_FILE_RE.search(file_path))


def should_ignore_path(file_path, ignore_patterns):
    """Check if file path matches any ignore patterns from config."""
    if not file_path or not ignore_patterns:
        return False

    from fnmatch import fnmatch
    for pattern in ignore_patterns:
        if fnmatch(file_path, pattern):
            return True
    return False


def is_config_weakening(file_path, content):
    """Detect writes to .preflight.json that weaken security (add disabled checks)."""
    if not file_path or not file_path.endswith(CONFIG_FILENAME):
        return False
    try:
        new_config = json.loads(content)
        if new_config.get('disabled') and len(new_config['disabled']) > 0:
            return True
    except (json.JSONDecodeError, TypeError):
        pass
    return False


def main():
    """Main hook entry point."""
    # Read JSON from stdin
    try:
        raw_input = sys.stdin.read()
        input_data = json.loads(raw_input)
    except (json.JSONDecodeError, IOError):
        # Can't parse input, allow the operation
        sys.exit(0)

    tool_name = input_data.get('tool_name', '')
    tool_input = input_data.get('tool_input', {})

    # Only process Write/Edit/MultiEdit
    if tool_name not in ('Write', 'Edit', 'MultiEdit'):
        sys.exit(0)

    file_path = tool_input.get('file_path', '')
    if not file_path:
        sys.exit(0)

    # Extract content to scan
    content = extract_content(tool_name, tool_input)
    if not content:
        sys.exit(0)

    # Load project config
    config = load_config(file_path)

    # Check if path should be ignored
    if should_ignore_path(file_path, config.get('ignore_paths', [])):
        sys.exit(0)

    # Check for config weakening
    if is_config_weakening(file_path, content):
        print(
            "\n\u26a0\ufe0f  preflight: You are disabling security checks in .preflight.json.\n"
            "  Make sure this is intentional. Disabled checks will no longer protect your codebase.\n"
            "  Prefer inline suppression (// preflight-disable CHECK-ID) for specific cases.\n",
            file=sys.stderr
        )
        # Warn but allow
        sys.exit(0)

    # Get inline suppressions
    suppressed = set()
    if config.get('inline_suppression', True):
        suppressed = extract_suppressed_checks(content)

    # Determine if this is a test file
    is_test = is_test_file(file_path)

    # Get disabled checks from config
    disabled = set(c.upper() for c in config.get('disabled', []))

    # Import and run checkers
    try:
        from checkers import run_checks, Severity
    except ImportError:
        # Checkers not available (maybe plugin not fully installed)
        sys.exit(0)

    results = run_checks(content, file_path, config)

    if not results:
        sys.exit(0)

    # Process results
    blocked = []
    warned = []

    for result in results:
        check_id = result.check_id.upper()

        # Skip suppressed and disabled checks
        if check_id in suppressed or check_id in disabled:
            continue

        # Apply severity overrides from config
        severity = result.severity
        override = config.get('severity_overrides', {}).get(check_id)
        if override:
            severity_map = {'CRITICAL': Severity.CRITICAL, 'WARNING': Severity.WARNING, 'INFO': Severity.INFO}
            severity = severity_map.get(override.upper(), severity)

        # Auto-downgrade for test files
        if is_test and severity == Severity.CRITICAL:
            severity = Severity.WARNING

        if severity == Severity.CRITICAL:
            blocked.append(result)
        elif severity == Severity.WARNING:
            warned.append(result)
        # INFO is silent in hook mode

    # Output warnings (non-blocking)
    for result in warned:
        print(
            f"\n\u26a0\ufe0f  preflight [{result.check_id}] {result.category}: {result.message}"
            f"\n   Fix: {result.fix_suggestion}"
            f"\n   Suppress: // preflight-disable {result.check_id}\n",
            file=sys.stderr
        )

    # Block on CRITICAL findings
    if blocked:
        output = ["\n\U0001f6d1 preflight BLOCKED this write. Security vulnerabilities detected:\n"]
        for result in blocked:
            output.append(
                f"  [{result.check_id}] {result.category} | {result.message}\n"
                f"  \u2192 {result.fix_suggestion}\n"
                f"  CWE: {result.cwe}\n"
            )
        output.append(
            f"  Suppress if intentional: // preflight-disable {','.join(r.check_id for r in blocked)}\n"
        )
        print('\n'.join(output), file=sys.stderr)
        sys.exit(2)

    # All clear
    sys.exit(0)


if __name__ == '__main__':
    main()
