"""
BugHunter AI — False Positive Filter
Reduces noise by filtering out likely false positives
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from bughunter.models import Vulnerability

# Test file patterns — lower confidence for test code
TEST_PATTERNS = [
    re.compile(r'(?i)(test_|_test\.|spec\.|\.spec\.|\/tests\/|\/test\/|__tests__|mock|fixture|example)'),
]

# Comment patterns
COMMENT_PATTERNS = [
    re.compile(r'^\s*#'),    # Python comment
    re.compile(r'^\s*//'),   # JS/Java comment
    re.compile(r'^\s*/\*'),  # Block comment start
    re.compile(r'^\s*\*'),   # Block comment continuation
]

# Safe patterns — if line contains these, likely not vulnerable
SAFE_INDICATORS = {
    "cors": ["whitelist", "allowlist", "validate", "check_origin", "allowed_origins", "ALLOWED_ORIGINS"],
    "sqli": ["parameterized", "prepared", "escape", "sanitize", "orm", "ORM", "sqlalchemy"],
    "xss": ["escape", "sanitize", "DOMPurify", "encodeURIComponent", "htmlspecialchars"],
    "secrets": ["os.getenv", "environ.get", "getenv", "os.environ", "config.", "settings.", "vault", "placeholder", "example"],
}


class FalsePositiveFilter:
    """Filters likely false positives from vulnerability results."""

    def filter(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        return [v for v in vulns if not self._is_false_positive(v)]

    def _is_false_positive(self, vuln: Vulnerability) -> bool:
        # Check if in test file
        path_str = str(vuln.file_path)
        for pat in TEST_PATTERNS:
            if pat.search(path_str):
                vuln.confidence *= 0.5
                vuln.false_positive_score += 0.4

        # Check if the matched line is a comment
        if vuln.snippet:
            lines = vuln.snippet.content.splitlines()
            matched_lines = [l for i, l in enumerate(lines, start=vuln.snippet.start_line)
                           if i == vuln.line_number]
            if matched_lines:
                line = matched_lines[0]
                for cp in COMMENT_PATTERNS:
                    if cp.match(line):
                        return True  # Definitely FP — it's in a comment

        # Check for safe indicators
        cat = vuln.category.value
        indicators = SAFE_INDICATORS.get(cat, [])
        if vuln.snippet and indicators:
            snippet_lower = vuln.snippet.content.lower()
            if any(ind.lower() in snippet_lower for ind in indicators):
                vuln.confidence *= 0.6
                vuln.false_positive_score += 0.3

        # Filter out if FP score too high
        return vuln.false_positive_score >= 0.9
