"""
BugHunter AI — Data Models
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(str, Enum):
    INJECTION = "injection"
    AUTH = "authentication"
    XSS = "xss"
    CORS = "cors"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    CRYPTO = "cryptography"
    SECRETS = "secrets"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    CSRF = "csrf"
    MISCONFIG = "misconfiguration"
    DEPENDENCY = "dependency"
    OTHER = "other"


@dataclass
class CodeSnippet:
    content: str
    start_line: int
    end_line: int
    highlighted_lines: List[int] = field(default_factory=list)


@dataclass
class Fix:
    description: str
    code_before: Optional[str] = None
    code_after: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    # Identity
    vuln_id: str
    vuln_type: str
    category: VulnCategory
    severity: Severity

    # Location
    file_path: Path
    line_number: int
    column: int = 0
    end_line: Optional[int] = None

    # Description
    title: str = ""
    description: str = ""
    impact: str = ""
    recommendation: str = ""

    # Evidence
    snippet: Optional[CodeSnippet] = None
    matched_pattern: Optional[str] = None

    # AI fields
    ai_confirmed: bool = False
    ai_explanation: Optional[str] = None
    confidence: float = 0.5   # 0.0 – 1.0

    # References
    cwe_id: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    references: List[str] = field(default_factory=list)

    # Fix
    fix: Optional[Fix] = None

    # Metadata
    detector: str = "static"
    false_positive_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.vuln_id,
            "type": self.vuln_type,
            "category": self.category.value,
            "severity": self.severity.value,
            "file": str(self.file_path),
            "line": self.line_number,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "cwe": self.cwe_id,
            "owasp": self.owasp_category,
            "confidence": self.confidence,
            "ai_confirmed": self.ai_confirmed,
            "detector": self.detector,
        }

    @property
    def severity_emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }.get(self.severity, "⚪")

    @property
    def short_path(self) -> str:
        parts = self.file_path.parts
        if len(parts) > 3:
            return f".../{'/'.join(parts[-2:])}"
        return str(self.file_path)
