"""
BugHunter AI — Static Analyzer
AST-based analysis for Python + heuristic analysis for other languages
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import List, Optional

from bughunter.models import Vulnerability, Severity, VulnCategory, CodeSnippet


class StaticAnalyzer:
    """Static code analysis using AST (Python) and heuristics."""

    def __init__(self, config):
        self.config = config

    async def analyze(self, file_path: Path) -> List[Vulnerability]:
        suffix = file_path.suffix.lower()
        if suffix == ".py":
            return await self._analyze_python(file_path)
        return []  # Pattern analyzer handles other langs

    async def _analyze_python(self, file_path: Path) -> List[Vulnerability]:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (SyntaxError, Exception):
            return []

        visitor = PythonVulnVisitor(source, file_path)
        visitor.visit(tree)
        return visitor.vulns


class PythonVulnVisitor(ast.NodeVisitor):
    """AST visitor that detects Python-specific vulnerabilities."""

    def __init__(self, source: str, file_path: Path):
        self.source = source
        self.lines = source.splitlines()
        self.file_path = file_path
        self.vulns: List[Vulnerability] = []

    def _vuln(self, node, vuln_id, title, description, severity, category,
              recommendation="", cwe=None, owasp=None) -> Vulnerability:
        line = node.lineno
        start = max(0, line - 3)
        end = min(len(self.lines), line + 3)
        snippet = "\n".join(self.lines[start:end])

        return Vulnerability(
            vuln_id=f"{vuln_id}-{hashlib.md5(f'{self.file_path}{line}'.encode()).hexdigest()[:6]}",
            vuln_type=vuln_id.lower(),
            category=category,
            severity=severity,
            file_path=self.file_path,
            line_number=line,
            title=title,
            description=description,
            recommendation=recommendation,
            snippet=CodeSnippet(content=snippet, start_line=start+1, end_line=end, highlighted_lines=[line]),
            cwe_id=cwe,
            owasp_category=owasp,
            detector="static_ast",
            confidence=0.80,
        )

    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node)

        # exec() / eval() with non-constant argument
        if func_name in ("eval", "exec"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.vulns.append(self._vuln(
                    node, "AST-EXEC",
                    "exec()/eval() with Dynamic Argument",
                    "exec() or eval() called with a non-constant argument — possible code injection.",
                    Severity.CRITICAL, VulnCategory.INJECTION,
                    "Avoid exec/eval with user input. Refactor to use safer alternatives.",
                    "CWE-78", "A03:2021 Injection",
                ))

        # os.system() with any non-constant
        if func_name in ("os.system", "os.popen"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.vulns.append(self._vuln(
                    node, "AST-OSSYS",
                    f"{func_name}() with Dynamic Argument",
                    f"{func_name}() with a potentially user-controlled argument.",
                    Severity.CRITICAL, VulnCategory.INJECTION,
                    "Use subprocess.run() with shell=False and a list of arguments.",
                    "CWE-78", "A03:2021 Injection",
                ))

        # subprocess with shell=True
        if func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.vulns.append(self._vuln(
                        node, "AST-SUBSHELL",
                        "subprocess with shell=True",
                        "subprocess called with shell=True — enables shell injection if input is user-controlled.",
                        Severity.HIGH, VulnCategory.INJECTION,
                        "Use shell=False and pass a list: subprocess.run(['cmd', arg])",
                        "CWE-78", "A03:2021 Injection",
                    ))

        # pickle.loads()
        if func_name in ("pickle.loads", "pickle.load", "cPickle.loads"):
            self.vulns.append(self._vuln(
                node, "AST-PICKLE",
                "Unsafe pickle Deserialization",
                "pickle.loads/load on potentially untrusted data allows RCE.",
                Severity.CRITICAL, VulnCategory.DESERIALIZATION,
                "Never deserialize untrusted data with pickle. Use JSON instead.",
                "CWE-502", "A08:2021 Software and Data Integrity Failures",
            ))

        # yaml.load without SafeLoader
        if func_name == "yaml.load":
            safe = any(
                (isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader")
                or (isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader")
                for kw in node.keywords if kw.arg == "Loader"
            )
            if not safe:
                self.vulns.append(self._vuln(
                    node, "AST-YAML",
                    "yaml.load() Without SafeLoader",
                    "yaml.load() without SafeLoader can execute arbitrary Python code.",
                    Severity.HIGH, VulnCategory.DESERIALIZATION,
                    "Use yaml.safe_load() instead.",
                    "CWE-502", "A08:2021 Software and Data Integrity Failures",
                ))

        # hashlib.md5 / sha1
        if func_name in ("hashlib.md5", "hashlib.new") or (
            isinstance(node.func, ast.Attribute) and node.func.attr in ("md5", "sha1")
        ):
            self.vulns.append(self._vuln(
                node, "AST-HASH",
                "Weak Hash Algorithm Used",
                "MD5/SHA1 is cryptographically weak.",
                Severity.HIGH, VulnCategory.CRYPTO,
                "Use hashlib.sha256() or stronger. For passwords, use bcrypt/argon2.",
                "CWE-327", "A02:2021 Cryptographic Failures",
            ))

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        """Detect use of assert for security checks (removed with -O flag)."""
        # Check if assert appears to be doing auth/security check
        test_src = ast.unparse(node.test) if hasattr(ast, 'unparse') else ""
        if any(kw in test_src.lower() for kw in ("user", "auth", "permission", "admin", "role", "token")):
            self.vulns.append(self._vuln(
                node, "AST-ASSERT",
                "Security Check Using assert Statement",
                "assert statements are removed when Python runs with -O (optimize) flag, disabling the check.",
                Severity.HIGH, VulnCategory.AUTH,
                "Replace assert with proper if/raise statements for security checks.",
                "CWE-617", "A07:2021 Identification and Authentication Failures",
            ))
        self.generic_visit(node)

    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            return ".".join(reversed(parts))
        return ""
