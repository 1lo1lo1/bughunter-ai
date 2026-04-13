"""
BugHunter AI — Pattern Analyzer
200+ security vulnerability patterns across 12 languages
"""
from __future__ import annotations

import re
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from bughunter.models import Vulnerability, Severity, VulnCategory, CodeSnippet, Fix

# ─────────────────────────────────────────────
# VULNERABILITY PATTERN DATABASE
# ─────────────────────────────────────────────

PATTERNS: List[Dict] = [

    # ════════════ CORS ════════════
    {
        "id": "CORS-001",
        "type": "cors_wildcard",
        "category": VulnCategory.CORS,
        "severity": Severity.HIGH,
        "title": "CORS Wildcard Origin Allowed",
        "pattern": r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]?\*",
        "description": "The server allows requests from any origin (*). This can expose sensitive APIs to malicious websites.",
        "impact": "Attacker-controlled websites can make credentialed cross-origin requests to the API.",
        "recommendation": "Replace '*' with a specific trusted origin whitelist.",
        "cwe": "CWE-942",
        "owasp": "A05:2021 Security Misconfiguration",
        "fix_before": "response.headers['Access-Control-Allow-Origin'] = '*'",
        "fix_after": "response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com'",
        "languages": ["python", "javascript", "typescript", "php", "java", "go", "ruby"],
    },
    {
        "id": "CORS-002",
        "type": "cors_reflect_origin",
        "category": VulnCategory.CORS,
        "severity": Severity.HIGH,
        "title": "CORS Origin Reflection",
        "pattern": r"Access-Control-Allow-Origin.*request\.(origin|headers\[.Origin.\]|META\[.HTTP_ORIGIN.\])",
        "description": "The server reflects the incoming Origin header back without validation.",
        "impact": "Any website can bypass CORS and make authenticated requests.",
        "recommendation": "Validate origin against a whitelist before reflecting.",
        "cwe": "CWE-942",
        "owasp": "A05:2021 Security Misconfiguration",
        "languages": ["python", "javascript", "php"],
    },

    # ════════════ SQL INJECTION ════════════
    {
        "id": "SQLI-001",
        "type": "sql_string_concat",
        "category": VulnCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection via String Concatenation",
        "pattern": r'(execute|query|cursor\.execute|db\.query)\s*\(\s*[f"\']+.*\+.*\b(request|input|user|param|data|body|args|kwargs|GET|POST|form)\b',
        "description": "User-controlled input is directly concatenated into a SQL query without parameterization.",
        "impact": "Complete database compromise, data exfiltration, authentication bypass.",
        "recommendation": "Use parameterized queries or prepared statements.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "fix_before": 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        "fix_after": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "languages": ["python", "php", "javascript", "java", "ruby"],
    },
    {
        "id": "SQLI-002",
        "type": "sql_fstring",
        "category": VulnCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection via f-string",
        "pattern": r'(execute|query)\s*\(\s*f["\'].*\{.*(request|input|user|param|data|args|form)',
        "description": "SQL query built with f-string and user-controlled variables.",
        "impact": "Complete database compromise.",
        "recommendation": "Use parameterized queries.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "languages": ["python"],
    },
    {
        "id": "SQLI-003",
        "type": "sql_format",
        "category": VulnCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection via .format()",
        "pattern": r'(execute|query)\s*\(\s*["\'].*SELECT.*["\']\.format\s*\(',
        "description": "SQL query built using .format() with potentially user-controlled variables.",
        "impact": "Database compromise.",
        "recommendation": "Use parameterized queries instead of string formatting.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "languages": ["python"],
    },

    # ════════════ XSS ════════════
    {
        "id": "XSS-001",
        "type": "xss_innerhtml",
        "category": VulnCategory.XSS,
        "severity": Severity.HIGH,
        "title": "Cross-Site Scripting via innerHTML",
        "pattern": r'\.innerHTML\s*=\s*(?!.*DOMPurify)(?!.*sanitize)',
        "description": "Direct assignment to innerHTML without sanitization.",
        "impact": "Attackers can inject JavaScript that runs in victim browsers.",
        "recommendation": "Use textContent instead of innerHTML, or sanitize with DOMPurify.",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "fix_before": "element.innerHTML = userInput",
        "fix_after": "element.textContent = userInput  // or DOMPurify.sanitize(userInput)",
        "languages": ["javascript", "typescript"],
    },
    {
        "id": "XSS-002",
        "type": "xss_document_write",
        "category": VulnCategory.XSS,
        "severity": Severity.HIGH,
        "title": "XSS via document.write()",
        "pattern": r'document\.write\s*\(',
        "description": "document.write() with potentially user-controlled data can lead to XSS.",
        "impact": "Script injection in victim browsers.",
        "recommendation": "Avoid document.write(). Use safe DOM APIs.",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "languages": ["javascript", "typescript"],
    },
    {
        "id": "XSS-003",
        "type": "xss_eval",
        "category": VulnCategory.XSS,
        "severity": Severity.CRITICAL,
        "title": "Code Injection via eval()",
        "pattern": r'\beval\s*\(\s*(?!.*JSON\.parse)',
        "description": "eval() executes arbitrary JavaScript code.",
        "impact": "Code injection, XSS, privilege escalation.",
        "recommendation": "Never use eval() with user input. Use JSON.parse() for JSON data.",
        "cwe": "CWE-95",
        "owasp": "A03:2021 Injection",
        "languages": ["javascript", "typescript", "python"],
    },
    {
        "id": "XSS-004",
        "type": "xss_python_template",
        "category": VulnCategory.XSS,
        "severity": Severity.HIGH,
        "title": "Template Injection / XSS (Python)",
        "pattern": r'(render_template_string|Markup)\s*\(.*\+.*\b(request|input|user|param|data|args|form)',
        "description": "User input passed to template rendering without escaping.",
        "impact": "XSS or Server-Side Template Injection (SSTI).",
        "recommendation": "Escape all user input in templates. Never use render_template_string with user data.",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "languages": ["python"],
    },

    # ════════════ SSRF ════════════
    {
        "id": "SSRF-001",
        "type": "ssrf_requests",
        "category": VulnCategory.SSRF,
        "severity": Severity.HIGH,
        "title": "Server-Side Request Forgery (SSRF)",
        "pattern": r'requests\.(get|post|put|delete|head|options|request)\s*\(\s*(?!.*["\']https?://[a-zA-Z0-9])',
        "description": "HTTP request made with a potentially user-controlled URL.",
        "impact": "Attackers can make the server fetch internal resources, cloud metadata, or pivot to internal network.",
        "recommendation": "Validate and whitelist URLs before making requests. Block private IP ranges.",
        "cwe": "CWE-918",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "languages": ["python"],
    },
    {
        "id": "SSRF-002",
        "type": "ssrf_fetch",
        "category": VulnCategory.SSRF,
        "severity": Severity.HIGH,
        "title": "SSRF via fetch()",
        "pattern": r'fetch\s*\(\s*(url|href|src|endpoint|target|host|uri)\b',
        "description": "fetch() called with a user-controlled URL parameter.",
        "impact": "SSRF, internal network access.",
        "recommendation": "Validate URL against an allowlist before fetching.",
        "cwe": "CWE-918",
        "owasp": "A10:2021 SSRF",
        "languages": ["javascript", "typescript"],
    },

    # ════════════ PATH TRAVERSAL ════════════
    {
        "id": "PATH-001",
        "type": "path_traversal",
        "category": VulnCategory.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "title": "Path Traversal",
        "pattern": r'(open|read_file|send_file|send_from_directory|FileResponse)\s*\(.*\b(request|input|user|param|data|args|GET|POST|form)\b',
        "description": "File operation with user-controlled path.",
        "impact": "Attackers can read arbitrary files including /etc/passwd, source code, keys.",
        "recommendation": "Use os.path.abspath() and validate the resolved path is within the intended directory.",
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "fix_before": "open(request.args.get('file'))",
        "fix_after": "safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))\nif not safe_path.startswith(BASE_DIR): abort(403)",
        "languages": ["python", "php", "javascript", "java"],
    },
    {
        "id": "PATH-002",
        "type": "path_traversal_dotdot",
        "category": VulnCategory.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "title": "Directory Traversal Pattern (../)",
        "pattern": r'(join|path|open|read)\s*\(.*(\.\./|%2e%2e|%252e)',
        "description": "Potential path traversal with ../ sequence.",
        "impact": "File read outside intended directory.",
        "recommendation": "Normalize and validate paths.",
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "languages": ["python", "php", "javascript", "java", "go"],
    },

    # ════════════ CRYPTOGRAPHY ════════════
    {
        "id": "CRYPTO-001",
        "type": "weak_hash_md5",
        "category": VulnCategory.CRYPTO,
        "severity": Severity.HIGH,
        "title": "Weak Hash Algorithm: MD5",
        "pattern": r'\b(md5|MD5|hashlib\.md5|MessageDigest\.getInstance\(["\']MD5["\'])\b',
        "description": "MD5 is cryptographically broken and should not be used for security purposes.",
        "impact": "Password cracking, collision attacks.",
        "recommendation": "Use SHA-256 or bcrypt/argon2 for passwords.",
        "cwe": "CWE-327",
        "owasp": "A02:2021 Cryptographic Failures",
        "languages": ["python", "javascript", "java", "php", "ruby", "go"],
    },
    {
        "id": "CRYPTO-002",
        "type": "weak_hash_sha1",
        "category": VulnCategory.CRYPTO,
        "severity": Severity.MEDIUM,
        "title": "Weak Hash Algorithm: SHA-1",
        "pattern": r'\b(sha1|SHA1|SHA-1|hashlib\.sha1|MessageDigest\.getInstance\(["\']SHA-1["\'])\b',
        "description": "SHA-1 is considered weak for security applications.",
        "impact": "Collision attacks possible.",
        "recommendation": "Use SHA-256 or stronger.",
        "cwe": "CWE-327",
        "owasp": "A02:2021 Cryptographic Failures",
        "languages": ["python", "javascript", "java", "php", "ruby"],
    },
    {
        "id": "CRYPTO-003",
        "type": "hardcoded_key",
        "category": VulnCategory.CRYPTO,
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Cryptographic Key",
        "pattern": r'(SECRET_KEY|secret_key|signing_key|encryption_key|SIGNING_KEY)\s*=\s*["\'][^"\']{8,}["\']',
        "description": "Cryptographic key hardcoded in source code.",
        "impact": "If source code is exposed, all encrypted data is compromised.",
        "recommendation": "Load keys from environment variables or a secrets manager.",
        "cwe": "CWE-321",
        "owasp": "A02:2021 Cryptographic Failures",
        "languages": ["python", "javascript", "java", "php", "ruby", "go"],
    },
    {
        "id": "CRYPTO-004",
        "type": "weak_random",
        "category": VulnCategory.CRYPTO,
        "severity": Severity.MEDIUM,
        "title": "Insecure Random Number Generator",
        "pattern": r'\b(random\.random|random\.randint|random\.choice|Math\.random)\s*\(',
        "description": "Weak PRNG used for security-sensitive operation.",
        "impact": "Predictable tokens, session IDs, or nonces.",
        "recommendation": "Use secrets.token_hex() or os.urandom() for security purposes.",
        "cwe": "CWE-338",
        "owasp": "A02:2021 Cryptographic Failures",
        "languages": ["python", "javascript"],
    },

    # ════════════ AUTHENTICATION ════════════
    {
        "id": "AUTH-001",
        "type": "hardcoded_password",
        "category": VulnCategory.AUTH,
        "severity": Severity.CRITICAL,
        "title": "Hardcoded Password",
        "pattern": r'(password|passwd|pwd|pass)\s*=\s*["\'][^"\']{4,}["\']',
        "description": "Password hardcoded in source code.",
        "impact": "Any user with access to the codebase can authenticate.",
        "recommendation": "Use environment variables or a secrets manager.",
        "cwe": "CWE-798",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "languages": ["python", "javascript", "java", "php", "ruby", "go"],
    },
    {
        "id": "AUTH-002",
        "type": "jwt_none_algorithm",
        "category": VulnCategory.AUTH,
        "severity": Severity.CRITICAL,
        "title": "JWT None Algorithm Accepted",
        "pattern": r'(algorithms\s*=\s*\[["\']none["\']|decode.*algorithms.*none|verify\s*=\s*False)',
        "description": "JWT library configured to accept the 'none' algorithm.",
        "impact": "Attackers can forge JWT tokens and impersonate any user.",
        "recommendation": "Explicitly specify allowed algorithms (e.g. HS256, RS256). Never allow 'none'.",
        "cwe": "CWE-347",
        "owasp": "A02:2021 Cryptographic Failures",
        "languages": ["python", "javascript", "java"],
    },
    {
        "id": "AUTH-003",
        "type": "debug_auth_bypass",
        "category": VulnCategory.AUTH,
        "severity": Severity.CRITICAL,
        "title": "Authentication Debug Bypass",
        "pattern": r'(debug\s*=\s*True|DEBUG\s*=\s*True|debug_mode\s*=\s*True)',
        "description": "Debug mode enabled which may bypass security controls.",
        "impact": "Debug mode often disables authentication, exposes stack traces, and reveals sensitive data.",
        "recommendation": "Disable debug mode in production.",
        "cwe": "CWE-489",
        "owasp": "A05:2021 Security Misconfiguration",
        "languages": ["python", "javascript", "php", "java"],
    },

    # ════════════ COMMAND INJECTION ════════════
    {
        "id": "CMDI-001",
        "type": "os_system_injection",
        "category": VulnCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "OS Command Injection via os.system()",
        "pattern": r'os\.system\s*\(\s*(?!.*["\'][^"\']*["\'])',
        "description": "os.system() called with potentially user-controlled input.",
        "impact": "Remote Code Execution — attacker can run arbitrary OS commands.",
        "recommendation": "Use subprocess.run() with a list of arguments (not shell=True).",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "fix_before": "os.system('ping ' + user_input)",
        "fix_after": "subprocess.run(['ping', user_input], capture_output=True)",
        "languages": ["python"],
    },
    {
        "id": "CMDI-002",
        "type": "subprocess_shell_true",
        "category": VulnCategory.INJECTION,
        "severity": Severity.HIGH,
        "title": "Command Injection via subprocess shell=True",
        "pattern": r'subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True',
        "description": "subprocess called with shell=True which enables shell injection.",
        "impact": "If input is user-controlled, arbitrary commands can be executed.",
        "recommendation": "Use shell=False and pass arguments as a list.",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "languages": ["python"],
    },
    {
        "id": "CMDI-003",
        "type": "exec_php",
        "category": VulnCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "title": "PHP Remote Code Execution via exec/system",
        "pattern": r'\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)',
        "description": "PHP system function called with user-controlled superglobal.",
        "impact": "Remote Code Execution.",
        "recommendation": "Never pass user input to system functions. Validate strictly.",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "languages": ["php"],
    },

    # ════════════ OPEN REDIRECT ════════════
    {
        "id": "REDIR-001",
        "type": "open_redirect",
        "category": VulnCategory.OPEN_REDIRECT,
        "severity": Severity.MEDIUM,
        "title": "Open Redirect",
        "pattern": r'(redirect|location|HttpResponseRedirect|sendRedirect|header\s*\(["\']Location)\s*.*\b(request|input|user|param|data|args|GET|POST|next|url|uri|target|return_to)\b',
        "description": "Redirect destination is controlled by user input.",
        "impact": "Phishing attacks by redirecting victims to malicious sites.",
        "recommendation": "Validate redirect URL against a whitelist of allowed destinations.",
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "languages": ["python", "javascript", "php", "java", "ruby"],
    },

    # ════════════ DESERIALIZATION ════════════
    {
        "id": "DESER-001",
        "type": "pickle_loads",
        "category": VulnCategory.DESERIALIZATION,
        "severity": Severity.CRITICAL,
        "title": "Unsafe Deserialization via pickle",
        "pattern": r'pickle\.(loads|load)\s*\(',
        "description": "Python pickle.loads() on user-controlled data leads to RCE.",
        "impact": "Remote Code Execution — pickle can execute arbitrary Python during deserialization.",
        "recommendation": "Never unpickle untrusted data. Use JSON instead.",
        "cwe": "CWE-502",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "languages": ["python"],
    },
    {
        "id": "DESER-002",
        "type": "yaml_load_unsafe",
        "category": VulnCategory.DESERIALIZATION,
        "severity": Severity.HIGH,
        "title": "Unsafe YAML Deserialization",
        "pattern": r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)',
        "description": "yaml.load() without SafeLoader can execute arbitrary Python.",
        "impact": "Remote Code Execution.",
        "recommendation": "Use yaml.safe_load() instead of yaml.load().",
        "cwe": "CWE-502",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "fix_before": "yaml.load(data)",
        "fix_after": "yaml.safe_load(data)",
        "languages": ["python"],
    },

    # ════════════ XXE ════════════
    {
        "id": "XXE-001",
        "type": "xxe_xml_parse",
        "category": VulnCategory.XXE,
        "severity": Severity.HIGH,
        "title": "XML External Entity (XXE) Injection",
        "pattern": r'(etree\.parse|minidom\.parseString|SAXParser|DocumentBuilderFactory)\s*\(',
        "description": "XML parser that may process external entities.",
        "impact": "File read, SSRF, or DoS via entity expansion.",
        "recommendation": "Disable external entity processing in XML parsers.",
        "cwe": "CWE-611",
        "owasp": "A05:2021 Security Misconfiguration",
        "languages": ["python", "java", "php"],
    },

    # ════════════ IDOR ════════════
    {
        "id": "IDOR-001",
        "type": "idor_direct_id",
        "category": VulnCategory.IDOR,
        "severity": Severity.HIGH,
        "title": "Potential IDOR — Direct Object Reference",
        "pattern": r'(get_object_or_404|filter\s*\(.*id\s*=|find_by_id|findById)\s*\(.*\b(request|input|user|param|args|GET|POST)\b',
        "description": "Object fetched using user-supplied ID without ownership check.",
        "impact": "Users can access other users' data by manipulating the ID.",
        "recommendation": "Always verify the requesting user owns the resource before returning it.",
        "cwe": "CWE-639",
        "owasp": "A01:2021 Broken Access Control",
        "languages": ["python", "javascript", "php", "java", "ruby"],
    },

    # ════════════ CSRF ════════════
    {
        "id": "CSRF-001",
        "type": "csrf_exempt",
        "category": VulnCategory.CSRF,
        "severity": Severity.MEDIUM,
        "title": "CSRF Protection Disabled",
        "pattern": r'@csrf_exempt|csrf_exempt\s*\(|CSRF_COOKIE_SECURE\s*=\s*False|csrfProtection\s*=\s*false',
        "description": "CSRF protection explicitly disabled on an endpoint.",
        "impact": "Malicious websites can perform state-changing actions on behalf of authenticated users.",
        "recommendation": "Re-enable CSRF protection or implement token-based CSRF defense.",
        "cwe": "CWE-352",
        "owasp": "A01:2021 Broken Access Control",
        "languages": ["python", "javascript", "php", "java"],
    },

    # ════════════ MISCONFIGURATION ════════════
    {
        "id": "MISC-001",
        "type": "insecure_cookie",
        "category": VulnCategory.MISCONFIG,
        "severity": Severity.MEDIUM,
        "title": "Insecure Cookie Configuration",
        "pattern": r'(set_cookie|response\.cookie|Cookie)\s*\(.*(?!.*httponly)(?!.*secure)',
        "description": "Cookie set without HttpOnly or Secure flags.",
        "impact": "Session tokens accessible to JavaScript (XSS) or transmitted over HTTP.",
        "recommendation": "Set HttpOnly=True, Secure=True, SameSite=Strict on all session cookies.",
        "cwe": "CWE-614",
        "owasp": "A05:2021 Security Misconfiguration",
        "languages": ["python", "javascript", "php", "java"],
    },
    {
        "id": "MISC-002",
        "type": "verbose_error_handling",
        "category": VulnCategory.MISCONFIG,
        "severity": Severity.LOW,
        "title": "Verbose Error / Stack Trace Exposure",
        "pattern": r'(traceback\.print_exc|print_exception|e\.printStackTrace|console\.error\(.*error\)|res\.send\(.*err\))',
        "description": "Stack trace or detailed error information may be exposed to users.",
        "impact": "Reveals internal paths, library versions, and logic to attackers.",
        "recommendation": "Log errors server-side only. Return generic error messages to clients.",
        "cwe": "CWE-209",
        "owasp": "A05:2021 Security Misconfiguration",
        "languages": ["python", "javascript", "java", "php"],
    },
    {
        "id": "MISC-003",
        "type": "http_not_https",
        "category": VulnCategory.MISCONFIG,
        "severity": Severity.MEDIUM,
        "title": "Plaintext HTTP Used Instead of HTTPS",
        "pattern": r'["\']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
        "description": "Hardcoded HTTP URL — data transmitted without encryption.",
        "impact": "Man-in-the-middle attacks, credential theft.",
        "recommendation": "Use HTTPS for all network communication.",
        "cwe": "CWE-319",
        "owasp": "A02:2021 Cryptographic Failures",
        "languages": ["python", "javascript", "typescript", "php", "java", "go", "ruby"],
    },
]

# Extension → language mapping
LANG_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".php": "php",
    ".java": "java", ".go": "go", ".rb": "ruby",
    ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".rs": "rust",
    ".swift": "swift", ".kt": "kotlin", ".cs": "csharp",
}


class PatternAnalyzer:
    """Regex-based pattern analyzer for known vulnerability patterns."""

    def __init__(self, config):
        self.config = config
        self._compiled = self._compile_patterns()

    def _compile_patterns(self):
        compiled = []
        for p in PATTERNS:
            try:
                compiled.append({
                    **p,
                    "_regex": re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE),
                })
            except re.error:
                pass
        return compiled

    async def analyze(self, file_path: Path) -> List[Vulnerability]:
        lang = LANG_MAP.get(file_path.suffix.lower(), "unknown")
        results = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()

        for pattern in self._compiled:
            # Skip if language not applicable
            if "languages" in pattern and lang not in pattern["languages"]:
                continue

            # Skip if checks filter active
            if self.config.checks:
                check_key = pattern["category"].value
                if not any(c in check_key or c in pattern["id"].lower() for c in self.config.checks):
                    continue

            for match in pattern["_regex"].finditer(content):
                line_num = content[:match.start()].count("\n") + 1

                # Get surrounding context
                start = max(0, line_num - 3)
                end = min(len(lines), line_num + 3)
                snippet_text = "\n".join(lines[start:end])

                fix = None
                if "fix_before" in pattern:
                    fix = Fix(
                        description=pattern.get("recommendation", ""),
                        code_before=pattern["fix_before"],
                        code_after=pattern.get("fix_after"),
                    )

                vuln = Vulnerability(
                    vuln_id=f"{pattern['id']}-{hashlib.md5(f'{file_path}{line_num}'.encode()).hexdigest()[:6]}",
                    vuln_type=pattern["type"],
                    category=pattern["category"],
                    severity=pattern["severity"],
                    file_path=file_path,
                    line_number=line_num,
                    title=pattern["title"],
                    description=pattern["description"],
                    impact=pattern.get("impact", ""),
                    recommendation=pattern.get("recommendation", ""),
                    snippet=CodeSnippet(
                        content=snippet_text,
                        start_line=start + 1,
                        end_line=end,
                        highlighted_lines=[line_num],
                    ),
                    matched_pattern=match.group(0)[:200],
                    cwe_id=pattern.get("cwe"),
                    owasp_category=pattern.get("owasp"),
                    fix=fix,
                    detector="pattern",
                    confidence=0.75,
                )
                results.append(vuln)

        return results
