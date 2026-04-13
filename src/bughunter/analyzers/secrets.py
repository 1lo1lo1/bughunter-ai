"""
BugHunter AI — Secrets Analyzer
Finds API keys, tokens, credentials, and other secrets in source code
"""
from __future__ import annotations

import re
import hashlib
from pathlib import Path
from typing import List

from bughunter.models import Vulnerability, Severity, VulnCategory, CodeSnippet

SECRET_PATTERNS = [
    # AWS
    ("SECRETS-AWS-KEY",    r'AKIA[0-9A-Z]{16}',                               "AWS Access Key ID",           Severity.CRITICAL),
    ("SECRETS-AWS-SECRET", r'(?i)aws(.{0,20})?secret.{0,10}["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key", Severity.CRITICAL),

    # GitHub
    ("SECRETS-GH-TOKEN",   r'ghp_[a-zA-Z0-9]{36}',                            "GitHub Personal Access Token", Severity.CRITICAL),
    ("SECRETS-GH-OAUTH",   r'gho_[a-zA-Z0-9]{36}',                            "GitHub OAuth Token",           Severity.CRITICAL),
    ("SECRETS-GH-APP",     r'(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})',   "GitHub Fine-grained PAT",      Severity.CRITICAL),

    # OpenAI / Anthropic
    ("SECRETS-OPENAI",     r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}',   "OpenAI API Key",               Severity.CRITICAL),
    ("SECRETS-ANTHROPIC",  r'sk-ant-[a-zA-Z0-9\-]{90,}',                      "Anthropic API Key",            Severity.CRITICAL),

    # Stripe
    ("SECRETS-STRIPE-SK",  r'sk_live_[a-zA-Z0-9]{24,}',                       "Stripe Live Secret Key",       Severity.CRITICAL),
    ("SECRETS-STRIPE-PK",  r'pk_live_[a-zA-Z0-9]{24,}',                       "Stripe Live Publishable Key",  Severity.HIGH),
    ("SECRETS-STRIPE-RK",  r'rk_live_[a-zA-Z0-9]{24,}',                       "Stripe Restricted Key",        Severity.CRITICAL),

    # Slack
    ("SECRETS-SLACK-BOT",  r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',      "Slack Bot Token",              Severity.HIGH),
    ("SECRETS-SLACK-USER", r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{32}', "Slack User Token",        Severity.HIGH),
    ("SECRETS-SLACK-WH",   r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+', "Slack Webhook URL", Severity.HIGH),

    # Google
    ("SECRETS-GCP-KEY",    r'AIza[0-9A-Za-z_\-]{35}',                         "Google API Key",               Severity.HIGH),
    ("SECRETS-GCP-SA",     r'"type":\s*"service_account"',                     "GCP Service Account JSON",     Severity.CRITICAL),

    # Generic tokens
    ("SECRETS-JWT",        r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*', "JSON Web Token", Severity.MEDIUM),
    ("SECRETS-BEARER",     r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}={0,2}',     "Bearer Token",                 Severity.MEDIUM),

    # Database
    ("SECRETS-DB-CONN",    r'(?i)(mongodb(\+srv)?|postgresql|mysql|redis)://[^:]+:[^@]+@', "Database Connection String with Credentials", Severity.CRITICAL),
    ("SECRETS-PG-PASS",    r'(?i)PGPASSWORD\s*=\s*["\']?[^\s"\']{8,}["\']?',  "PostgreSQL Password",          Severity.CRITICAL),

    # Private keys
    ("SECRETS-RSA-KEY",    r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "Private Key",                 Severity.CRITICAL),
    ("SECRETS-PEM",        r'-----BEGIN CERTIFICATE-----',                      "SSL Certificate (embedded)",  Severity.MEDIUM),

    # Generic passwords in config
    ("SECRETS-GENERIC-PW", r'(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth_token)\s*[=:]\s*["\'][^"\']{8,}["\']', "Potential Hardcoded Secret", Severity.HIGH),
    ("SECRETS-ENV-LEAK",   r'(?i)(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*[^${\s][^\s]{8,}', "Exposed Secret in Config", Severity.HIGH),

    # Twilio
    ("SECRETS-TWILIO",     r'AC[a-z0-9]{32}',                                  "Twilio Account SID",           Severity.HIGH),

    # SendGrid
    ("SECRETS-SENDGRID",   r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',       "SendGrid API Key",             Severity.HIGH),

    # Heroku
    ("SECRETS-HEROKU",     r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "UUID/Heroku API Key", Severity.LOW),

    # npm auth tokens
    ("SECRETS-NPM",        r'//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9\-]+', "npm Auth Token",             Severity.HIGH),
]

# Files to skip for secrets (binary, lock files, etc.)
SKIP_EXTENSIONS = {".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".ttf"}

# False-positive patterns (test/example values)
FP_PATTERNS = [
    re.compile(r'(?i)(example|test|fake|dummy|sample|placeholder|your[-_]|<[^>]+>|\$\{|xxx|123456)'),
]


class SecretsAnalyzer:
    """Finds secrets, API keys, and credentials in source code."""

    def __init__(self, config):
        self.config = config
        self._compiled = [
            (pid, re.compile(pattern, re.MULTILINE), title, severity)
            for pid, pattern, title, severity in SECRET_PATTERNS
        ]

    async def analyze(self, file_path: Path) -> List[Vulnerability]:
        if file_path.suffix in SKIP_EXTENSIONS:
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()
        results = []

        for pid, regex, title, severity in self._compiled:
            for match in regex.finditer(content):
                matched = match.group(0)

                # Skip obvious false positives
                if any(fp.search(matched) for fp in FP_PATTERNS):
                    continue

                # Skip lines with comments that say "example" etc
                line_num = content[:match.start()].count("\n") + 1
                if line_num <= len(lines):
                    line_content = lines[line_num - 1]
                    if any(fp.search(line_content) for fp in FP_PATTERNS):
                        continue

                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 2)
                snippet_text = "\n".join(
                    f"{'>' if i + 1 == line_num else ' '} {lines[i]}"
                    for i in range(start, end)
                )

                # Redact the secret in display
                redacted = matched[:4] + "***REDACTED***" if len(matched) > 8 else "***REDACTED***"

                vuln = Vulnerability(
                    vuln_id=f"{pid}-{hashlib.md5(f'{file_path}{line_num}{pid}'.encode()).hexdigest()[:6]}",
                    vuln_type="secret_exposure",
                    category=VulnCategory.SECRETS,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"Secret Exposed: {title}",
                    description=f"A {title} was found hardcoded in the source file. Value: {redacted}",
                    impact="If this file is committed to version control or exposed, the secret can be used by attackers.",
                    recommendation=(
                        "1. Revoke/rotate this secret immediately.\n"
                        "2. Remove from source code.\n"
                        "3. Store in environment variables or a secrets manager (Vault, AWS Secrets Manager).\n"
                        "4. Add .env to .gitignore."
                    ),
                    snippet=CodeSnippet(
                        content=snippet_text,
                        start_line=start + 1,
                        end_line=end,
                        highlighted_lines=[line_num],
                    ),
                    matched_pattern=redacted,
                    cwe_id="CWE-798",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    detector="secrets",
                    confidence=0.85,
                )
                results.append(vuln)

        return results
