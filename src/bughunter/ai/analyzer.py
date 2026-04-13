"""
BugHunter AI — AI Analyzer
Supports OpenAI GPT-4, Anthropic Claude, and local Ollama models
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from bughunter.models import Vulnerability, Severity, VulnCategory, CodeSnippet

AI_SYSTEM_PROMPT = """You are an elite security researcher and bug bounty hunter.
Your job is to analyze source code and identify security vulnerabilities.

For each vulnerability found, respond with a JSON array of objects with these fields:
- vuln_type: string (e.g. "sql_injection", "xss", "ssrf")
- severity: one of "critical", "high", "medium", "low", "info"
- category: one of "injection", "authentication", "xss", "cors", "ssrf", "path_traversal", "cryptography", "secrets", "business_logic", "idor", "csrf", "misconfiguration", "other"
- line_number: integer
- title: short title
- description: detailed description
- impact: business impact
- recommendation: how to fix
- cwe_id: CWE identifier (e.g. "CWE-89")
- confidence: float 0.0-1.0

Only return the JSON array, no other text. If no issues found, return [].
Focus on: CORS, SQLi, XSS, SSRF, path traversal, auth bypass, business logic flaws, IDOR, secrets.
Be thorough but avoid false positives. Mark confidence honestly.
"""


class AIAnalyzer:
    """AI-powered vulnerability analyzer using LLM APIs."""

    def __init__(self, model: str = "ollama:llama3", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self._client = None

    async def analyze(
        self,
        files: List[Path],
        candidates: List[Vulnerability],
    ) -> List[Vulnerability]:
        """Use AI to analyze files and confirm/enrich candidates."""
        results = []

        if self.model.startswith("ollama:"):
            results = await self._analyze_ollama(files, candidates)
        elif self.model.startswith("gpt") or "openai" in self.model.lower():
            results = await self._analyze_openai(files, candidates)
        elif "claude" in self.model.lower() or "anthropic" in self.model.lower():
            results = await self._analyze_anthropic(files, candidates)

        return results

    async def _analyze_ollama(self, files: List[Path], candidates: List[Vulnerability]) -> List[Vulnerability]:
        try:
            import ollama
            model_name = self.model.split(":", 1)[1] if ":" in self.model else "llama3"

            results = []
            # Analyze each candidate file chunk
            for vuln in candidates[:10]:  # Limit to top 10 to avoid timeout
                try:
                    code = self._get_code_context(vuln)
                    prompt = f"Analyze this code for security vulnerabilities:\n\nFile: {vuln.file_path}\nLine {vuln.line_number}:\n\n```\n{code}\n```"

                    response = ollama.chat(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": AI_SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                    )
                    text = response["message"]["content"]
                    new_vulns = self._parse_ai_response(text, vuln.file_path)
                    results.extend(new_vulns)
                except Exception:
                    continue

            return results
        except ImportError:
            return []

    async def _analyze_openai(self, files: List[Path], candidates: List[Vulnerability]) -> List[Vulnerability]:
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=self.api_key)
            results = []

            for vuln in candidates[:15]:
                try:
                    code = self._get_code_context(vuln)
                    prompt = f"Analyze this code for security vulnerabilities:\n\nFile: {vuln.file_path}\nLine {vuln.line_number}:\n\n```\n{code}\n```"

                    response = await client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": AI_SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.1,
                        max_tokens=2000,
                    )
                    text = response.choices[0].message.content
                    new_vulns = self._parse_ai_response(text, vuln.file_path)
                    results.extend(new_vulns)
                except Exception:
                    continue

            return results
        except ImportError:
            return []

    async def _analyze_anthropic(self, files: List[Path], candidates: List[Vulnerability]) -> List[Vulnerability]:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            results = []

            model_name = "claude-3-5-sonnet-20241022" if "claude" not in self.model else self.model

            for vuln in candidates[:15]:
                try:
                    code = self._get_code_context(vuln)
                    prompt = f"Analyze this code for security vulnerabilities:\n\nFile: {vuln.file_path}\nLine {vuln.line_number}:\n\n```\n{code}\n```"

                    response = client.messages.create(
                        model=model_name,
                        max_tokens=2000,
                        system=AI_SYSTEM_PROMPT,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    text = response.content[0].text
                    new_vulns = self._parse_ai_response(text, vuln.file_path)
                    results.extend(new_vulns)
                except Exception:
                    continue

            return results
        except ImportError:
            return []

    def _get_code_context(self, vuln: Vulnerability, context_lines: int = 30) -> str:
        try:
            lines = vuln.file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(0, vuln.line_number - context_lines)
            end = min(len(lines), vuln.line_number + context_lines)
            return "\n".join(lines[start:end])
        except Exception:
            return ""

    def _parse_ai_response(self, text: str, file_path: Path) -> List[Vulnerability]:
        results = []
        try:
            # Extract JSON from response
            text = text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()

            data = json.loads(text)
            if not isinstance(data, list):
                return []

            import hashlib
            for item in data:
                try:
                    severity_map = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
                    }
                    cat_map = {c.value: c for c in VulnCategory}

                    sev = severity_map.get(item.get("severity", "low").lower(), Severity.LOW)
                    cat = cat_map.get(item.get("category", "other"), VulnCategory.OTHER)
                    line = int(item.get("line_number", 1))

                    vuln = Vulnerability(
                        vuln_id=f"AI-{hashlib.md5(f'{file_path}{line}{item.get(\"vuln_type\", \"\")} '.encode()).hexdigest()[:6]}",
                        vuln_type=item.get("vuln_type", "unknown"),
                        category=cat,
                        severity=sev,
                        file_path=file_path,
                        line_number=line,
                        title=item.get("title", "AI-detected Vulnerability"),
                        description=item.get("description", ""),
                        impact=item.get("impact", ""),
                        recommendation=item.get("recommendation", ""),
                        cwe_id=item.get("cwe_id"),
                        ai_confirmed=True,
                        ai_explanation=item.get("description", ""),
                        confidence=float(item.get("confidence", 0.7)),
                        detector="ai",
                    )
                    results.append(vuln)
                except Exception:
                    continue
        except Exception:
            pass
        return results
