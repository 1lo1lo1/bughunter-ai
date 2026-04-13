"""
BugHunter AI — Core Scanner
Orchestrates all analysis engines
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live

from bughunter.models import Vulnerability, Severity
from bughunter.analyzers.static import StaticAnalyzer
from bughunter.analyzers.secrets import SecretsAnalyzer
from bughunter.analyzers.patterns import PatternAnalyzer
from bughunter.ai.analyzer import AIAnalyzer
from bughunter.utils.file_collector import FileCollector
from bughunter.utils.fp_filter import FalsePositiveFilter

console = Console()

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".php", ".java", ".go", ".rb",
    ".c", ".cpp", ".cc", ".h", ".hpp",
    ".rs", ".swift", ".kt", ".cs",
    ".html", ".htm", ".xml", ".yaml", ".yml",
    ".env", ".config", ".conf", ".ini", ".toml",
    ".sh", ".bash", ".zsh",
}


@dataclass
class ScanConfig:
    target: Path
    deep: bool = False
    use_ai: bool = False
    ai_model: str = "ollama:llama3"
    checks: Optional[List[str]] = None
    min_severity: str = "low"
    cve_lookup: bool = False
    workers: int = 4
    exclude_patterns: List[str] = field(default_factory=list)
    api_key: Optional[str] = None
    max_file_size_kb: int = 500
    timeout_seconds: int = 300


class Scanner:
    """Main scanner — coordinates all analysis engines."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.static_analyzer = StaticAnalyzer(config)
        self.secrets_analyzer = SecretsAnalyzer(config)
        self.pattern_analyzer = PatternAnalyzer(config)
        self.fp_filter = FalsePositiveFilter()

        if config.use_ai:
            self.ai_analyzer = AIAnalyzer(
                model=config.ai_model,
                api_key=config.api_key,
            )
        else:
            self.ai_analyzer = None

    async def scan(self, verbose: bool = True) -> List[Vulnerability]:
        """Run full scan and return vulnerability list."""
        start_time = time.time()

        # Collect files
        collector = FileCollector(
            self.config.target,
            extensions=SUPPORTED_EXTENSIONS,
            exclude_patterns=self.config.exclude_patterns,
            max_size_kb=self.config.max_file_size_kb,
        )
        files = collector.collect()

        if not files:
            console.print("[yellow]⚠ No scannable files found[/yellow]")
            return []

        if verbose:
            console.print(f"[cyan]📁 Files found:[/cyan] {len(files)}")

        all_vulns: List[Vulnerability] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=not verbose,
        ) as progress:

            # Static analysis
            task = progress.add_task("[cyan]Static Analysis...", total=len(files))
            static_results = await self._run_static(files, progress, task)
            all_vulns.extend(static_results)

            # Pattern matching
            task2 = progress.add_task("[cyan]Pattern Matching...", total=len(files))
            pattern_results = await self._run_patterns(files, progress, task2)
            all_vulns.extend(pattern_results)

            # Secrets scanning
            task3 = progress.add_task("[cyan]Secrets Scanning...", total=len(files))
            secrets_results = await self._run_secrets(files, progress, task3)
            all_vulns.extend(secrets_results)

            # AI analysis (if enabled)
            if self.ai_analyzer:
                # Only send high-value findings to AI for confirmation + enrichment
                candidates = [v for v in all_vulns if v.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
                if candidates or self.config.deep:
                    task4 = progress.add_task("[magenta]AI Analysis...", total=len(candidates) or len(files))
                    ai_results = await self._run_ai(files if self.config.deep else [], candidates, progress, task4)
                    all_vulns.extend(ai_results)

        # Deduplicate
        all_vulns = self._deduplicate(all_vulns)

        # False positive filter
        all_vulns = self.fp_filter.filter(all_vulns)

        # Filter by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        min_idx = severity_order.index(self.config.min_severity.lower())
        all_vulns = [v for v in all_vulns if severity_order.index(v.severity.value) <= min_idx]

        # Sort by severity
        all_vulns.sort(key=lambda v: severity_order.index(v.severity.value))

        elapsed = time.time() - start_time
        if verbose:
            console.print(f"[dim]⏱ Scan completed in {elapsed:.1f}s[/dim]")

        return all_vulns

    async def _run_static(self, files, progress, task) -> List[Vulnerability]:
        results = []
        semaphore = asyncio.Semaphore(self.config.workers)

        async def analyze_file(f):
            async with semaphore:
                try:
                    vulns = await self.static_analyzer.analyze(f)
                    results.extend(vulns)
                except Exception:
                    pass
                finally:
                    progress.advance(task)

        await asyncio.gather(*[analyze_file(f) for f in files])
        return results

    async def _run_patterns(self, files, progress, task) -> List[Vulnerability]:
        results = []
        semaphore = asyncio.Semaphore(self.config.workers)

        async def analyze_file(f):
            async with semaphore:
                try:
                    vulns = await self.pattern_analyzer.analyze(f)
                    results.extend(vulns)
                except Exception:
                    pass
                finally:
                    progress.advance(task)

        await asyncio.gather(*[analyze_file(f) for f in files])
        return results

    async def _run_secrets(self, files, progress, task) -> List[Vulnerability]:
        results = []
        for f in files:
            try:
                vulns = await self.secrets_analyzer.analyze(f)
                results.extend(vulns)
            except Exception:
                pass
            progress.advance(task)
        return results

    async def _run_ai(self, files, candidates, progress, task) -> List[Vulnerability]:
        results = []
        try:
            ai_results = await self.ai_analyzer.analyze(files, candidates)
            results.extend(ai_results)
        except Exception as e:
            console.print(f"[yellow]⚠ AI analysis error: {e}[/yellow]")
        progress.advance(task)
        return results

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        seen = set()
        unique = []
        for v in vulns:
            key = (v.file_path, v.line_number, v.vuln_type)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
