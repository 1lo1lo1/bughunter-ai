"""BugHunter AI — Interactive Mode"""
from __future__ import annotations

import asyncio
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()


class InteractiveMode:
    def run(self):
        console.print("\n[bold cyan]🎮 BugHunter AI Interactive Mode[/bold cyan]")
        console.print("[dim]Guided vulnerability hunting — great for beginners[/dim]\n")

        # Get target
        target = Prompt.ask("📁 Target file or directory", default=".")
        target_path = Path(target)
        if not target_path.exists():
            console.print(f"[red]❌ Not found: {target}[/red]")
            return

        # Select checks
        console.print("\n[bold]Available checks:[/bold]")
        checks_menu = [
            ("cors", "CORS misconfiguration"),
            ("sqli", "SQL Injection"),
            ("xss", "Cross-Site Scripting"),
            ("ssrf", "Server-Side Request Forgery"),
            ("secrets", "Hardcoded secrets & API keys"),
            ("auth", "Authentication flaws"),
            ("crypto", "Cryptography issues"),
        ]
        for i, (k, v) in enumerate(checks_menu, 1):
            console.print(f"  {i}. {k:12} — {v}")

        checks_input = Prompt.ask("\nChecks to run (comma-separated, or 'all')", default="all")
        checks = None if checks_input.lower() == "all" else [c.strip() for c in checks_input.split(",")]

        # AI?
        use_ai = Confirm.ask("\n🤖 Enable AI analysis?", default=False)
        model = "ollama:llama3"
        if use_ai:
            model = Prompt.ask("Model (ollama:llama3 / gpt-4o / claude-3-5-sonnet)", default="ollama:llama3")

        # Output format
        fmt = Prompt.ask("📄 Report format", choices=["table", "html", "json", "markdown"], default="table")
        output = None
        if fmt != "table":
            output = Prompt.ask("Output file", default=f"bughunter-report.{fmt}")

        console.print("\n[cyan]🚀 Starting scan...[/cyan]\n")

        from bughunter.core import Scanner, ScanConfig
        from bughunter.reporters import ReportGenerator, ReportFormat
        from bughunter.utils.display import print_results_table, print_summary

        config = ScanConfig(
            target=target_path,
            use_ai=use_ai,
            ai_model=model,
            checks=checks,
        )

        results = asyncio.run(Scanner(config).scan())

        print_results_table(results)
        if output and fmt != "table":
            ReportGenerator().generate(results, Path(output), ReportFormat(fmt), config)
            console.print(f"\n[green]📄 Report saved:[/green] {output}")
        print_summary(results)
