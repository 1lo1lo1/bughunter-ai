"""
BugHunter AI - CLI Entry Point
The AI-Powered Security Bug Hunter
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from bughunter.core import Scanner, ScanConfig
from bughunter.reporters import ReportGenerator, ReportFormat
from bughunter.utils.display import print_banner, print_results_table, print_summary
from bughunter.utils.config_manager import ConfigManager

app = typer.Typer(
    name="bughunter",
    help="🐛 BugHunter AI — AI-Powered Security Bug Hunter (Free Penligent Alternative)",
    add_completion=True,
    rich_markup_mode="rich",
)
console = Console()


def version_callback(value: bool):
    if value:
        rprint("[bold cyan]BugHunter AI[/bold cyan] [green]v1.0.0[/green]")
        rprint("Free & Open Source — https://github.com/YOUR_USERNAME/bughunter-ai")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit."
    )
):
    """🐛 BugHunter AI — Find security bugs with the power of AI."""
    pass


@app.command("scan")
def scan_command(
    target: str = typer.Argument(..., help="File or directory to scan"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep analysis mode (slower but more thorough)"),
    ai: bool = typer.Option(False, "--ai", "-a", help="Enable AI-powered analysis"),
    model: str = typer.Option("ollama:llama3", "--model", "-m", help="AI model to use (e.g. gpt-4o, ollama:llama3, claude-3-5-sonnet)"),
    checks: Optional[str] = typer.Option(None, "--checks", "-c", help="Comma-separated list of checks (cors,sqli,xss,ssrf,path_traversal,auth,crypto,secrets)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, html, json, sarif, markdown"),
    severity: str = typer.Option("low", "--severity", "-s", help="Minimum severity to report: low, medium, high, critical"),
    cve_lookup: bool = typer.Option(False, "--cve-lookup", help="Look up CVE references for found vulnerabilities"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner and progress output"),
    workers: int = typer.Option(4, "--workers", "-w", help="Number of parallel workers"),
    exclude: Optional[str] = typer.Option(None, "--exclude", "-e", help="Comma-separated patterns to exclude"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="API key for cloud AI (or set via env: OPENAI_API_KEY, ANTHROPIC_API_KEY)"),
):
    """
    🔍 Scan a file or directory for security vulnerabilities.

    Examples:

    \b
    # Basic scan
    bughunter scan ./myapp/

    \b
    # Deep scan with AI
    bughunter scan ./myapp/ --deep --ai --model gpt-4o

    \b
    # Scan with specific checks
    bughunter scan ./myapp/ --checks cors,sqli,xss

    \b
    # Generate HTML report
    bughunter scan ./myapp/ --output report.html --format html

    \b
    # Use free local AI (Ollama)
    bughunter scan ./myapp/ --ai --model ollama:llama3
    """
    if not quiet:
        print_banner()

    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]❌ Target not found:[/red] {target}")
        raise typer.Exit(1)

    # Build check list
    check_list = None
    if checks:
        check_list = [c.strip() for c in checks.split(",")]

    exclude_list = []
    if exclude:
        exclude_list = [e.strip() for e in exclude.split(",")]

    config = ScanConfig(
        target=target_path,
        deep=deep,
        use_ai=ai,
        ai_model=model,
        checks=check_list,
        min_severity=severity,
        cve_lookup=cve_lookup,
        workers=workers,
        exclude_patterns=exclude_list,
        api_key=api_key,
    )

    # Run scan
    try:
        results = asyncio.run(_run_scan(config, quiet))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user[/yellow]")
        raise typer.Exit(0)

    if not results:
        console.print("[green]✅ No vulnerabilities found![/green]")
        raise typer.Exit(0)

    # Display results
    fmt = ReportFormat(format.lower())
    if fmt == ReportFormat.TABLE or not output:
        print_results_table(results, min_severity=severity)

    if output:
        reporter = ReportGenerator()
        report_path = reporter.generate(results, Path(output), fmt, config)
        console.print(f"\n[green]📄 Report saved:[/green] {report_path}")

    print_summary(results)

    # Exit with non-zero if critical/high found
    has_critical = any(r.severity in ("critical", "high") for r in results)
    raise typer.Exit(1 if has_critical else 0)


async def _run_scan(config: ScanConfig, quiet: bool):
    """Run the scan asynchronously."""
    scanner = Scanner(config)
    results = await scanner.scan(verbose=not quiet)
    return results


@app.command("watch")
def watch_command(
    target: str = typer.Argument(..., help="Directory to watch"),
    ai: bool = typer.Option(True, "--ai/--no-ai", help="Enable AI analysis"),
    model: str = typer.Option("ollama:llama3", "--model", "-m", help="AI model"),
):
    """
    👁 Watch a directory for changes and scan in real-time.

    \b
    Example:
    bughunter watch ./src/ --ai
    """
    print_banner()
    console.print(f"[cyan]👁 Watching:[/cyan] {target}")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        from bughunter.utils.watcher import FileWatcher
        watcher = FileWatcher(Path(target), ai_enabled=ai, model=model)
        asyncio.run(watcher.start())
    except ImportError:
        console.print("[red]Install watchdog:[/red] pip install watchdog")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch stopped.[/yellow]")


@app.command("interactive")
def interactive_command():
    """
    🎮 Launch interactive mode — guided vulnerability hunting.

    Best for beginners or when you want a step-by-step walkthrough.
    """
    print_banner()
    from bughunter.utils.interactive import InteractiveMode
    InteractiveMode().run()


@app.command("config")
def config_command(
    show: bool = typer.Option(False, "--show", help="Show current config"),
    reset: bool = typer.Option(False, "--reset", help="Reset to defaults"),
    set_key: Optional[str] = typer.Option(None, "--set", help="Set a config value (key=value)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Set API key"),
    model: Optional[str] = typer.Option(None, "--model", help="Set default AI model"),
):
    """
    ⚙️  Manage BugHunter AI configuration.

    \b
    Examples:
    bughunter config --show
    bughunter config --api-key sk-...
    bughunter config --model gpt-4o
    """
    manager = ConfigManager()

    if show:
        manager.show()
    elif reset:
        manager.reset()
        console.print("[green]✅ Config reset to defaults[/green]")
    elif api_key:
        manager.set("api_key", api_key)
        console.print("[green]✅ API key saved[/green]")
    elif model:
        manager.set("default_model", model)
        console.print(f"[green]✅ Default model set to:[/green] {model}")
    elif set_key:
        k, _, v = set_key.partition("=")
        manager.set(k.strip(), v.strip())
        console.print(f"[green]✅ Set {k} = {v}[/green]")
    else:
        console.print("Use --show to view config, --help for options")


@app.command("list-checks")
def list_checks_command():
    """📋 List all available vulnerability checks."""
    from bughunter.analyzers.registry import CheckRegistry
    registry = CheckRegistry()
    registry.print_all()


@app.command("explain")
def explain_command(
    vuln_id: str = typer.Argument(..., help="Vulnerability ID from a scan result"),
    report: Optional[str] = typer.Option(None, "--report", "-r", help="Report file to load vuln from"),
):
    """
    💡 Get a detailed AI explanation of a vulnerability.

    \b
    Example:
    bughunter explain BH-001
    bughunter explain BH-001 --report report.json
    """
    console.print(f"[cyan]💡 Explaining vulnerability:[/cyan] {vuln_id}")
    # Load from report and explain
    console.print("[dim]Feature: loads vuln from scan report and gives detailed AI explanation[/dim]")


@app.command("update")
def update_command():
    """🔄 Update BugHunter AI to the latest version."""
    console.print("[cyan]🔄 Checking for updates...[/cyan]")
    import subprocess
    result = subprocess.run(
        ["pip", "install", "--upgrade", "bughunter-ai"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        console.print("[green]✅ Updated successfully![/green]")
    else:
        console.print("[yellow]Update via git:[/yellow]")
        console.print("  git pull origin main && pip install -e .")


if __name__ == "__main__":
    app()
