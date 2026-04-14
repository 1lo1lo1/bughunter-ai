"""
__version__ = "2.2.0"
BugHunter AI — Command Line Interface
"""
import sys
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, List
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from bughunter.core import Scanner, ScanConfig

app = typer.Typer(
    name="bughunter",
    help="🐛 BugHunter AI — AI-Powered Security Bug Hunter",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Path to file or directory to scan"),
    checks: str = typer.Option("all", "--checks", "-c", help="Comma-separated checks"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Deep scan mode"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI analysis"),
    model: str = typer.Option("gpt-4o", "--model", "-m", help="AI model"),
    format: str = typer.Option("html", "--format", "-f", help="Output format"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Scan local files for security bugs"""
    console.print(Panel.fit("[bold cyan]🐛 BugHunter AI v2.0[/bold cyan]"))
    
    if not target.exists():
        console.print(f"[red]❌ Target not found: {target}[/red]")
        raise typer.Exit(1)
    
    check_list = None
    if checks and checks != "all":
        check_list = [c.strip() for c in checks.split(",")]
    
    config = ScanConfig(
        target=target,
        deep=deep,
        use_ai=ai,
        ai_model=model,
        checks=check_list,
    )
    
    scanner = Scanner(config)
    results = asyncio.run(scanner.scan())
    
    output_file = output or f"bughunter_report.{format}"
    console.print(f"\n[green]✅ Scan complete: {output_file}[/green]")
    console.print(f"[yellow]Findings: {len(results)}[/yellow]")


@app.command(name="scan-url")
def scan_url(
    url: str = typer.Argument(..., help="URL to scan"),
    checks: str = typer.Option("cors,secrets,xss", "--checks", "-c"),
    depth: int = typer.Option(2, "--depth", "-d", min=1, max=5),
    ai: bool = typer.Option(False, "--ai"),
    model: str = typer.Option("gpt-4o", "--model", "-m"),
    format: str = typer.Option("html", "--format", "-f"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
):
    """🌐 Scan live website"""
    console.print(Panel.fit("[bold green]🐛 BugHunter AI — Live URL Scanner[/bold green]"))
    
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    console.print(f"Target: {url}")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]Downloading...[/cyan]", total=None)
            
            try:
                subprocess.run([
                    "wget", "--mirror", f"--level={depth}",
                    "--accept=html,js,css,json",
                    "--reject=jpg,png,gif,pdf",
                    "--no-parent", "-q", "-P", tmpdir, url
                ], capture_output=True, timeout=300)
            except Exception as e:
                console.print(f"[red]Download failed: {e}[/red]")
                raise typer.Exit(1)
            
            progress.update(task, description="[green]Download complete[/green]")
        
        files = [f for f in Path(tmpdir).rglob("*") if f.is_file()]
        console.print(f"[green]Found {len(files)} files[/green]\n")
        
        if not files:
            console.print("[red]No files downloaded[/red]")
            raise typer.Exit(1)
        
        check_list = [c.strip() for c in checks.split(",")] if checks else None
        
        config = ScanConfig(
            target=Path(tmpdir),
            deep=True,
            use_ai=ai,
            ai_model=model,
            checks=check_list,
        )
        
        scanner = Scanner(config)
        results = asyncio.run(scanner.scan())
        
        output_file = output or f"bughunter_{domain}.{format}"
        console.print(f"\n[green]✅ Scan complete: {output_file}[/green]")
        console.print(f"[yellow]Findings: {len(results)}[/yellow]")


if __name__ == "__main__":
    app()
@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    if version:
        typer.echo(f"BugHunter AI v{__version__}")
        raise typer.Exit()

# Subdomain discovery command
@app.command(name="discover")
def discover_subdomains_cmd(
    target: str = typer.Argument(..., help="Target domain (e.g., snb.ch)"),
    output: str = typer.Option(None, "--output", "-o", help="Output file for results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    🔍 Discover subdomains using OSINT sources (crt.sh, JLDC, RapidDNS)
    
    Example: bughunter discover snb.ch --output subdomains.txt
    """
    console.print(f"[bold blue]🔍 BugHunter AI — Subdomain Discovery[/bold blue]")
    console.print(f"Target: {target}\n")
    
    from bughunter.discover import discover_subdomains
    
    try:
        result = discover_subdomains(target, output)
        
        console.print(f"\n[green]✅ Discovery complete![/green]")
        console.print(f"Total subdomains found: {result['total_found']}")
        
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)
