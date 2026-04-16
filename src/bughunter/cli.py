import typer
import asyncio
from rich.console import Console
from .scanner import BugHunterCore
from .core.subdomains import SubdomainFinder
from .core.reporter import BugReporter

# შევქმნათ მთავარი ობიექტი
app = typer.Typer(help="BugHunter AI v3.5", no_args_is_help=True)
console = Console()

async def run_scan_logic(domain, limit):
    finder = SubdomainFinder(domain)
    subdomains = finder.find_all()
    
    if not subdomains:
        console.print("[bold red]No subdomains found.[/bold red]")
        return

    scanner = BugHunterCore()
    reporter = BugReporter(domain)
    
    console.print(f"\n[bold green]🚀 Hunting on {domain}...[/bold green]")

    to_scan = subdomains[:limit]
    
    # ფუნქცია თითოეული სკანირებისთვის
    async def scan_one(sub):
        try:
            findings = await scanner.scan_target(f"https://{sub}")
            return sub, findings
        except:
            return sub, []

    tasks = [scan_one(sub) for sub in to_scan]
    results = await asyncio.gather(*tasks)

    for sub, findings in results:
        if findings:
            console.print(f"[bold red]🔥 Found {len(findings)} on {sub}[/bold red]")
            for f in findings:
                reporter.add_finding(sub, f)
        else:
            console.print(f"[dim]Checked: {sub}[/dim]")

    report_file = reporter.generate_html()
    console.print(f"\n[bold blue]✅ Complete! Report: [yellow]{report_file}[/yellow][/bold blue]")

@app.command()
def mass_hunt(domain: str):
    """Scan all subdomains of a target."""
    asyncio.run(run_scan_logic(domain, 50))

@app.command()
def hunt(target: str):
    """Scan a single URL."""
    scanner = BugHunterCore()
    findings = asyncio.run(scanner.scan_target(target))
    console.print(findings)

if __name__ == "__main__":
    app()
