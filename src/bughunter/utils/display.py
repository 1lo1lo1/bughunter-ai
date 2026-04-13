"""
BugHunter AI — Display Utilities
Beautiful terminal output with Rich
"""
from __future__ import annotations

from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

BANNER = r"""[bold cyan]
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold cyan]"""

SEV_COLORS = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "bold green",
    "low": "bold blue",
    "info": "dim",
}

SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def print_banner():
    console.print(BANNER)
    console.print(
        "  [dim]AI-Powered Security Bug Hunter · Free Penligent Alternative · v1.0.0[/dim]\n"
    )


def print_results_table(vulns, min_severity: str = "low"):
    if not vulns:
        console.print("\n[bold green]✅ No vulnerabilities found![/bold green]\n")
        return

    table = Table(
        title=f"\n🐛 Found {len(vulns)} Vulnerabilities",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("ID", style="dim", width=18)
    table.add_column("Severity", width=12)
    table.add_column("Title", width=35)
    table.add_column("File", width=30)
    table.add_column("Line", width=6, justify="right")
    table.add_column("CWE", width=10)
    table.add_column("AI", width=4, justify="center")

    for v in vulns:
        sev_color = SEV_COLORS.get(v.severity.value, "white")
        emoji = SEV_EMOJI.get(v.severity.value, "⚪")

        table.add_row(
            v.vuln_id[:18],
            f"[{sev_color}]{emoji} {v.severity.value.upper()}[/{sev_color}]",
            v.title[:35],
            v.short_path[-30:],
            str(v.line_number),
            v.cwe_id or "-",
            "🤖" if v.ai_confirmed else "",
        )

    console.print(table)

    # Print details for critical/high
    critical_high = [v for v in vulns if v.severity.value in ("critical", "high")]
    if critical_high:
        console.print("\n[bold red]⚠ Critical / High Details:[/bold red]")
        for v in critical_high[:5]:  # Show top 5
            emoji = SEV_EMOJI.get(v.severity.value, "⚪")
            console.print(f"\n  {emoji} [bold]{v.title}[/bold]")
            console.print(f"     📁 {v.file_path}:{v.line_number}")
            if v.description:
                console.print(f"     💬 {v.description[:120]}...")
            if v.recommendation:
                console.print(f"     💡 [green]{v.recommendation[:120]}[/green]")
            if v.cwe_id:
                console.print(f"     🔗 {v.cwe_id} · {v.owasp_category or ''}")


def print_summary(vulns):
    sev_count = {}
    for v in vulns:
        sev_count[v.severity.value] = sev_count.get(v.severity.value, 0) + 1

    lines = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_count.get(sev, 0)
        if count:
            emoji = SEV_EMOJI[sev]
            color = SEV_COLORS[sev]
            lines.append(f"  {emoji} [{color}]{sev.capitalize():10}[/{color}] {count}")

    ai_count = sum(1 for v in vulns if v.ai_confirmed)
    if ai_count:
        lines.append(f"\n  🤖 [cyan]{ai_count} AI-confirmed[/cyan]")

    panel_text = "\n".join(lines) if lines else "  ✅ No issues found"
    console.print(Panel(panel_text, title="[bold]Scan Summary[/bold]", border_style="cyan"))
