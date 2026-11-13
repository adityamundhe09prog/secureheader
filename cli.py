import typer
from rich.console import Console
from rich.table import Table
from rich import box
from .scanner import fetch_headers
from .headers import analyze_headers
from .reporter import build_report, save_json, save_html

app = typer.Typer(help="Analyze HTTP security headers for a website.")
console = Console()

@app.command()
def scan(
    url: str = typer.Argument(..., help="Website URL (http:// or https://)."),
    json_out: str = typer.Option(None, "--json", help="Save a JSON report."),
    html_out: str = typer.Option(None, "--html", help="Save an HTML report."),
    timeout: int = typer.Option(10, min=1, max=60, help="HTTP timeout in seconds."),
):
    """Fetch a website's response headers and report common security headers."""
    try:
        scan_result = fetch_headers(url, timeout=timeout)
        analysis = analyze_headers(scan_result["headers"])
        report = build_report(scan_result, analysis)
    except (ValueError, Exception) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"\n[bold]SecureHeader report[/bold] — {scan_result['final_url']}")
    console.print(f"HTTP status: {scan_result['status_code']}")
    console.print(f"Header presence score: [bold]{analysis['score']}/100[/bold]\n")

    table = Table(box=box.SIMPLE)
    table.add_column("Header")
    table.add_column("Status")
    table.add_column("Severity")
    for item in analysis["checks"]:
        table.add_row(
            item["header"],
            "[green]Present[/green]" if item["present"] else "[red]Missing[/red]",
            item["severity"].upper(),
        )
    console.print(table)

    if json_out:
        save_json(report, json_out)
        console.print(f"[green]JSON report saved:[/green] {json_out}")
    if html_out:
        save_html(report, html_out)
        console.print(f"[green]HTML report saved:[/green] {html_out}")

if __name__ == "__main__":
    app()
