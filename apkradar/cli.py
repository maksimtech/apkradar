"""
APKRadar — APK compliance auditor.
GDPR art.9 — tracker detection, permissions analysis.
Requires: mailradar + cookieradar
"""
import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(
    name="apkradar",
    help="📱 APK compliance auditor — GDPR art.9",
    add_completion=False,
)

console = Console()


def _print_result(result) -> None:
    """Print scan result to console."""
    score_color = {
        "GOOD": "green",
        "MODERATE": "yellow",
        "POOR": "orange3",
        "CRITICAL": "red",
    }.get(result.score_label, "white")

    # Header
    console.print(f"\n[bold]📱 APKRadar Report — {result.package_name or result.apk_path}[/bold]")
    console.print(f"[{score_color}]Score: {result.score}/100 — {result.score_label}[/{score_color}]\n")

    if result.error:
        console.print(f"[red]❌ Error: {result.error}[/red]")
        return

    # Metadata
    console.print(f"[dim]App:     {result.app_name}[/dim]")
    console.print(f"[dim]Version: {result.version_name} ({result.version_code})[/dim]")
    console.print(f"[dim]SDK:     min={result.min_sdk} target={result.target_sdk}[/dim]")
    console.print(f"[dim]SHA256:  {result.sha256[:16]}...[/dim]\n")

    # Trackers
    if result.trackers:
        t = Table(title=f"🔴 Trackers ({result.tracker_count})", box=box.ROUNDED)
        t.add_column("Tracker", style="red")
        t.add_column("Package", style="dim")
        for tracker in result.trackers:
            t.add_row(tracker.name, tracker.package)
        console.print(t)
    else:
        console.print("[green]✅ No trackers detected[/green]")

    # Sensitive permissions
    if result.sensitive_permissions:
        t = Table(title=f"⚠️  Sensitive Permissions ({result.sensitive_permission_count})", box=box.ROUNDED)
        t.add_column("Permission", style="yellow")
        t.add_column("GDPR Concern", style="dim")
        for perm in result.sensitive_permissions:
            t.add_row(perm.permission.split(".")[-1], perm.description)
        console.print(t)
    else:
        console.print("[green]✅ No sensitive permissions[/green]")

    # Extra-EU transfers
    if result.extra_eu_transfers:
        t = Table(title=f"🌍 Extra-EU Transfers ({len(result.extra_eu_transfers)})", box=box.ROUNDED)
        t.add_column("Entity", style="magenta")
        t.add_column("Package Prefix", style="dim")
        for transfer in result.extra_eu_transfers:
            t.add_row(transfer.entity, transfer.package_prefix)
        console.print(t)
    else:
        console.print("[green]✅ No extra-EU transfers detected[/green]")

    console.print()


@app.command()
def audit(
    apk: str = typer.Argument(..., help="Path to APK file"),
    output: str = typer.Option(None, "--output", "-o", help="Save report to file"),
    lang: str = typer.Option("it", "--lang", "-l", help="Report language (it/en)"),
):
    """
    Audit an APK for GDPR compliance.
    Detects trackers, suspicious permissions, and extra-EU data transfers.
    """
    from apkradar.scanner import scan

    console.print(f"\n[dim]Auditing [bold]{apk}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)


@app.command()
def batch(
    file: str = typer.Argument(..., help="File with APK paths (one per line)"),
    output: str = typer.Option(None, "--output", "-o", help="Save reports to directory"),
):
    """
    Audit multiple APKs from a file.
    """
    from apkradar.scanner import scan

    try:
        with open(file) as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        console.print(f"[red]❌ File not found: {file}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[dim]Loaded {len(paths)} APKs from {file}[/dim]\n")

    for path in paths:
        console.print(f"[cyan]Auditing {path}...[/cyan]")
        result = scan(path)
        status = "🔴 CRITICAL" if result.score_label == "CRITICAL" else \
                 "🟠 POOR" if result.score_label == "POOR" else \
                 "🟡 MODERATE" if result.score_label == "MODERATE" else "🟢 GOOD"
        console.print(f"  {status} — {result.score}/100 — {result.tracker_count} trackers, {result.sensitive_permission_count} sensitive permissions")
        if result.error:
            console.print(f"  [red]❌ {result.error}[/red]")
        console.print()


if __name__ == "__main__":
    app()
