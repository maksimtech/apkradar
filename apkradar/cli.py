"""
APKRadar — APK compliance auditor.
GDPR art.9 — tracker detection, permissions analysis.
Requires: mailradar + cookieradar
"""
import asyncio
import ssl
import socket
from datetime import datetime, timezone
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

    console.print(f"\n[bold]📱 APKRadar Report — {result.package_name or result.apk_path}[/bold]")
    console.print(f"[{score_color}]Score: {result.score}/100 — {result.score_label}[/{score_color}]\n")

    if result.error:
        console.print(f"[red]❌ Error: {result.error}[/red]")
        return

    console.print(f"[dim]App:     {result.app_name}[/dim]")
    console.print(f"[dim]Version: {result.version_name} ({result.version_code})[/dim]")
    console.print(f"[dim]SDK:     min={result.min_sdk} target={result.target_sdk}[/dim]")
    console.print(f"[dim]Format:  {result.apk_format.upper()}[/dim]")
    console.print(f"[dim]SHA256:  {result.sha256[:16]}...[/dim]\n")

    if result.trackers:
        t = Table(title=f"🔴 Trackers ({result.tracker_count})", box=box.ROUNDED)
        t.add_column("Tracker", style="red")
        t.add_column("Package", style="dim")
        for tracker in result.trackers:
            t.add_row(tracker.name, tracker.package)
        console.print(t)
    else:
        console.print("[green]✅ No trackers detected[/green]")

    if result.sensitive_permissions:
        t = Table(title=f"⚠️  Sensitive Permissions ({result.sensitive_permission_count})", box=box.ROUNDED)
        t.add_column("Permission", style="yellow")
        t.add_column("GDPR Concern", style="dim")
        for perm in result.sensitive_permissions:
            t.add_row(perm.permission.split(".")[-1], perm.description)
        console.print(t)
    else:
        console.print("[green]✅ No sensitive permissions[/green]")

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


def _check_ssl(domain: str) -> tuple[bool, str | None]:
    """
    Check SSL certificate validity.

    Returns:
        Tuple of (ssl_expired, expiry_date_str)
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                expired = expire_date < datetime.now(timezone.utc)
                return expired, expire_date.strftime("%d/%m/%Y")
    except ssl.SSLCertVerificationError:
        return True, None
    except Exception:
        return False, None


def _check_mailradar(domain: str) -> tuple[int | None, str | None]:
    """
    Run MailRadar analysis on domain.

    Returns:
        Tuple of (score, grade)
    """
    try:
        from mailradar.checker import analyze_domain
        mail_result = analyze_domain(domain)
        return mail_result.total_score, mail_result.grade
    except Exception:
        return None, None


@app.command()
def audit(
    apk: str = typer.Argument(..., help="Path to APK/XAPK/APKM file"),
    output: str = typer.Option(None, "--output", "-o", help="Save report to file"),
    lang: str = typer.Option("it", "--lang", "-l", help="Report language (it/en)"),
    full: bool = typer.Option(False, "--full", "-f", help="Full stack analysis: APK + MailRadar + CookieRadar"),
):
    """
    Audit an APK for GDPR compliance.
    Supports .apk, .xapk (APKPure) and .apkm (APKMirror) formats.
    Use --full for complete stack analysis including email and web audit.
    """
    from apkradar.scanner import scan
    from apkradar.utils import package_to_domain, domain_to_url

    console.print(f"\n[dim]Auditing [bold]{apk}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)

    if full and result.package_name:
        domain = package_to_domain(result.package_name)
        if domain:
            console.print(f"\n[bold cyan]🔗 Full stack analysis for publisher: {domain}[/bold cyan]\n")

            # MailRadar
            try:
                from mailradar.checker import analyze_domain
                console.print(f"[dim]Running MailRadar on {domain}...[/dim]")
                mail_result = analyze_domain(domain)
                console.print(f"[bold]📡 MailRadar — {domain}[/bold]")
                console.print(f"Score: {mail_result.total_score}/100 — {mail_result.grade}\n")
            except ImportError:
                console.print("[yellow]⚠️  MailRadar not installed — pip install mailradar[/yellow]")
            except Exception as e:
                console.print(f"[red]❌ MailRadar error: {e}[/red]")

            # SSL check
            ssl_expired, ssl_expiry = _check_ssl(domain)
            if ssl_expired:
                console.print(f"[red]⚠️  SSL certificate EXPIRED{f' on {ssl_expiry}' if ssl_expiry else ''}[/red]")
            else:
                console.print(f"[green]✅ SSL certificate valid{f' until {ssl_expiry}' if ssl_expiry else ''}[/green]")

            # CookieRadar
            try:
                from cookieradar.scanner import scan as cookie_scan
                url = domain_to_url(domain)
                console.print(f"\n[dim]Running CookieRadar on {url}...[/dim]")
                cookie_result = asyncio.run(cookie_scan(url))
                pre = set(t.domain for t in cookie_result.pre_consent.trackers)
                rej = set(t.domain for t in cookie_result.post_reject.trackers)
                persistent = pre & rej
                console.print(f"[bold]🍪 CookieRadar — {url}[/bold]")
                console.print(f"Pre-consent trackers: {len(pre)}")
                if persistent:
                    console.print(f"[red]⚠️  VIOLATION — {len(persistent)} tracker(s) persist after rejection[/red]")
                else:
                    console.print("[green]✅ No trackers persist after rejection[/green]")
                console.print()
            except ImportError:
                console.print("[yellow]⚠️  CookieRadar not installed — pip install cookieradar[/yellow]")
            except Exception as e:
                console.print(f"[red]❌ CookieRadar error: {e}[/red]")


@app.command()
def batch(
    file: str = typer.Argument(..., help="File with APK paths (one per line)"),
    output: str = typer.Option(None, "--output", "-o", help="Save reports to directory"),
    full: bool = typer.Option(False, "--full", "-f", help="Full stack analysis for each APK"),
):
    """
    Audit multiple APKs from a file.
    Supports .apk, .xapk and .apkm formats.
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


@app.command()
def send(
    apk: str = typer.Argument(..., help="Path to APK/XAPK/APKM file"),
    to: str = typer.Option(..., "--to", help="DPO email address"),
    publisher: str = typer.Option(..., "--publisher", help="Publisher name"),
    from_email: str = typer.Option(..., "--from", help="Sender email"),
    smtp_host: str = typer.Option(..., "--smtp-host", help="SMTP host"),
    smtp_port: int = typer.Option(465, "--smtp-port", help="SMTP port"),
    smtp_user: str = typer.Option(..., "--smtp-user", help="SMTP username"),
    name: str = typer.Option(..., "--name", help="Sender full name"),
    org: str = typer.Option("", "--org", help="Sender organization"),
    lang: str = typer.Option("it", "--lang", help="Letter language (it/en)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print letter without sending"),
):
    """
    Audit an APK and send a GDPR DPO letter to the publisher.
    Includes MailRadar score and SSL certificate status.
    """
    from apkradar.scanner import scan
    from apkradar.sender import render_letter, send_letter
    from apkradar.utils import package_to_domain

    console.print(f"\n[dim]Auditing [bold]{apk}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)

    domain = package_to_domain(result.package_name) or ""

    # MailRadar check
    mail_score = None
    mail_grade = None
    ssl_expired = False
    ssl_expiry = None

    if domain:
        console.print(f"[dim]Running MailRadar on {domain}...[/dim]")
        mail_score, mail_grade = _check_mailradar(domain)
        if mail_score is not None:
            console.print(f"📡 MailRadar — {domain}: {mail_score}/100 — {mail_grade}")

        console.print(f"[dim]Checking SSL on {domain}...[/dim]")
        ssl_expired, ssl_expiry = _check_ssl(domain)
        if ssl_expired:
            console.print(f"[red]⚠️  SSL EXPIRED{f' on {ssl_expiry}' if ssl_expiry else ''}[/red]")
        else:
            console.print(f"[green]✅ SSL valid{f' until {ssl_expiry}' if ssl_expiry else ''}[/green]")

    # Render letter
    letter = render_letter(
        result=result,
        publisher=publisher,
        publisher_domain=domain,
        sender_name=name,
        sender_org=org,
        sender_email=from_email,
        mail_score=mail_score,
        mail_grade=mail_grade,
        ssl_expired=ssl_expired,
        ssl_expiry=ssl_expiry,
        lang=lang,
    )

    if dry_run:
        console.print("\n[bold]--- DPO Letter Preview ---[/bold]\n")
        console.print(letter)
        return

    console.print(f"\n[dim]Sending DPO letter to [bold]{to}[/bold]...[/dim]")
    subject = f"Esercizio diritti GDPR — {result.app_name or result.package_name}"

    try:
        send_letter(
            letter=letter,
            subject=subject,
            to_email=to,
            from_email=from_email,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
        )
        console.print(f"[green]✅ Letter sent to {to}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
