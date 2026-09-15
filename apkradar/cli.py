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
    Enforces TLS 1.2 minimum.

    Returns:
        Tuple of (ssl_expired, expiry_date_str)
    """
    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
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


def _full_stack_domain(domain: str, verbose: bool = False) -> None:
    """Run full stack analysis on a single domain."""
    console.print(f"\n[bold cyan]🔗 {domain}[/bold cyan]")

    # MailRadar
    if verbose:
        console.print(f"  [dim]→ Running MailRadar...[/dim]")
    mail_score, mail_grade = _check_mailradar(domain)
    if mail_score is not None:
        grade_color = "green" if mail_score >= 80 else "yellow" if mail_score >= 60 else "red"
        console.print(f"  📡 MailRadar: [{grade_color}]{mail_score}/100 — {mail_grade}[/{grade_color}]")
    else:
        console.print(f"  📡 MailRadar: [dim]unavailable[/dim]")

    # SSL
    if verbose:
        console.print(f"  [dim]→ Checking SSL...[/dim]")
    ssl_expired, ssl_expiry = _check_ssl(domain)
    if ssl_expired:
        console.print(f"  🔒 SSL: [red]EXPIRED{f' on {ssl_expiry}' if ssl_expiry else ''}[/red]")
    elif ssl_expiry:
        console.print(f"  🔒 SSL: [green]valid until {ssl_expiry}[/green]")
    else:
        console.print(f"  🔒 SSL: [dim]check failed[/dim]")

    # CookieRadar
    if verbose:
        console.print(f"  [dim]→ Running CookieRadar...[/dim]")
    try:
        from cookieradar.scanner import scan as cookie_scan
        url = f"https://{domain}"
        cookie_result = asyncio.run(cookie_scan(url))
        pre = set(t.domain for t in cookie_result.pre_consent.trackers)
        rej = set(t.domain for t in cookie_result.post_reject.trackers)
        persistent = pre & rej
        if persistent:
            console.print(f"  🍪 CookieRadar: [red]VIOLATION — {len(persistent)} tracker(s) post-rejection[/red]")
            for t in sorted(persistent):
                console.print(f"       → {t}")
        else:
            console.print(f"  🍪 CookieRadar: [green]{len(pre)} pre-consent trackers, none persist[/green]")
    except ImportError:
        console.print(f"  🍪 CookieRadar: [dim]not installed[/dim]")
    except Exception as e:
        console.print(f"  🍪 CookieRadar: [dim]error: {e}[/dim]")


@app.command()
def audit(
    apk: str = typer.Argument(..., help="Path to APK/XAPK/APKM file"),
    output: str = typer.Option(None, "--output", "-o", help="Save report to file"),
    lang: str = typer.Option("it", "--lang", "-l", help="Report language (it/en)"),
    full: bool = typer.Option(False, "--full", "-f", help="Full stack analysis: APK + MailRadar + CookieRadar on all SDK domains"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug output during full stack analysis"),
):
    """
    Audit an APK for GDPR compliance.
    Supports .apk, .xapk (APKPure) and .apkm (APKMirror) formats.
    Use --full for complete stack analysis on publisher and all SDK domains.
    Use --verbose to see what is happening during analysis.
    """
    from apkradar.scanner import scan
    from apkradar.utils import get_all_domains

    console.print(f"\n[dim]Auditing [bold]{apk}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)

    if full and result.package_name:
        domains = get_all_domains(result)

        if domains:
            console.print(f"\n[bold]🔗 Full stack analysis — {len(domains)} domains[/bold]")
            console.print(f"[dim]Publisher + SDK domains detected[/dim]\n")

            for domain in sorted(domains):
                _full_stack_domain(domain, verbose=verbose)

        console.print()


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
def search(
    query: str = typer.Argument(..., help="Package name (e.g. com.moonactive.coinmaster) or app name"),
    audit_app: bool = typer.Option(False, "--audit", "-a", help="Audit the app after lookup"),
):
    """
    Lookup app info by package name on Google Play Store.
    If the app is not found, searches for removal reason.

    Examples:
        apkradar search com.moonactive.coinmaster
        apkradar search "Coin Master"
    """
    from apkradar.search_cmd import lookup

    if "." in query and " " not in query:
        # Package name lookup
        console.print(f"\n[dim]Looking up [bold]{query}[/bold]...[/dim]")

        with console.status("[cyan]Querying Google Play Store...[/cyan]"):
            result = lookup(query)

        if result.available:
            console.print(f"\n[bold]📱 {result.title}[/bold]")
            console.print(f"[dim]Package:   {result.package_name}[/dim]")
            console.print(f"[dim]Developer: {result.developer}[/dim]")
            console.print(f"[dim]Category:  {result.category}[/dim]")
            console.print(f"[dim]Installs:  {result.installs}[/dim]")
            console.print(f"[dim]Rating:    {result.score:.1f}/5.0[/dim]")
            if result.description:
                console.print(f"\n[dim]{result.description}...[/dim]")
            console.print()
        else:
            console.print(f"\n[red]⚠️  App not found on Google Play[/red]")
            console.print(f"[dim]Package: {query}[/dim]")
            if result.removal_reason:
                console.print(f"\n[yellow]Possible reason:[/yellow]")
                console.print(f"[dim]{result.removal_reason}[/dim]")
            else:
                console.print(f"[dim]No removal reason found — app may have been removed or never published.[/dim]")
    else:
        # Name search — guide user
        query_url = query.replace(" ", "+")
        console.print(f"\n[yellow]⚠️  Searching by name is not yet supported.[/yellow]")
        console.print(f"\n[dim]To find the package name:[/dim]")
        console.print(f"  1. Open: [link]https://play.google.com/store/search?q={query_url}[/link]")
        console.print(f"  2. Open the app page")
        console.print(f"  3. Copy the 'id=' parameter from the URL")
        console.print(f"  4. Run: [bold]apkradar search <package_name>[/bold]")
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
    noyb: bool = typer.Option(False, "--noyb", help="Include NOYB reference in escalation"),
    noyb_id: str = typer.Option(None, "--noyb-id", help="NOYB supporter ID (e.g. 7645)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print letter without sending"),
):
    """
    Audit an APK and send a GDPR DPO letter to the publisher.
    Includes MailRadar score and SSL certificate status.

    Examples:
        apkradar send app.apk --to dpo@example.com --publisher "Example Inc" ...
        apkradar send app.apk --to dpo@example.com --noyb ...
        apkradar send app.apk --to dpo@example.com --noyb-id 7645 ...
    """
    from apkradar.scanner import scan
    from apkradar.sender import render_letter, send_letter
    from apkradar.utils import package_to_domain

    console.print(f"\n[dim]Auditing [bold]{apk}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)

    domain = package_to_domain(result.package_name) or ""

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

    if noyb_id:
        noyb = True

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
        noyb_id=noyb_id,
        noyb=noyb,
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
