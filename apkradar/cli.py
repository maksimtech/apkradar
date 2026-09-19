"""
APKRadar — APK compliance auditor.
GDPR art.9 — tracker detection, permissions analysis.
Requires: mailradar + cookieradar
"""
import asyncio
import ssl
import socket
from datetime import datetime, timezone
from pathlib import Path
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich import box
from apkradar import __version__

app = typer.Typer(
    name="apkradar",
    help="📱 APK compliance auditor — GDPR art.9",
    add_completion=False,
)

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"APKRadar {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """📱 APK compliance auditor — GDPR art.9"""


def _print_result(result) -> None:
    """Print scan result to console."""
    score_color = {
        "GOOD": "green",
        "MODERATE": "yellow",
        "POOR": "orange3",
        "CRITICAL": "red",
    }.get(result.score_label, "white")

    console.print(f"\n[bold]📱 APKRadar Report — {escape(result.package_name or result.apk_path)}[/bold]")
    console.print(f"[{score_color}]Score: {result.score}/100 — {result.score_label}[/{score_color}]\n")

    if result.error:
        console.print(f"[red]❌ Error: {escape(result.error)}[/red]")
        return

    console.print(f"[dim]App:     {escape(result.app_name)}[/dim]")
    console.print(f"[dim]Version: {escape(result.version_name)} ({escape(result.version_code)})[/dim]")
    console.print(f"[dim]SDK:     min={escape(result.min_sdk)} target={escape(result.target_sdk)}[/dim]")
    console.print(f"[dim]Format:  {escape(result.apk_format.upper())}[/dim]")
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


# OpenSSL X509_V_ERR_* codes → SSL status
_SSL_VERIFY_STATUS = {
    10: "expired",            # CERT_HAS_EXPIRED
    62: "hostname_mismatch",  # HOSTNAME_MISMATCH
    18: "self_signed",        # DEPTH_ZERO_SELF_SIGNED_CERT
    19: "self_signed",        # SELF_SIGNED_CERT_IN_CHAIN
    2: "unknown_ca",          # UNABLE_TO_GET_ISSUER_CERT
    20: "unknown_ca",         # UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    21: "unknown_ca",         # UNABLE_TO_VERIFY_LEAF_SIGNATURE
}

_SSL_STATUS_TEXT = {
    "expired": "[red]EXPIRED[/red]",
    "hostname_mismatch": "[yellow]hostname mismatch[/yellow]",
    "self_signed": "[red]self-signed certificate[/red]",
    "unknown_ca": "[red]unknown certificate authority[/red]",
    "invalid": "[yellow]certificate verification failed[/yellow]",
    "timeout": "[dim]timeout[/dim]",
    "error": "[dim]check failed[/dim]",
}


def _check_ssl(domain: str) -> tuple[str, str | None]:
    """
    Check SSL certificate validity.
    Enforces TLS 1.2 minimum.

    Returns:
        Tuple of (status, expiry_date_str). Status is one of:
        valid, expired, hostname_mismatch, self_signed, unknown_ca,
        invalid, timeout, error. Expiry date is only set when valid.
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
                return "valid", expire_date.strftime("%d/%m/%Y")
    except ssl.SSLCertVerificationError as e:
        return _SSL_VERIFY_STATUS.get(getattr(e, "verify_code", None), "invalid"), None
    except TimeoutError:
        return "timeout", None
    except Exception:
        return "error", None


def _ssl_status_text(status: str, expiry: str | None) -> str:
    """Rich-formatted description of an SSL status."""
    if status == "valid":
        return f"[green]valid{f' until {expiry}' if expiry else ''}[/green]"
    return _SSL_STATUS_TEXT.get(status, "[dim]check failed[/dim]")


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


def _full_stack_domain(domain: str, verbose: bool = False) -> bool:
    """
    Run full stack analysis on a single domain.

    Returns:
        True if CookieRadar found trackers that persist after rejection.
    """
    console.print(f"\n[bold cyan]🔗 {escape(domain)}[/bold cyan]")

    # MailRadar
    if verbose:
        console.print(f"  [dim]→ Running MailRadar...[/dim]")
    mail_score, mail_grade = _check_mailradar(domain)
    if mail_score is not None:
        grade_color = "green" if mail_score >= 80 else "yellow" if mail_score >= 60 else "red"
        console.print(f"  📡 MailRadar: [{grade_color}]{mail_score}/100 — {escape(str(mail_grade))}[/{grade_color}]")
    else:
        console.print(f"  📡 MailRadar: [dim]unavailable[/dim]")

    # SSL
    if verbose:
        console.print(f"  [dim]→ Checking SSL...[/dim]")
    ssl_status, ssl_expiry = _check_ssl(domain)
    console.print(f"  🔒 SSL: {_ssl_status_text(ssl_status, ssl_expiry)}")

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
                console.print(f"       → {escape(t)}")
            return True
        console.print(f"  🍪 CookieRadar: [green]{len(pre)} pre-consent trackers, none persist[/green]")
    except ImportError:
        console.print(f"  🍪 CookieRadar: [dim]not installed[/dim]")
    except Exception as e:
        console.print(f"  🍪 CookieRadar: [dim]error: {escape(str(e))}[/dim]")
    return False


_FINDING_TITLES = {
    "tracker": "Tracker e SDK di terze parti",
    "extra_eu": "Trasferimenti extra-UE",
    "consent": "Consenso",
    "sensitive": "Permessi sensibili",
}


def _print_law_check(result, consent_violation: bool = False) -> None:
    """Cite the GDPR provisions applied to the findings, with their SHA-256."""
    from apkradar import law_checker
    from apkradar.law_fetcher import CELEX

    try:
        law = law_checker.check(result, consent_violation=consent_violation)
    except Exception as e:
        console.print(f"[yellow]⚠️  Verifica delle norme non riuscita: {escape(str(e))}[/yellow]\n")
        return
    if not law.citations:
        return

    console.print("[bold]⚖️  Norme applicate[/bold]")
    if law.source == "eur-lex":
        console.print(f"[dim]Testo verificato su EUR-Lex (CELEX {CELEX})[/dim]")
    elif law.source == "cache":
        console.print("[yellow]EUR-Lex non raggiungibile: testo dalla copia in cache, non riverificato[/yellow]")
    else:
        console.print("[yellow]EUR-Lex non raggiungibile e nessuna copia in cache: testo non verificabile[/yellow]")
    if law.error:
        console.print(f"[dim]{escape(law.error)}[/dim]")
    for ref, previous in law.changed.items():
        console.print(f"[yellow]⚠️  Il testo di art. {escape(ref)} è cambiato dall'ultimo audit[/yellow]")
        console.print(f"[dim]   precedente: {previous}[/dim]")

    console.print()
    finding = None
    for citation in law.citations:
        if citation.finding != finding:
            finding = citation.finding
            console.print(f"[bold]{_FINDING_TITLES[finding]}[/bold]")
        console.print(law_checker.format_citation(citation), markup=False, highlight=False)
        console.print()


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

    console.print(f"\n[dim]Auditing [bold]{escape(apk)}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)

    if result.error:
        raise typer.Exit(1)

    consent_violation = False
    if full and result.package_name:
        domains = get_all_domains(result)

        if domains:
            console.print(f"\n[bold]🔗 Full stack analysis — {len(domains)} domains[/bold]")
            console.print(f"[dim]Publisher + SDK domains detected[/dim]\n")

            for domain in sorted(domains):
                if _full_stack_domain(domain, verbose=verbose):
                    consent_violation = True

        console.print()

    _print_law_check(result, consent_violation=consent_violation)


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
        console.print(f"[red]❌ File not found: {escape(file)}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[dim]Loaded {len(paths)} APKs from {escape(file)}[/dim]\n")

    failed = 0
    for path in paths:
        console.print(f"[cyan]Auditing {escape(path)}...[/cyan]")
        result = scan(path)
        status = "🔴 CRITICAL" if result.score_label == "CRITICAL" else \
                 "🟠 POOR" if result.score_label == "POOR" else \
                 "🟡 MODERATE" if result.score_label == "MODERATE" else "🟢 GOOD"
        console.print(f"  {status} — {result.score}/100 — {result.tracker_count} trackers, {result.sensitive_permission_count} sensitive permissions")
        if result.error:
            failed += 1
            console.print(f"  [red]❌ {escape(result.error)}[/red]")
        console.print()

    if failed:
        console.print(f"[red]❌ {failed}/{len(paths)} scans failed[/red]")
        raise typer.Exit(1)


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
        console.print(f"\n[dim]Looking up [bold]{escape(query)}[/bold]...[/dim]")

        with console.status("[cyan]Querying Google Play Store...[/cyan]"):
            result = lookup(query)

        if result.available:
            console.print(f"\n[bold]📱 {escape(str(result.title))}[/bold]")
            console.print(f"[dim]Package:   {escape(result.package_name)}[/dim]")
            console.print(f"[dim]Developer: {escape(str(result.developer))}[/dim]")
            console.print(f"[dim]Category:  {escape(str(result.category))}[/dim]")
            console.print(f"[dim]Installs:  {escape(str(result.installs))}[/dim]")
            console.print(f"[dim]Rating:    {result.score:.1f}/5.0[/dim]")
            if result.description:
                console.print(f"\n[dim]{escape(result.description)}...[/dim]")
            console.print()
        else:
            console.print(f"\n[red]⚠️  App not found on Google Play[/red]")
            console.print(f"[dim]Package: {escape(query)}[/dim]")
            if result.removal_reason:
                console.print(f"\n[yellow]Possible reason:[/yellow]")
                console.print(f"[dim]{escape(result.removal_reason)}[/dim]")
            else:
                console.print(f"[dim]No removal reason found — app may have been removed or never published.[/dim]")
    else:
        # Name search — guide user
        query_url = query.replace(" ", "+")
        console.print(f"\n[yellow]⚠️  Searching by name is not yet supported.[/yellow]")
        console.print(f"\n[dim]To find the package name:[/dim]")
        console.print(f"  1. Open: [link]https://play.google.com/store/search?q={escape(query_url)}[/link]")
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

    console.print(f"\n[dim]Auditing [bold]{escape(apk)}[/bold]...[/dim]")

    with console.status("[cyan]Analyzing APK...[/cyan]"):
        result = scan(apk)

    _print_result(result)

    if result.error:
        console.print(
            "[red]❌ Scan failed — DPO letter not sent. "
            "A letter can only be based on a successful audit.[/red]"
        )
        raise typer.Exit(1)

    domain = package_to_domain(result.package_name) or ""

    mail_score = None
    mail_grade = None
    ssl_status = None
    ssl_expiry = None

    if domain:
        console.print(f"[dim]Running MailRadar on {escape(domain)}...[/dim]")
        mail_score, mail_grade = _check_mailradar(domain)
        if mail_score is not None:
            console.print(f"📡 MailRadar — {escape(domain)}: {mail_score}/100 — {escape(str(mail_grade))}")

        console.print(f"[dim]Checking SSL on {escape(domain)}...[/dim]")
        ssl_status, ssl_expiry = _check_ssl(domain)
        console.print(f"🔒 SSL {_ssl_status_text(ssl_status, ssl_expiry)}")

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
        ssl_status=ssl_status,
        noyb_id=noyb_id,
        noyb=noyb,
        lang=lang,
    )

    if dry_run:
        console.print("\n[bold]--- DPO Letter Preview ---[/bold]\n")
        console.print(letter, markup=False, emoji=False, highlight=False)
        return

    console.print(f"\n[dim]Sending DPO letter to [bold]{escape(to)}[/bold]...[/dim]")
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
        console.print(f"[green]✅ Letter sent to {escape(to)}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error: {escape(str(e))}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()


@app.command(name="batch-excel")
def batch_excel(
    file: str = typer.Argument(..., help="Excel file with APK paths or package names (.xlsx)"),
    output: str = typer.Option(None, "--output", "-o", help="Output Excel file path"),
    augment: bool = typer.Option(False, "--augment", "-a", help="Add results columns to input file"),
):
    """
    Audit APKs from an Excel file and write results back to Excel.

    The Excel file must have columns:
    - 'Package Name' or 'APK Path' (required)
    - 'App Name' (optional)

    Examples:
        apkradar batch-excel registro.xlsx
        apkradar batch-excel registro.xlsx --output report.xlsx
        apkradar batch-excel registro.xlsx --augment
    """
    from apkradar.excel import read_apk_list, write_results
    from apkradar.scanner import scan

    console.print(f"\n[dim]Reading [bold]{escape(file)}[/bold]...[/dim]")

    try:
        rows = read_apk_list(file)
    except Exception as e:
        console.print(f"[red]❌ Error reading Excel: {escape(str(e))}[/red]")
        raise typer.Exit(1)

    if not rows:
        console.print("[yellow]⚠️  No APKs found in Excel file[/yellow]")
        raise typer.Exit(0)

    console.print(f"[dim]Found {len(rows)} apps to audit[/dim]\n")

    results = []
    for row in rows:
        path = row.apk_path or row.package_name
        console.print(f"[cyan]Auditing {escape(row.app_name or path)}...[/cyan]")

        if row.apk_path:
            result = scan(row.apk_path)
        else:
            # No APK path — create minimal result
            from apkradar.scanner import ScanResult
            result = ScanResult(
                apk_path=row.package_name,
                package_name=row.package_name,
                app_name=row.app_name,
                skipped=True,
            )

        if result.skipped:
            console.print("  [dim]⏭️  SKIPPED — no APK path[/dim]")
        else:
            status = "🔴 CRITICAL" if result.score_label == "CRITICAL" else \
                     "🟠 POOR" if result.score_label == "POOR" else \
                     "🟡 MODERATE" if result.score_label == "MODERATE" else "🟢 GOOD"
            console.print(f"  {status} — {result.score}/100 — {result.tracker_count} trackers")
        if result.error:
            console.print(f"  [red]❌ {escape(result.error)}[/red]")

        results.append(result)

    # Write output
    in_path = Path(file)
    out_path = output or str(in_path.with_name(f"{in_path.stem}_report.xlsx"))
    if augment:
        out_path = output or file

    console.print(f"\n[dim]Writing results to [bold]{escape(out_path)}[/bold]...[/dim]")

    try:
        write_results(
            results=results,
            output_path=out_path,
            input_path=file if augment else None,
        )
        console.print(f"[green]✅ Report saved to {escape(out_path)}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error writing Excel: {escape(str(e))}[/red]")
        raise typer.Exit(1)

    skipped = sum(1 for r in results if r.skipped)
    if skipped:
        console.print(f"[dim]⏭️  {skipped}/{len(results)} skipped — no APK path[/dim]")

    failed = sum(1 for r in results if r.error)
    if failed:
        console.print(f"[red]❌ {failed}/{len(results)} apps could not be audited[/red]")
        raise typer.Exit(1)
