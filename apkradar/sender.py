"""
APKRadar — DPO letter sender.
Generates and sends GDPR DPO letters based on APK audit results.
"""
from __future__ import annotations

import getpass
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from apkradar.scanner import ScanResult

# MailRadar scores below this are reported as inadequate technical measures
MAIL_SCORE_POOR_THRESHOLD = 60

# SSL statuses stated as issues in the letter. hostname_mismatch is excluded:
# the publisher domain is inferred from the package name and may be wrong.
SSL_LETTER_ISSUES = {"expired", "self_signed", "unknown_ca"}


def render_letter(
    result: ScanResult,
    publisher: str,
    publisher_domain: str,
    sender_name: str,
    sender_org: str,
    sender_email: str,
    mail_score: int | None = None,
    mail_grade: str | None = None,
    ssl_status: str | None = None,
    publisher_domain_verified: bool = False,
    noyb_id: str | None = None,
    noyb: bool = False,
    lang: str = "it",
) -> str:
    """
    Render DPO letter from scan result.

    Args:
        result: APKRadar scan result
        publisher: Publisher name
        publisher_domain: Publisher domain
        sender_name: Sender full name
        sender_org: Sender organization
        sender_email: Sender email
        mail_score: MailRadar score (optional)
        mail_grade: MailRadar grade (optional)
        ssl_status: SSL check status (valid, expired, self_signed, unknown_ca,
            hostname_mismatch, invalid, timeout, error). Only expired,
            self_signed and unknown_ca are reported as issues in the letter.
        publisher_domain_verified: Whether publisher_domain is established rather
            than guessed — the sender stated it, or the package name and the Play
            listing agree. Section 4 makes no art. 32 allegation without it, and
            it defaults to False so that omitting it cannot produce one.
            An unverified domain is not named in the letter at all: naming a
            third party's domain, even as unverified, is not this letter's place.
        noyb_id: NOYB supporter ID e.g. '7645' (optional)
        noyb: Include NOYB reference without membership ID
        lang: Language (it/en)

    Returns:
        Rendered letter as string
    """
    from jinja2 import Template

    template_path = Path(__file__).parent / "templates" / f"dpo_letter_{lang}.txt"
    if not template_path.exists():
        template_path = Path(__file__).parent / "templates" / "dpo_letter_it.txt"

    template = Template(template_path.read_text(encoding="utf-8"))

    import apkradar
    return template.render(
        app_name=result.app_name or result.package_name,
        package_name=result.package_name,
        version=result.version_name,
        sha256=result.sha256,
        trackers=result.trackers,
        sensitive_permissions=result.sensitive_permissions,
        extra_eu_transfers=result.extra_eu_transfers,
        publisher=publisher,
        publisher_domain=publisher_domain,
        sender_name=sender_name,
        sender_org=sender_org,
        sender_email=sender_email,
        mail_score=mail_score,
        mail_grade=mail_grade,
        mail_poor=mail_score is not None and mail_score < MAIL_SCORE_POOR_THRESHOLD,
        ssl_status=ssl_status,
        ssl_issue=ssl_status in SSL_LETTER_ISSUES,
        publisher_domain_verified=publisher_domain_verified,
        noyb_id=noyb_id,
        noyb=noyb,
        date=datetime.now().strftime("%d/%m/%Y"),
        apkradar_version=apkradar.__version__,
    )


def send_letter(
    letter: str,
    subject: str,
    to_email: str,
    from_email: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str | None = None,
) -> bool:
    """
    Send DPO letter via SMTP.

    Returns:
        True if sent successfully
    """
    if not smtp_password:
        smtp_password = getpass.getpass(f"Password for {smtp_user}: ")

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(letter, "plain", "utf-8"))

    # Verify server certificate and hostname before sending credentials
    context = ssl.create_default_context()

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls(context=context)
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        return True
    except Exception as e:
        raise RuntimeError(f"SMTP error: {e}") from e
