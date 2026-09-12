"""
APKRadar — DPO letter sender.
Generates and sends GDPR DPO letters based on APK audit results.
"""
from __future__ import annotations

import smtplib
import getpass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from apkradar.scanner import ScanResult


def render_letter(
    result: ScanResult,
    publisher: str,
    publisher_domain: str,
    sender_name: str,
    sender_org: str,
    sender_email: str,
    mail_score: Optional[int] = None,
    mail_grade: Optional[str] = None,
    ssl_expired: bool = False,
    ssl_expiry: Optional[str] = None,
    noyb_id: Optional[str] = None,
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
        ssl_expired: Whether SSL certificate is expired
        ssl_expiry: SSL expiry date string (optional)
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
        ssl_expired=ssl_expired,
        ssl_expiry=ssl_expiry,
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
    smtp_password: Optional[str] = None,
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

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        return True
    except Exception as e:
        raise RuntimeError(f"SMTP error: {e}") from e
