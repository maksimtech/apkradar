"""Tests for APKRadar sender module."""
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from apkradar.scanner import ScanResult, TrackerFound, PermissionFound, TransferFound
from apkradar.sender import render_letter


def _make_result():
    result = ScanResult(
        apk_path="test.apkm",
        package_name="com.wonet.usims",
        app_name="USIMS",
        version_name="3.88",
        version_code="388",
        min_sdk="26",
        target_sdk="36",
        sha256="abc123" * 11,
        apk_format="apkm",
    )
    result.trackers = [
        TrackerFound(package="com.google.firebase.analytics", name="Firebase Analytics"),
        TrackerFound(package="com.mixpanel.android", name="Mixpanel"),
    ]
    result.sensitive_permissions = [
        PermissionFound(
            permission="android.permission.ACCESS_FINE_LOCATION",
            description="precise GPS location",
        ),
        PermissionFound(
            permission="android.permission.READ_PHONE_STATE",
            description="device ID/IMEI",
        ),
    ]
    result.extra_eu_transfers = [
        TransferFound(package_prefix="com.google", entity="Google LLC (USA)"),
        TransferFound(package_prefix="com.mixpanel", entity="Mixpanel Inc. (USA)"),
    ]
    return result


class TestRenderLetter(unittest.TestCase):
    """Tests for render_letter function."""

    def test_render_basic(self):
        """Letter should contain basic app info."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="Test Org",
            sender_email="test@example.com",
        )
        self.assertIn("USIMS", letter)
        self.assertIn("com.wonet.usims", letter)
        self.assertIn("WONE SAGL", letter)
        self.assertIn("Test User", letter)

    def test_render_includes_trackers(self):
        """Letter should list found trackers."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
        )
        self.assertIn("Firebase Analytics", letter)
        self.assertIn("Mixpanel", letter)

    def test_render_includes_permissions(self):
        """Letter should list sensitive permissions."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
        )
        self.assertIn("GPS", letter)
        self.assertIn("IMEI", letter)

    def test_render_includes_extra_eu(self):
        """Letter should list extra-EU transfers."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
        )
        self.assertIn("Google LLC (USA)", letter)
        self.assertIn("Mixpanel Inc. (USA)", letter)

    def test_render_with_mailradar_score(self):
        """Letter should include MailRadar score when provided."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            mail_score=20,
            mail_grade="CRITICAL",
        )
        self.assertIn("20/100", letter)
        self.assertIn("CRITICAL", letter)

    def test_render_with_ssl_expired(self):
        """Letter should mention SSL expiry."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            ssl_expired=True,
            ssl_expiry="08/04/2026",
        )
        self.assertIn("scaduto", letter.lower())

    def test_render_includes_apkradar_version(self):
        """Letter should include APKRadar version."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
        )
        self.assertIn("APKRadar", letter)
        self.assertIn("github.com/maksimtech/apkradar", letter)

    def test_render_no_noyb_by_default(self):
        """Letter without noyb flag should not mention NOYB."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
        )
        self.assertNotIn("NOYB", letter)

    def test_render_noyb_flag(self):
        """Letter with noyb=True should mention NOYB without ID."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            noyb=True,
        )
        self.assertIn("NOYB", letter)
        self.assertNotIn("#", letter.split("NOYB")[1][:20])

    def test_render_noyb_with_id(self):
        """Letter with noyb_id should include member number dynamically."""
        result = _make_result()
        member_id = "12345"
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            noyb_id=member_id,
        )
        self.assertIn("NOYB", letter)
        self.assertIn(f"#{member_id}", letter)

    def test_render_no_org(self):
        """Letter without org should not show empty line."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
        )
        self.assertIn("Test User", letter)


class TestCheckSsl(unittest.TestCase):
    """Tests for _check_ssl function."""

    def test_ssl_exception_returns_false(self):
        """Exception during SSL check should return (False, None)."""
        from apkradar.cli import _check_ssl
        with patch("apkradar.cli.socket.create_connection", side_effect=Exception("timeout")):
            expired, date = _check_ssl("nonexistent.example.com")
            self.assertFalse(expired)
            self.assertIsNone(date)

    def test_ssl_cert_verification_error(self):
        """SSLCertVerificationError should return (True, None)."""
        import ssl
        from apkradar.cli import _check_ssl
        with patch("apkradar.cli.socket.create_connection", side_effect=ssl.SSLCertVerificationError("expired")):
            expired, date = _check_ssl("expired.example.com")
            self.assertTrue(expired)
            self.assertIsNone(date)


class TestCheckMailradar(unittest.TestCase):
    """Tests for _check_mailradar function."""

    def test_mailradar_exception_returns_none(self):
        """Exception should return (None, None)."""
        from apkradar.cli import _check_mailradar
        with patch("mailradar.checker.analyze_domain", side_effect=Exception("error")):
            score, grade = _check_mailradar("nonexistent.example.com")
            self.assertIsNone(score)
            self.assertIsNone(grade)


if __name__ == "__main__":
    unittest.main()


class TestSendLetter(unittest.TestCase):
    """Tests for send_letter function."""

    def test_send_letter_ssl(self):
        """send_letter should use SMTP_SSL on port 465."""
        from apkradar.sender import send_letter
        with patch("apkradar.sender.smtplib.SMTP_SSL") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            result = send_letter(
                letter="Test letter",
                subject="Test subject",
                to_email="dpo@example.com",
                from_email="test@example.com",
                smtp_host="mail.example.com",
                smtp_port=465,
                smtp_user="test@example.com",
                smtp_password="password",
            )
            self.assertTrue(result)
            mock_smtp.assert_called_once_with("mail.example.com", 465)

    def test_send_letter_starttls(self):
        """send_letter should use STARTTLS on port 587."""
        from apkradar.sender import send_letter
        with patch("apkradar.sender.smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
            result = send_letter(
                letter="Test letter",
                subject="Test subject",
                to_email="dpo@example.com",
                from_email="test@example.com",
                smtp_host="mail.example.com",
                smtp_port=587,
                smtp_user="test@example.com",
                smtp_password="password",
            )
            self.assertTrue(result)
            mock_server.starttls.assert_called_once()

    def test_send_letter_raises_on_smtp_error(self):
        """send_letter should raise RuntimeError on SMTP failure."""
        from apkradar.sender import send_letter
        with patch("apkradar.sender.smtplib.SMTP_SSL", side_effect=Exception("Connection refused")):
            with self.assertRaises(RuntimeError):
                send_letter(
                    letter="Test letter",
                    subject="Test subject",
                    to_email="dpo@example.com",
                    from_email="test@example.com",
                    smtp_host="mail.example.com",
                    smtp_port=465,
                    smtp_user="test@example.com",
                    smtp_password="password",
                )
