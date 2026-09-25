"""Tests for APKRadar sender module."""
import unittest
from unittest.mock import MagicMock, patch

from apkradar.scanner import PermissionFound, ScanResult, TrackerFound, TransferFound
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
        """Letter should include MailRadar score when provided.

        publisher_domain_verified says the sender established that wonet.com is
        WONE SAGL's domain. Section 4 states a finding against the addressee, so
        without that it now declines to — see test_publisher_letter.py.
        """
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            publisher_domain_verified=True,
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            mail_score=20,
            mail_grade="CRITICAL",
        )
        self.assertIn("20/100", letter)
        self.assertIn("CRITICAL", letter)

    def test_render_with_ssl_expired(self):
        """Letter should mention SSL expiry — on a domain known to be theirs."""
        result = _make_result()
        letter = render_letter(
            result=result,
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            publisher_domain_verified=True,
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            ssl_status="expired",
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


class TestRenderLetterMailScore(unittest.TestCase):
    """Section 4 must reflect the actual MailRadar score.

    These are about the threshold, so the domain is stated as established: a
    letter that declines to make any finding would not test where 60 falls.
    Whether the domain may be treated as established is the subject of
    test_publisher_letter.py.
    """

    INADEQUATE = "misure tecniche inadeguate"
    NO_ISSUES = "Non sono state rilevate criticità"

    def _render(self, mail_score, mail_grade):
        return render_letter(
            result=_make_result(),
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            publisher_domain_verified=True,
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            mail_score=mail_score,
            mail_grade=mail_grade,
        )

    def test_good_score_no_accusation(self):
        letter = self._render(100, "A+")
        self.assertNotIn(self.INADEQUATE, letter)
        self.assertIn(self.NO_ISSUES, letter)

    def test_threshold_score_no_accusation(self):
        letter = self._render(60, "C")
        self.assertNotIn(self.INADEQUATE, letter)

    def test_poor_score_accusation(self):
        letter = self._render(59, "D")
        self.assertIn(self.INADEQUATE, letter)
        self.assertIn("59/100", letter)
        self.assertNotIn(self.NO_ISSUES, letter)

    def test_zero_score_is_poor(self):
        """Score 0 is the worst result, not 'no data'."""
        letter = self._render(0, "F")
        self.assertIn(self.INADEQUATE, letter)
        self.assertIn("0/100", letter)
        self.assertNotIn(self.NO_ISSUES, letter)

    def test_absent_score_not_mentioned(self):
        letter = self._render(None, None)
        self.assertNotIn(self.INADEQUATE, letter)
        self.assertNotIn("/100", letter)


class TestCheckSsl(unittest.TestCase):
    """Tests for _check_ssl function."""

    def _check_with_error(self, exc):
        from apkradar.cli import _check_ssl
        with patch("apkradar.cli.socket.create_connection", side_effect=exc):
            return _check_ssl("host.example.com")

    @staticmethod
    def _verify_error(code):
        import ssl
        e = ssl.SSLCertVerificationError(1, "certificate verify failed")
        e.verify_code = code
        e.verify_message = "test"
        return e

    def test_ssl_generic_exception_is_error(self):
        self.assertEqual(self._check_with_error(Exception("boom")), ("error", None))

    def test_ssl_dns_failure_is_error(self):
        import socket
        self.assertEqual(self._check_with_error(socket.gaierror("dns")), ("error", None))

    def test_ssl_timeout(self):
        self.assertEqual(self._check_with_error(TimeoutError("timed out")), ("timeout", None))

    def test_ssl_expired(self):
        self.assertEqual(self._check_with_error(self._verify_error(10)), ("expired", None))

    def test_ssl_hostname_mismatch(self):
        self.assertEqual(self._check_with_error(self._verify_error(62)), ("hostname_mismatch", None))

    def test_ssl_self_signed(self):
        self.assertEqual(self._check_with_error(self._verify_error(18)), ("self_signed", None))
        self.assertEqual(self._check_with_error(self._verify_error(19)), ("self_signed", None))

    def test_ssl_unknown_ca(self):
        self.assertEqual(self._check_with_error(self._verify_error(20)), ("unknown_ca", None))

    def test_ssl_other_verification_failure_is_invalid(self):
        """Unclassified verification errors must not be reported as expired."""
        import ssl
        exc = ssl.SSLCertVerificationError("certificate verify failed")
        self.assertEqual(self._check_with_error(exc), ("invalid", None))

    def test_ssl_valid(self):
        from apkradar.cli import _check_ssl
        ctx = MagicMock()
        ssock = ctx.wrap_socket.return_value.__enter__.return_value
        ssock.getpeercert.return_value = {"notAfter": "Jan  1 00:00:00 2099 GMT"}
        with patch("apkradar.cli.socket.create_connection"), \
             patch("apkradar.cli.ssl.create_default_context", return_value=ctx):
            self.assertEqual(_check_ssl("host.example.com"), ("valid", "01/01/2099"))


class TestRenderLetterSsl(unittest.TestCase):
    """The letter must only claim 'expired' when the certificate is expired.

    Which certificate, though, is the other half: these tests state that the
    domain belongs to the addressee so that the wording of each status can be
    checked. hostname_mismatch is excluded from the claims partly because the
    domain used to be a guess — that reason is now handled upstream, and the
    exclusion stands on its own.
    """

    NO_ISSUES = "Non sono state rilevate criticità"

    def _render(self, ssl_status):
        return render_letter(
            result=_make_result(),
            publisher="WONE SAGL",
            publisher_domain="wonet.com",
            publisher_domain_verified=True,
            sender_name="Test User",
            sender_org="",
            sender_email="test@example.com",
            ssl_status=ssl_status,
        )

    def test_expired(self):
        letter = self._render("expired")
        self.assertIn("scaduto", letter)
        self.assertNotIn(self.NO_ISSUES, letter)

    def test_self_signed(self):
        letter = self._render("self_signed")
        self.assertNotIn("scaduto", letter)
        self.assertIn("autofirmato", letter)
        self.assertNotIn(self.NO_ISSUES, letter)

    def test_unknown_ca(self):
        letter = self._render("unknown_ca")
        self.assertNotIn("scaduto", letter)
        self.assertIn("autorità di certificazione non riconosciuta", letter)
        self.assertNotIn(self.NO_ISSUES, letter)

    def test_not_claimed_as_issue(self):
        """Mismatch, timeout, errors and valid certs are not asserted in the letter."""
        for status in ("hostname_mismatch", "invalid", "timeout", "error", "valid", None):
            with self.subTest(status=status):
                letter = self._render(status)
                self.assertNotIn("scaduto", letter)
                self.assertNotIn("certificato SSL", letter)
                self.assertIn(self.NO_ISSUES, letter)


class TestSendSslOutput(unittest.TestCase):
    """CLI output must match the actual SSL status."""

    def setUp(self):
        from typer.testing import CliRunner
        self.runner = CliRunner()

    def _dry_run(self, ssl_result):
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        scan_result = ScanResult(apk_path="test.apk", package_name="com.wonet.usims", app_name="USIMS")
        with patch("apkradar.scanner.scan", return_value=scan_result), \
             patch("apkradar.cli._check_mailradar", return_value=(None, None)), \
             patch("apkradar.cli._check_ssl", return_value=ssl_result):
            return self.runner.invoke(app, [
                "send", "test.apk",
                "--to", "dpo@example.com",
                "--publisher", "WONE SAGL",
                "--from", "test@example.com",
                "--smtp-host", "mail.example.com",
                "--smtp-user", "test@example.com",
                "--name", "Test User",
                "--dry-run",
            ])

    def test_check_failure_not_shown_as_valid(self):
        result = self._dry_run(("error", None))
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("SSL valid", result.output)
        self.assertIn("check failed", result.output)

    def test_hostname_mismatch_not_expired(self):
        result = self._dry_run(("hostname_mismatch", None))
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("EXPIRED", result.output)
        self.assertNotIn("scaduto", result.output)
        self.assertIn("hostname mismatch", result.output)

    def test_valid_shows_expiry(self):
        result = self._dry_run(("valid", "01/01/2099"))
        self.assertIn("SSL valid until 01/01/2099", result.output)

    def test_full_stack_mismatch_not_expired(self):
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        scan_result = ScanResult(apk_path="test.apk", package_name="com.example.app")
        with patch("apkradar.scanner.scan", return_value=scan_result), \
             patch("apkradar.cli._check_mailradar", return_value=(None, None)), \
             patch("apkradar.cli._check_ssl", return_value=("hostname_mismatch", None)), \
             patch("apkradar.cli.asyncio.run", side_effect=Exception("no browser")):
            result = self.runner.invoke(app, ["audit", "test.apk", "--full"])
        self.assertNotIn("EXPIRED", result.output)
        self.assertIn("hostname mismatch", result.output)


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
            mock_smtp.assert_called_once()
            args, kwargs = mock_smtp.call_args
            self.assertEqual(args, ("mail.example.com", 465))
            self._assert_verifying_context(kwargs.get("context"))

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
            self._assert_verifying_context(mock_server.starttls.call_args.kwargs.get("context"))

    def _assert_verifying_context(self, context):
        """TLS context must verify the server certificate and hostname."""
        import ssl
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_send_letter_raises_on_smtp_error(self):
        """send_letter should raise RuntimeError on SMTP failure."""
        from apkradar.sender import send_letter
        with (
            patch("apkradar.sender.smtplib.SMTP_SSL", side_effect=Exception("Connection refused")),
            self.assertRaises(RuntimeError),
        ):
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


class TestSendCommand(unittest.TestCase):
    """Tests for send CLI command."""

    def setUp(self):
        from typer.testing import CliRunner
        self.runner = CliRunner()

    @patch("apkradar.scanner.scan")
    @patch("apkradar.cli._check_mailradar", return_value=(None, None))
    @patch("apkradar.cli._check_ssl", return_value=("error", None))
    def test_send_dry_run(self, mock_ssl, mock_mail, mock_scan):
        """--dry-run should print letter without sending."""
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        mock_scan.return_value = ScanResult(
            apk_path="test.apk",
            package_name="com.wonet.usims",
            app_name="USIMS",
            version_name="3.88",
            version_code="388",
            sha256="abc123" * 11,
        )
        result = self.runner.invoke(app, [
            "send", "test.apk",
            "--to", "dpo@example.com",
            "--publisher", "WONE SAGL",
            "--from", "test@example.com",
            "--smtp-host", "mail.example.com",
            "--smtp-user", "test@example.com",
            "--name", "Test User",
            "--dry-run",
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("DPO Letter Preview", result.output)

    @patch("apkradar.scanner.scan")
    @patch("apkradar.cli._check_mailradar", return_value=(20, "CRITICAL"))
    @patch("apkradar.cli._check_ssl", return_value=("expired", None))
    def test_send_dry_run_with_noyb_id(self, mock_ssl, mock_mail, mock_scan):
        """--dry-run with --noyb-id should include NOYB in letter."""
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        mock_scan.return_value = ScanResult(
            apk_path="test.apk",
            package_name="com.wonet.usims",
            app_name="USIMS",
            version_name="3.88",
            version_code="388",
            sha256="abc123" * 11,
        )
        result = self.runner.invoke(app, [
            "send", "test.apk",
            "--to", "dpo@example.com",
            "--publisher", "WONE SAGL",
            "--from", "test@example.com",
            "--smtp-host", "mail.example.com",
            "--smtp-user", "test@example.com",
            "--name", "Test User",
            "--noyb-id", "7645",
            "--dry-run",
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("#7645", result.output)

    @patch("apkradar.sender.send_letter")
    @patch("apkradar.scanner.scan")
    @patch("apkradar.cli._check_mailradar", return_value=(None, None))
    @patch("apkradar.cli._check_ssl", return_value=("error", None))
    def test_send_real_send_success(self, mock_ssl, mock_mail, mock_scan, mock_send):
        """send without --dry-run should call send_letter."""
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        mock_scan.return_value = ScanResult(
            apk_path="test.apk",
            package_name="com.wonet.usims",
            app_name="USIMS",
            version_name="3.88",
            version_code="388",
            sha256="abc123" * 11,
        )
        mock_send.return_value = True
        result = self.runner.invoke(app, [
            "send", "test.apk",
            "--to", "dpo@example.com",
            "--publisher", "WONE SAGL",
            "--from", "test@example.com",
            "--smtp-host", "mail.example.com",
            "--smtp-user", "test@example.com",
            "--name", "Test User",
            "--smtp-port", "465",
        ], input="password\n")
        self.assertEqual(result.exit_code, 0)
        mock_send.assert_called_once()

    def _invoke_send_with_failed_scan(self, extra_args):
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        failed = ScanResult(apk_path="missing.apk", error="File not found: missing.apk")
        with patch("apkradar.scanner.scan", return_value=failed), \
             patch("apkradar.cli._check_mailradar") as mock_mail, \
             patch("apkradar.cli._check_ssl") as mock_ssl, \
             patch("apkradar.sender.render_letter") as mock_render, \
             patch("apkradar.sender.send_letter") as mock_send:
            result = self.runner.invoke(app, [
                "send", "missing.apk",
                "--to", "dpo@example.com",
                "--publisher", "WONE SAGL",
                "--from", "test@example.com",
                "--smtp-host", "mail.example.com",
                "--smtp-user", "test@example.com",
                "--name", "Test User",
            ] + extra_args, input="password\n")
        return result, mock_mail, mock_ssl, mock_render, mock_send

    def test_send_failed_scan_does_not_send(self):
        """A failed scan must not produce or send a DPO letter."""
        result, mock_mail, mock_ssl, mock_render, mock_send = self._invoke_send_with_failed_scan([])
        self.assertEqual(result.exit_code, 1)
        mock_render.assert_not_called()
        mock_send.assert_not_called()
        mock_mail.assert_not_called()
        mock_ssl.assert_not_called()
        self.assertIn("letter not sent", result.output.lower())

    def test_send_failed_scan_dry_run_no_letter(self):
        result, _, _, mock_render, mock_send = self._invoke_send_with_failed_scan(["--dry-run"])
        self.assertEqual(result.exit_code, 1)
        mock_render.assert_not_called()
        mock_send.assert_not_called()
        self.assertNotIn("DPO Letter Preview", result.output)

    @patch("apkradar.sender.send_letter", side_effect=RuntimeError("SMTP error"))
    @patch("apkradar.scanner.scan")
    @patch("apkradar.cli._check_mailradar", return_value=(None, None))
    @patch("apkradar.cli._check_ssl", return_value=("error", None))
    def test_send_smtp_error(self, mock_ssl, mock_mail, mock_scan, mock_send):
        """send should exit with error on SMTP failure."""
        from apkradar.cli import app
        from apkradar.scanner import ScanResult
        mock_scan.return_value = ScanResult(
            apk_path="test.apk",
            package_name="com.wonet.usims",
            app_name="USIMS",
            version_name="3.88",
            version_code="388",
            sha256="abc123" * 11,
        )
        result = self.runner.invoke(app, [
            "send", "test.apk",
            "--to", "dpo@example.com",
            "--publisher", "WONE SAGL",
            "--from", "test@example.com",
            "--smtp-host", "mail.example.com",
            "--smtp-user", "test@example.com",
            "--name", "Test User",
        ], input="password\n")
        self.assertNotEqual(result.exit_code, 0)


class TestRenderLetterSignature(unittest.TestCase):
    """ssl_expiry is not used by the letter: the template only reads ssl_status."""

    def test_ssl_expiry_not_a_parameter(self):
        import inspect

        from apkradar.sender import render_letter
        self.assertNotIn("ssl_expiry", inspect.signature(render_letter).parameters)

    def test_template_does_not_reference_ssl_expiry(self):
        from pathlib import Path

        import apkradar
        template = Path(apkradar.__file__).parent / "templates" / "dpo_letter_it.txt"
        self.assertNotIn("ssl_expiry", template.read_text(encoding="utf-8"))
