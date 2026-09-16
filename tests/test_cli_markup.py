"""Tests for Rich markup injection in CLI output."""
import io
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from rich.console import Console
from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import ScanResult
from apkradar.search_cmd import AppInfo

SEND_ARGS = [
    "--to", "dpo@example.com",
    "--publisher", "ACME",
    "--from", "test@example.com",
    "--smtp-host", "mail.example.com",
    "--smtp-user", "test@example.com",
    "--name", "Test User",
]


def _result(**kwargs):
    defaults = dict(apk_path="test.apk", package_name="com.example.app", sha256="a" * 64)
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _terminal_console():
    """Console that renders escape sequences (hyperlinks, styles) like a real TTY."""
    return Console(file=io.StringIO(), force_terminal=True, width=200, record=True)


class TestAuditMarkup(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_app_name_closing_tag_no_crash(self):
        with patch("apkradar.scanner.scan", return_value=_result(app_name="Pwn [/bold]")):
            result = self.runner.invoke(app, ["audit", "test.apk"])
        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Pwn [/bold]", result.output)

    def test_filename_shown_verbatim(self):
        """A file named '[red]nope.apk' must be shown in full."""
        result = self.runner.invoke(app, ["audit", "[red]nope.apk"])
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Auditing [red]nope.apk", result.output)
        self.assertIn("File not found: [red]nope.apk", result.output)

    def test_filename_closing_tag_no_crash(self):
        result = self.runner.invoke(app, ["audit", "report[/bold].apk"])
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertIn("report[/bold].apk", result.output)

    def test_link_injection_not_rendered(self):
        payload = "[link=https://evil.example]click me[/link]"
        console = _terminal_console()
        with patch("apkradar.cli.console", console), \
             patch("apkradar.scanner.scan", return_value=_result(app_name=payload)):
            result = self.runner.invoke(app, ["audit", "test.apk"])
        self.assertIsNone(result.exception)
        self.assertNotIn("\x1b]8;", console.file.getvalue())  # OSC 8 hyperlink escape
        self.assertIn(payload, console.export_text())

    def test_metadata_fields_escaped(self):
        scan_result = _result(
            package_name="com.evil[/dim]",
            version_name="1[/dim]",
            version_code="2[/dim]",
            min_sdk="3[/dim]",
            target_sdk="4[/dim]",
            error=None,
        )
        with patch("apkradar.scanner.scan", return_value=scan_result):
            result = self.runner.invoke(app, ["audit", "test.apk"])
        self.assertIsNone(result.exception)
        self.assertIn("com.evil[/dim]", result.output)
        self.assertIn("1[/dim] (2[/dim])", result.output)

    def test_error_message_escaped(self):
        with patch("apkradar.scanner.scan", return_value=_result(error="bad [/red] zip")):
            result = self.runner.invoke(app, ["audit", "test.apk"])
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertEqual(result.exit_code, 1)
        self.assertIn("bad [/red] zip", result.output)


class TestFullStackMarkup(unittest.TestCase):

    def test_domain_and_cookieradar_data_escaped(self):
        from apkradar.cli import _full_stack_domain
        cookie = MagicMock()
        cookie.pre_consent.trackers = [MagicMock(domain="tracker[/red].example")]
        cookie.post_reject.trackers = [MagicMock(domain="tracker[/red].example")]

        def fake_run(coro):
            coro.close()
            return cookie

        console = _terminal_console()
        with patch("apkradar.cli.console", console), \
             patch("apkradar.cli._check_mailradar", return_value=(10, "F[/red]")), \
             patch("apkradar.cli._check_ssl", return_value=("error", None)), \
             patch("apkradar.cli.asyncio.run", side_effect=fake_run):
            _full_stack_domain("evil[/bold].example", verbose=True)
        out = console.export_text()
        self.assertIn("evil[/bold].example", out)
        self.assertIn("tracker[/red].example", out)
        self.assertIn("F[/red]", out)

    def test_cookieradar_exception_escaped(self):
        from apkradar.cli import _full_stack_domain

        def fake_run(coro):
            coro.close()
            raise RuntimeError("boom [/dim] [link=https://evil.example]x[/link]")

        console = _terminal_console()
        with patch("apkradar.cli.console", console), \
             patch("apkradar.cli._check_mailradar", return_value=(None, None)), \
             patch("apkradar.cli._check_ssl", return_value=("error", None)), \
             patch("apkradar.cli.asyncio.run", side_effect=fake_run):
            _full_stack_domain("example.com")
        self.assertNotIn("\x1b]8;", console.file.getvalue())
        self.assertIn("boom [/dim]", console.export_text())


class TestBatchMarkup(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_batch_path_escaped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("[/bold]missing.apk\n")
            tmp = f.name
        try:
            result = self.runner.invoke(app, ["batch", tmp])
        finally:
            os.unlink(tmp)
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Auditing [/bold]missing.apk", result.output)

    def test_batch_list_filename_escaped(self):
        result = self.runner.invoke(app, ["batch", "[/red]list.txt"])
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertIn("File not found: [/red]list.txt", result.output)

    def test_batch_excel_app_name_escaped(self):
        from apkradar.excel import ExcelRow
        rows = [ExcelRow(row_number=2, app_name="Evil [/cyan]", package_name="com.x", apk_path="")]
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            tmp = f.name
        try:
            with patch("apkradar.excel.read_apk_list", return_value=rows), \
                 patch("apkradar.excel.write_results"):
                result = self.runner.invoke(app, ["batch-excel", tmp, "--output", tmp + ".out.xlsx"])
        finally:
            os.unlink(tmp)
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertIn("Auditing Evil [/cyan]", result.output)

    def test_batch_excel_read_error_escaped(self):
        with patch("apkradar.excel.read_apk_list", side_effect=ValueError("bad [/red] sheet")):
            result = self.runner.invoke(app, ["batch-excel", "x.xlsx"])
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertIn("bad [/red] sheet", result.output)


class TestSearchMarkup(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_play_store_fields_escaped(self):
        info = AppInfo(
            package_name="com.evil.app",
            title="Title [/dim]",
            developer="Dev [/dim]",
            score=4.0,
            installs="1+ [/dim]",
            category="Cat [/dim]",
            description="Desc [link=https://evil.example]x[/link] [/dim]",
        )
        with patch("apkradar.search_cmd.lookup", return_value=info):
            result = self.runner.invoke(app, ["search", "com.evil.app"])
        self.assertIsNone(result.exception)
        for text in ("Title [/dim]", "Dev [/dim]", "Cat [/dim]", "1+ [/dim]",
                     "Desc [link=https://evil.example]x[/link] [/dim]"):
            self.assertIn(text, result.output)

    def test_removal_reason_escaped(self):
        info = AppInfo("com.gone.app", "", "", 0.0, "", "", "",
                       available=False, removal_reason="Removed [/yellow]")
        with patch("apkradar.search_cmd.lookup", return_value=info):
            result = self.runner.invoke(app, ["search", "com.gone.app"])
        self.assertIsNone(result.exception)
        self.assertIn("Removed [/yellow]", result.output)

    def test_query_escaped(self):
        info = AppInfo("x", "", "", 0.0, "", "", "", available=False)
        with patch("apkradar.search_cmd.lookup", return_value=info):
            result = self.runner.invoke(app, ["search", "com.evil[/bold]"])
        self.assertIsNone(result.exception)
        self.assertIn("com.evil[/bold]", result.output)

    def test_name_query_escaped(self):
        result = self.runner.invoke(app, ["search", "Coin [/link] Master"])
        self.assertIsNone(result.exception)
        self.assertIn("Coin+[/link]+Master", result.output)


class TestSendMarkup(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_dry_run_letter_printed_verbatim(self):
        with patch("apkradar.scanner.scan", return_value=_result(app_name="App [/bold]")), \
             patch("apkradar.cli._check_mailradar", return_value=(None, None)), \
             patch("apkradar.cli._check_ssl", return_value=("error", None)):
            result = self.runner.invoke(app, [
                "send", "test.apk", *SEND_ARGS[:2],
                "--publisher", "ACME [/dim] [link=https://evil.example]x[/link]",
                *SEND_ARGS[4:], "--dry-run",
            ])
        self.assertIsNone(result.exception)
        self.assertIn("Spettabile ACME [/dim] [link=https://evil.example]x[/link]", result.output)
        self.assertIn("App [/bold]", result.output)

    def test_domain_and_recipient_escaped(self):
        with patch("apkradar.scanner.scan", return_value=_result(package_name="com.evil[/dim]")), \
             patch("apkradar.cli._check_mailradar", return_value=(50, "D[/dim]")), \
             patch("apkradar.cli._check_ssl", return_value=("error", None)), \
             patch("apkradar.sender.send_letter", side_effect=RuntimeError("SMTP [/red] down")):
            result = self.runner.invoke(app, [
                "send", "test.apk",
                "--to", "dpo[/bold]@example.com",
                *SEND_ARGS[2:],
            ])
        self.assertNotIn("MarkupError", repr(result.exception))
        self.assertEqual(result.exit_code, 1)
        self.assertIn("evil[/dim].com", result.output)
        self.assertIn("D[/dim]", result.output)
        self.assertIn("dpo[/bold]@example.com", result.output)
        self.assertIn("SMTP [/red] down", result.output)


if __name__ == "__main__":
    unittest.main()
