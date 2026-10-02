"""The letter carries its distribution terms, or carries none and says nothing.

`apkradar send --tlp amber` marks the document the way FIRST's TLP 2.0 asks: the
label in the subject line, so it is visible before the message is opened, and a
block at the top of the body saying what the recipient may do with it.

Without `--tlp` the letter is unmarked. Not CLEAR — unmarked. A sender who said
nothing has not granted unlimited redistribution, and the test that holds that is
`test_without_the_option_the_letter_says_nothing_about_distribution`: if TLP text
ever appears in a letter nobody asked to mark, it appears there too.

A label the standard does not define stops the send. `TLP:WHITE` is the case worth
testing, because it was a real label until 2022 and somebody will type it.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from apkradar.cli import app
from apkradar.scanner import ScanResult

BASE = [
    "send", "test.apk",
    "--to", "dpo@example.com",
    "--publisher", "WONE SAGL",
    "--from", "test@example.com",
    "--smtp-host", "mail.example.com",
    "--smtp-user", "test@example.com",
    "--name", "Test User",
]


def _result():
    return ScanResult(
        apk_path="test.apk",
        package_name="com.wonet.usims",
        app_name="USIMS",
        version_name="3.88",
        sha256="ab" * 32,
    )


@patch("apkradar.cli._check_ssl", return_value=("error", None))
@patch("apkradar.cli._check_mailradar", return_value=(None, None))
@patch("apkradar.scanner.scan")
class TestLetterMarking(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def _dry_run(self, mock_scan, *extra):
        mock_scan.return_value = _result()
        return self.runner.invoke(app, [*BASE, "--dry-run", *extra])

    def test_the_marked_letter_carries_the_label_and_the_permission(self, mock_scan, *_):
        outcome = self._dry_run(mock_scan, "--tlp", "amber")

        self.assertEqual(outcome.exit_code, 0, outcome.output)
        self.assertIn("TLP:AMBER", outcome.output)
        self.assertIn("www.first.org/tlp", outcome.output)
        self.assertIn("2.0", outcome.output)
        # The letter is Italian; the permission is too, and the label is not.
        self.assertIn("destinatario", outcome.output.lower())

    def test_the_marking_is_at_the_top_where_a_reader_meets_it_first(self, mock_scan, *_):
        outcome = self._dry_run(mock_scan, "--tlp", "amber")

        body = outcome.output[outcome.output.index("TLP:AMBER"):]
        self.assertLess(body.index("TLP:AMBER"), body.index("Oggetto:"))

    def test_amber_strict_says_something_different_from_amber(self, mock_scan, *_):
        amber = self._dry_run(mock_scan, "--tlp", "amber").output
        strict = self._dry_run(mock_scan, "--tlp", "amber+strict").output

        self.assertIn("TLP:AMBER+STRICT", strict)
        self.assertNotIn("TLP:AMBER+STRICT", amber)
        self.assertIn("client", amber.lower())
        self.assertNotIn("client", strict.split("Oggetto:")[0].lower())

    def test_without_the_option_the_letter_says_nothing_about_distribution(self, mock_scan, *_):
        """Unmarked is unmarked. The day this fails, something decided on the
        sender's behalf that the document may be shared."""
        outcome = self._dry_run(mock_scan)

        self.assertEqual(outcome.exit_code, 0, outcome.output)
        self.assertNotIn("TLP", outcome.output)
        self.assertNotIn("first.org/tlp", outcome.output)

    def test_a_label_from_the_old_standard_stops_the_send(self, mock_scan, *_):
        mock_scan.return_value = _result()

        with patch("apkradar.sender.send_letter") as send:
            outcome = self.runner.invoke(app, [*BASE, "--tlp", "white"])

        self.assertEqual(outcome.exit_code, 2, outcome.output)
        self.assertIn("CLEAR", outcome.output)
        self.assertIn("2.0", outcome.output)
        send.assert_not_called()

    def test_a_label_nobody_defines_stops_the_send_too(self, mock_scan, *_):
        mock_scan.return_value = _result()

        with patch("apkradar.sender.send_letter") as send:
            outcome = self.runner.invoke(app, [*BASE, "--tlp", "orange"])

        self.assertEqual(outcome.exit_code, 2, outcome.output)
        # Typer exits 2 for an unknown *option* too, so the code alone would pass
        # against a command with no --tlp at all. This is the module's own message.
        self.assertIn("TLP:AMBER+STRICT", outcome.output)
        self.assertNotIn("No such option", outcome.output)
        send.assert_not_called()

    def test_a_bad_label_is_refused_before_the_apk_is_read(self, mock_scan, *_):
        """Nothing is scanned, nothing is looked up, no network: the option is
        wrong and that is answerable without doing any of the work."""
        outcome = self.runner.invoke(app, [*BASE, "--tlp", "orange"])

        self.assertEqual(outcome.exit_code, 2, outcome.output)
        self.assertNotIn("No such option", outcome.output)   # as above
        self.assertIn("orange", outcome.output)
        mock_scan.assert_not_called()

    def test_the_subject_of_the_sent_message_leads_with_the_label(self, mock_scan, *_):
        mock_scan.return_value = _result()

        with patch("apkradar.sender.send_letter") as send:
            outcome = self.runner.invoke(app, [*BASE, "--tlp", "amber+strict"])

        self.assertEqual(outcome.exit_code, 0, outcome.output)
        send.assert_called_once()
        subject = send.call_args.kwargs["subject"]
        self.assertTrue(subject.startswith("TLP:AMBER+STRICT "), subject)
        self.assertIn("Esercizio diritti GDPR", subject)

    def test_an_unmarked_send_has_a_subject_with_no_label(self, mock_scan, *_):
        mock_scan.return_value = _result()

        with patch("apkradar.sender.send_letter") as send:
            self.runner.invoke(app, BASE)

        self.assertNotIn("TLP", send.call_args.kwargs["subject"])


if __name__ == "__main__":
    unittest.main()
