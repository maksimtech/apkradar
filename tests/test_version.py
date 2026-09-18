"""Tests for the --version option."""
import re
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch
from typer.testing import CliRunner
import apkradar
from apkradar.cli import app

ROOT = Path(__file__).resolve().parent.parent


class TestVersion(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner()

    def test_version_output(self):
        result = self.runner.invoke(app, ["--version"])
        self.assertEqual(result.output.strip(), f"APKRadar {apkradar.__version__}")

    def test_version_exit_code(self):
        result = self.runner.invoke(app, ["--version"])
        self.assertEqual(result.exit_code, 0)

    def test_version_reads_dunder_version(self):
        with patch("apkradar.cli.__version__", "9999.99.99"):
            result = self.runner.invoke(app, ["--version"])
        self.assertEqual(result.output.strip(), "APKRadar 9999.99.99")

    def test_version_matches_pyproject(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
        project = pyproject["project"]
        if "version" in project:
            self.assertEqual(project["version"], apkradar.__version__)
            return
        # Dynamic version: hatch must read it from apkradar/__init__.py
        self.assertIn("version", project.get("dynamic", []))
        path = pyproject["tool"]["hatch"]["version"]["path"]
        self.assertEqual(path, "apkradar/__init__.py")
        content = (ROOT / path).read_text()
        match = re.search(r'__version__ = "(.+?)"', content)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), apkradar.__version__)


if __name__ == "__main__":
    unittest.main()
