"""Tests for APKRadar Excel module."""
import os
import tempfile
import unittest
from apkradar.scanner import ScanResult, TrackerFound, PermissionFound, TransferFound
from apkradar.excel import read_apk_list, write_results, ExcelRow


def _make_result(package="com.example.app", score_label="POOR"):
    result = ScanResult(
        apk_path="test.apk",
        package_name=package,
        app_name="Test App",
        version_name="1.0",
        version_code="1",
        sha256="abc123" * 11,
        apk_format="apk",
    )
    result.trackers = [
        TrackerFound(package="com.google.firebase", name="Firebase Analytics")
    ]
    result.sensitive_permissions = [
        PermissionFound(
            permission="android.permission.ACCESS_FINE_LOCATION",
            description="precise GPS location",
        )
    ]
    result.extra_eu_transfers = [
        TransferFound(package_prefix="com.google", entity="Google LLC (USA)")
    ]
    return result


def _make_xlsx(data: list[dict]) -> str:
    """Create a temp Excel file with given data."""
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    if data:
        headers = list(data[0].keys())
        for col_idx, header in enumerate(headers, 1):
            ws.cell(row=1, column=col_idx, value=header)
        for row_idx, row in enumerate(data, 2):
            for col_idx, value in enumerate(row.values(), 1):
                ws.cell(row=row_idx, column=col_idx, value=value)
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        tmp = f.name
    wb.save(tmp)
    return tmp


class TestReadApkList(unittest.TestCase):

    def test_read_package_name_column(self):
        tmp = _make_xlsx([
            {"App Name": "Test App", "Package Name": "com.example.app"},
            {"App Name": "Another App", "Package Name": "com.another.app"},
        ])
        try:
            rows = read_apk_list(tmp)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].package_name, "com.example.app")
            self.assertEqual(rows[0].app_name, "Test App")
            self.assertEqual(rows[1].package_name, "com.another.app")
        finally:
            os.unlink(tmp)

    def test_read_apk_path_column(self):
        tmp = _make_xlsx([
            {"App Name": "Test App", "APK Path": "/path/to/app.apk"},
        ])
        try:
            rows = read_apk_list(tmp)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].apk_path, "/path/to/app.apk")
        finally:
            os.unlink(tmp)

    def test_read_empty_rows_skipped(self):
        tmp = _make_xlsx([
            {"Package Name": "com.example.app"},
            {"Package Name": ""},
            {"Package Name": "com.another.app"},
        ])
        try:
            rows = read_apk_list(tmp)
            self.assertEqual(len(rows), 2)
        finally:
            os.unlink(tmp)

    def test_read_row_numbers(self):
        tmp = _make_xlsx([
            {"Package Name": "com.example.app"},
            {"Package Name": "com.another.app"},
        ])
        try:
            rows = read_apk_list(tmp)
            self.assertEqual(rows[0].row_number, 2)
            self.assertEqual(rows[1].row_number, 3)
        finally:
            os.unlink(tmp)


class TestWriteResults(unittest.TestCase):

    def test_write_creates_file(self):
        results = [_make_result()]
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            tmp = f.name
        os.unlink(tmp)
        try:
            write_results(results, tmp)
            self.assertTrue(os.path.exists(tmp))
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def test_write_multiple_results(self):
        import openpyxl
        results = [
            _make_result("com.app1"),
            _make_result("com.app2"),
            _make_result("com.app3"),
        ]
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            tmp = f.name
        os.unlink(tmp)
        try:
            write_results(results, tmp)
            wb = openpyxl.load_workbook(tmp)
            ws = wb.active
            self.assertEqual(ws.max_row, 4)  # 1 header + 3 data rows
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def test_write_augment_mode(self):
        import openpyxl
        input_tmp = _make_xlsx([
            {"App Name": "Test App", "Package Name": "com.example.app"},
        ])
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            output_tmp = f.name
        os.unlink(output_tmp)
        try:
            results = [_make_result()]
            write_results(results, output_tmp, input_path=input_tmp)
            wb = openpyxl.load_workbook(output_tmp)
            ws = wb.active
            self.assertGreater(ws.max_column, 2)
        finally:
            os.unlink(input_tmp)
            if os.path.exists(output_tmp):
                os.unlink(output_tmp)


class TestExcelRow(unittest.TestCase):

    def test_excel_row_defaults(self):
        row = ExcelRow(
            row_number=2,
            app_name="Test",
            package_name="com.test.app",
            apk_path="",
        )
        self.assertEqual(row.row_number, 2)
        self.assertEqual(row.package_name, "com.test.app")
        self.assertEqual(row.apk_path, "")


if __name__ == "__main__":
    unittest.main()


class TestBatchExcelCommand(unittest.TestCase):

    def setUp(self):
        from typer.testing import CliRunner
        self.runner = CliRunner()

    def test_batch_excel_help(self):
        from apkradar.cli import app
        result = self.runner.invoke(app, ["batch-excel", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_batch_excel_missing_file(self):
        from apkradar.cli import app
        result = self.runner.invoke(app, ["batch-excel", "nonexistent.xlsx"])
        self.assertNotEqual(result.exit_code, 0)

    def test_batch_excel_empty_file(self):
        import openpyxl, tempfile, os
        from apkradar.cli import app
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.cell(row=1, column=1, value="Package Name")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            tmp = f.name
        wb.save(tmp)
        try:
            result = self.runner.invoke(app, ["batch-excel", tmp])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No APKs found", result.output)
        finally:
            os.unlink(tmp)

    def test_batch_excel_with_package_name(self):
        import openpyxl, tempfile, os
        from apkradar.cli import app
        from unittest.mock import patch
        from apkradar.scanner import ScanResult
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.cell(row=1, column=1, value="Package Name")
        ws.cell(row=2, column=1, value="com.example.app")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            tmp_in = f.name
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            tmp_out = f.name
        wb.save(tmp_in)
        os.unlink(tmp_out)
        try:
            mock_result = ScanResult(apk_path="com.example.app", package_name="com.example.app")
            with patch("apkradar.excel.read_apk_list") as mock_read:
                from apkradar.excel import ExcelRow
                mock_read.return_value = [ExcelRow(
                    row_number=2,
                    app_name="Example",
                    package_name="com.example.app",
                    apk_path="",
                )]
                with patch("apkradar.excel.write_results"):
                    result = self.runner.invoke(app, ["batch-excel", tmp_in, "--output", tmp_out])
                    self.assertEqual(result.exit_code, 0)
        finally:
            os.unlink(tmp_in)
            if os.path.exists(tmp_out):
                os.unlink(tmp_out)
