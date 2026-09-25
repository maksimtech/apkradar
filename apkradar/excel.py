"""
APKRadar — Excel input/output module.
Read APK lists from Excel and write audit results to Excel.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Leading characters that spreadsheet apps interpret as a formula
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _write_cell(ws, row: int, column: int, value):
    """
    Write a value to a cell without letting strings become formulas.

    Strings are always stored as text. Strings starting with a formula
    prefix also get quotePrefix (Excel's leading apostrophe), so they stay
    text even if the cell is edited or the sheet is exported to CSV.
    """
    cell = ws.cell(row=row, column=column, value=value)
    if isinstance(value, str):
        cell.data_type = "s"
        if value.startswith(FORMULA_PREFIXES):
            cell.quotePrefix = True
    return cell


@dataclass
class ExcelRow:
    row_number: int
    app_name: str
    package_name: str
    apk_path: str


def read_apk_list(path: str) -> list[ExcelRow]:
    """
    Read APK list from Excel file.

    Supported column names (case-insensitive):
    - Package Name / Package / PackageName / package_name
    - APK Path / APK / Path / apk_path
    - App Name / App / Name / app_name

    Args:
        path: Path to Excel file (.xlsx)

    Returns:
        List of ExcelRow objects
    """
    import openpyxl

    wb = openpyxl.load_workbook(path)
    ws = wb.active

    # Find header row
    headers = {}
    for col_idx, cell in enumerate(ws[1], 1):
        if cell.value:
            key = str(cell.value).lower().strip().replace(" ", "_")
            headers[key] = col_idx

    # Map known column names
    def find_col(*names):
        for name in names:
            key = name.lower().replace(" ", "_")
            if key in headers:
                return headers[key]
        return None

    pkg_col = find_col("package_name", "package", "packagename", "pkg")
    path_col = find_col("apk_path", "apk", "path", "file")
    name_col = find_col("app_name", "app", "name", "title")

    rows = []
    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), 2):
        pkg = str(row[pkg_col - 1]).strip() if pkg_col and row[pkg_col - 1] else ""
        apk = str(row[path_col - 1]).strip() if path_col and row[path_col - 1] else ""
        name = str(row[name_col - 1]).strip() if name_col and row[name_col - 1] else ""

        if pkg or apk:
            rows.append(ExcelRow(
                row_number=row_idx,
                app_name=name,
                package_name=pkg,
                apk_path=apk,
            ))

    return rows


def write_results(results: list, output_path: str, input_path: str | None = None) -> None:
    """
    Write audit results to Excel file.

    If input_path is provided, adds columns to the existing file.
    Otherwise creates a new file.

    Args:
        results: List of ScanResult objects
        output_path: Path to output Excel file
        input_path: Optional path to input Excel file to augment
    """
    import openpyxl
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    if input_path and Path(input_path).exists():
        wb = openpyxl.load_workbook(input_path)
        ws = wb.active
        # Find last column
        last_col = ws.max_column + 1
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "APKRadar Report"
        last_col = 1

        # Write headers
        headers = [
            "App Name", "Package Name", "Format", "Version",
            "Score", "Grade", "Trackers", "Sensitive Permissions",
            "Extra-EU Transfers", "Tracker Names", "SHA256"
        ]
        for col_idx, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(fill_type="solid", fgColor="1F4E79")
            cell.alignment = Alignment(horizontal="center")

    # Grade colors
    grade_colors = {
        "GOOD":     "C6EFCE",  # green
        "MODERATE": "FFEB9C",  # yellow
        "POOR":     "FFCC99",  # orange
        "CRITICAL": "FFC7CE",  # red
    }

    if input_path and Path(input_path).exists():
        # Add result columns to existing file
        result_headers = ["Score", "Grade", "Trackers", "Permissions", "Extra-EU", "Tracker Names"]
        for col_idx, header in enumerate(result_headers, last_col):
            cell = ws.cell(row=1, column=col_idx, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(fill_type="solid", fgColor="1F4E79")

        for row_idx, result in enumerate(results, 2):
            tracker_names = ", ".join(t.name for t in result.trackers)
            values = [
                # Blank, not 0: a zero in this column gets averaged,
                # sorted and charted alongside real scores.
                "" if result.score is None else result.score,
                result.score_label,
                result.tracker_count,
                result.sensitive_permission_count,
                len(result.extra_eu_transfers),
                tracker_names,
            ]
            for col_idx, value in enumerate(values, last_col):
                cell = _write_cell(ws, row_idx, col_idx, value)
                if col_idx == last_col + 1:  # Grade column
                    color = grade_colors.get(result.score_label, "FFFFFF")
                    cell.fill = PatternFill(fill_type="solid", fgColor=color)
    else:
        # Write all data
        for row_idx, result in enumerate(results, 2):
            tracker_names = ", ".join(t.name for t in result.trackers)
            values = [
                result.app_name or result.package_name,
                result.package_name,
                result.apk_format.upper(),
                result.version_name,
                # Blank, not 0: a zero in this column gets averaged,
                # sorted and charted alongside real scores.
                "" if result.score is None else result.score,
                result.score_label,
                result.tracker_count,
                result.sensitive_permission_count,
                len(result.extra_eu_transfers),
                tracker_names,
                result.sha256[:16] + "..." if result.sha256 else "",
            ]
            for col_idx, value in enumerate(values, 1):
                cell = _write_cell(ws, row_idx, col_idx, value)
                if col_idx == 6:  # Grade column
                    color = grade_colors.get(result.score_label, "FFFFFF")
                    cell.fill = PatternFill(fill_type="solid", fgColor=color)

    # Auto-width columns
    for col in ws.columns:
        max_length = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = min(max_length + 4, 50)

    wb.save(output_path)
