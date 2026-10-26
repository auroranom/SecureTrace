from pathlib import Path

from securetrace.ledger import add_requirement
from securetrace.reporting import render_report, write_report


def test_report_contains_requirement_and_caveat(tmp_path: Path):
    add_requirement(
        tmp_path,
        "Users can access only their own records",
        "Server checks record ownership.",
        category="authorization",
        severity="high",
        file_paths=["app/routes.py"],
    )
    report = render_report(tmp_path)
    assert "SecureTrace Security Report" in report
    assert "Users can access only their own records" in report
    assert "not proof that the entire application is secure" in report


def test_write_report_creates_file(tmp_path: Path):
    output = write_report(tmp_path)
    assert output.exists()
    assert output.name == "SECURITY_REPORT.md"
