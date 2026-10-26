from __future__ import annotations

import json
from pathlib import Path

import pytest

import securetrace.semgrep as semgrep
from securetrace.db import connect
from securetrace.dashboard import read_dashboard_data
from securetrace import cli
from securetrace.ledger import add_requirement, list_requirements, record_check
from securetrace.reporting import render_report


@pytest.fixture
def scan_project(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='scan-demo'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def handler():\n    return input()\n", encoding="utf-8")
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    requirement = add_requirement(tmp_path, "Input validation", "Inputs are validated.",
                                  category="authorization", file_paths=["app.py"])
    return tmp_path, requirement, rules


def semgrep_json(*, results=None, errors=None, skipped=None, scanned=None):
    return json.dumps({
        "results": results or [], "errors": errors or [],
        "paths": {"scanned": scanned if scanned is not None else ["app.py"],
                  "skipped": skipped or []},
    })


def mock_process(monkeypatch, payload: str, *, exit_code=0, timed_out=False, truncated=False):
    monkeypatch.setattr(semgrep.shutil, "which", lambda name: "C:/tools/semgrep.exe")
    calls = []

    def execute(argv, cwd, timeout):
        calls.append(argv)
        if argv[1:] == ["--version"]:
            return {"exit_code": 0, "output": "1.2.3", "truncated": False,
                    "timed_out": False, "error": None}
        return {"exit_code": exit_code, "output": payload, "truncated": truncated,
                "timed_out": timed_out, "error": None}

    monkeypatch.setattr(semgrep, "_bounded_process", execute)
    return calls


def result_item(path="app.py"):
    return {
        "check_id": "python.test.input",
        "path": path,
        "start": {"line": 3}, "end": {"line": 3},
        "extra": {"severity": "WARNING", "message": "Untrusted input reaches sink."},
    }


def scan_events(root: Path):
    with connect(root) as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM events WHERE event_type='SEMGREP_SCAN' ORDER BY id"
        )]


def test_plan_only_validates_config_without_execution_or_evidence(scan_project, monkeypatch):
    root, _, rules = scan_project
    monkeypatch.setattr(semgrep.shutil, "which", lambda name: pytest.fail("plan looked up scanner"))
    plan = semgrep.run_semgrep_scan(root, "rules.yml")
    assert plan["status"] == "PLANNED"
    assert plan["executed"] is False
    assert plan["ruleset_sha256"]
    assert scan_events(root) == []
    assert rules.exists()


def test_cli_requires_explicit_scanner_approval(scan_project, monkeypatch, capsys):
    root, _, _ = scan_project
    monkeypatch.setattr(cli, "project_root", lambda: root)
    monkeypatch.setattr(semgrep.shutil, "which", lambda name: pytest.fail("CLI plan executed scanner"))
    monkeypatch.setattr("sys.argv", ["securetrace", "semgrep", "--config", "rules.yml"])
    cli.main()
    assert "no scanner was executed" in capsys.readouterr().out
    assert scan_events(root) == []


def test_clean_scan_records_metadata_without_verifying_requirement(scan_project, monkeypatch):
    root, req, _ = scan_project
    record_check(root, req["id"], "manual", True, verification_complete=False)
    calls = mock_process(monkeypatch, semgrep_json())
    before_status = next(item for item in list_requirements(root) if item["id"] == req["id"])["status"]
    result = semgrep.run_semgrep_scan(root, "rules.yml", approve=True)
    assert result["status"] == "CLEAN"
    assert result["scanner_version"] == "1.2.3"
    assert result["exit_code"] == 0 and result["duration_seconds"] >= 0
    assert len(calls) == 2
    assert scan_events(root)
    after = next(item for item in list_requirements(root) if item["id"] == req["id"])["status"]
    assert before_status == after == "IMPLEMENTED"
    assert "CLEAN" in render_report(root)
    assert "CLEAN" in read_dashboard_data(root)["report"]


def test_finding_maps_only_by_exact_requirement_file_link(scan_project, monkeypatch):
    root, req, _ = scan_project
    mock_process(monkeypatch, semgrep_json(results=[result_item(), result_item("unlinked.py")]))
    result = semgrep.run_semgrep_scan(root, "rules.yml", approve=True)
    assert result["status"] == "FINDINGS"
    assert result["finding_count"] == 2
    assert result["findings"][0]["requirement_ids"] == [req["id"]]
    assert result["findings"][1]["requirement_ids"] == []
    assert result["unmapped_count"] == 1
    report = render_report(root)
    assert "FINDINGS" in report and "unmapped" in report
    assert req["id"] in report


@pytest.mark.parametrize(("payload", "exit_code", "timed_out", "truncated", "expected"), [
    ("not-json", 0, False, False, "ERROR"),
    (semgrep_json(errors=[{"message": "parse failed"}]), 0, False, False, "INCOMPLETE"),
    (semgrep_json(skipped=[{"path": "other.py"}]), 0, False, False, "INCOMPLETE"),
    (semgrep_json(), 0, True, False, "TIMEOUT"),
    (semgrep_json(), 0, False, True, "INCOMPLETE"),
    (semgrep_json(), 2, False, False, "ERROR"),
])
def test_scan_errors_timeout_and_partial_results_are_never_clean(
    scan_project, monkeypatch, payload, exit_code, timed_out, truncated, expected,
):
    root, _, _ = scan_project
    mock_process(monkeypatch, payload, exit_code=exit_code, timed_out=timed_out, truncated=truncated)
    result = semgrep.run_semgrep_scan(root, "rules.yml", approve=True)
    assert result["status"] == expected
    assert scan_events(root)
    assert "CLEAN" not in render_report(root)


def test_invalid_ruleset_and_out_of_root_symlink_block_scan(scan_project, monkeypatch):
    root, _, rules = scan_project
    monkeypatch.setattr(semgrep, "_bounded_process", lambda *a, **k: pytest.fail("invalid target executed"))
    with pytest.raises(ValueError):
        semgrep.run_semgrep_scan(root, "../outside.yml", approve=True)

    monkeypatch.setattr(semgrep, "_check_symlinks", lambda project: ["external-link.py"])
    monkeypatch.setattr(semgrep.shutil, "which", lambda name: "semgrep")
    monkeypatch.setattr(semgrep, "_bounded_process", lambda *a, **k: {
        "exit_code": 0, "output": "1.2.3", "truncated": False,
        "timed_out": False, "error": None,
    })
    result = semgrep.run_semgrep_scan(root, "rules.yml", approve=True)
    assert result["status"] == "ERROR"
    assert "Out-of-root symlinks" in result["error"]
    assert rules.exists()


def test_remote_or_inherited_ruleset_is_rejected(scan_project):
    root, _, rules = scan_project
    rules.write_text("extends: p/security-audit\nrules: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Remote or inherited"):
        semgrep.run_semgrep_scan(root, "rules.yml", approve=True)


def test_missing_scanner_records_error_in_existing_events(scan_project, monkeypatch):
    root, _, _ = scan_project
    monkeypatch.setattr(semgrep.shutil, "which", lambda name: None)
    result = semgrep.run_semgrep_scan(root, "rules.yml", approve=True)
    assert result["status"] == "ERROR"
    assert result["executed"] is False
    assert len(scan_events(root)) == 1


def test_same_file_finding_maps_to_all_linked_requirements(scan_project, monkeypatch):
    root, first, _ = scan_project
    second = add_requirement(root, "Second input rule", "Also concerns app.py.",
                             category="authorization", file_paths=["app.py"])
    mock_process(monkeypatch, semgrep_json(results=[result_item()]))
    result = semgrep.run_semgrep_scan(root, "rules.yml", approve=True)
    assert result["findings"][0]["requirement_ids"] == sorted([first["id"], second["id"]])
