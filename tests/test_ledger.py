from pathlib import Path

import pytest

from securetrace.ledger import (
    add_requirement,
    list_requirements,
    mark_changed_files,
    record_check,
)


def test_add_requirement_and_list(tmp_path: Path):
    item = add_requirement(
        tmp_path,
        "Only owners can cancel appointments",
        "The backend verifies appointment ownership.",
        category="authorization",
        severity="high",
        file_paths=["src/routes/appointments.py"],
    )
    items = list_requirements(tmp_path)
    assert len(items) == 1
    assert items[0]["id"] == item["id"]
    assert items[0]["status"] == "IDENTIFIED"
    assert items[0]["file_paths"] == ["src/routes/appointments.py"]


def test_failed_check_marks_regression(tmp_path: Path):
    item = add_requirement(tmp_path, "Protected route requires auth", "No anonymous access.")
    result = record_check(
        tmp_path,
        item["id"],
        "anonymous-access-test",
        passed=False,
        details="Anonymous request was accepted.",
    )
    assert result["status"] == "REGRESSION"
    assert list_requirements(tmp_path)[0]["status"] == "REGRESSION"


def test_complete_passing_check_marks_verified(tmp_path: Path):
    item = add_requirement(tmp_path, "Only owners can cancel appointments", "Check ownership.")
    result = record_check(
        tmp_path,
        item["id"],
        "owner-authorization-test",
        passed=True,
        verification_complete=True,
    )
    assert result["status"] == "VERIFIED"


def test_partial_passing_check_does_not_mark_verified(tmp_path: Path):
    item = add_requirement(tmp_path, "Only owners can cancel appointments", "Check ownership.")
    result = record_check(
        tmp_path,
        item["id"],
        "static-analysis",
        passed=True,
        verification_complete=False,
    )
    assert result["status"] == "IMPLEMENTED"


def test_linked_file_change_marks_verified_requirement_stale(tmp_path: Path):
    item = add_requirement(
        tmp_path,
        "Only owners can cancel appointments",
        "Check ownership.",
        category="authorization",
        file_paths=["src/routes/appointments.py"],
    )
    record_check(
        tmp_path,
        item["id"],
        "owner-test",
        passed=True,
        verification_complete=True,
    )

    affected = mark_changed_files(tmp_path, ["src/routes/appointments.py"])
    assert affected == [{
        "requirement_id": item["id"],
        "changed_files": ["src/routes/appointments.py"],
        "mapped_tests": [],
        "verification_plan": [],
        "eligible_reruns": [],
        "unmapped": True,
        "evidence_stale": False,
        "evidence_freshness": "UNKNOWN",
        "historical_runs_preserved": 1,
        "uncertainty": "No approved test mapping is available; rerun eligibility cannot be determined.",
    }]
    assert list_requirements(tmp_path)[0]["status"] == "STALE"


def test_unknown_requirement_check_fails(tmp_path: Path):
    with pytest.raises(ValueError):
        record_check(tmp_path, "SEC-DOESNOTEXIST", "test", passed=True)
