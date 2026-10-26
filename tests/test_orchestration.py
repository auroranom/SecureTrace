from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

import securetrace.orchestration as orchestration
from securetrace.db import connect, migrate_mappings
from securetrace.ledger import add_requirement, get_requirement_detail, map_requirement_test
from securetrace.orchestration import orchestrate_verification
from securetrace.reporting import render_report
from securetrace.test_runner import EvidencePersistenceError


@pytest.fixture
def orchestration_project(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='orchestration-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_access.py").write_text(
        "def test_access():\n    assert True\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("ACCESS = True\n", encoding="utf-8")
    requirement = add_requirement(tmp_path, "Owner access", "Only owners may access records.",
                                  category="authorization", file_paths=["app.py"])
    migrate_mappings(tmp_path)
    mapping = map_requirement_test(tmp_path, requirement["id"], "tests/test_access.py", "test_access",
                                   verification_complete=True)
    return tmp_path, requirement, mapping


def fake_result(outcome="PASSED", stable=True):
    return {
        "outcome": outcome,
        "execution": {
            "source_state_stable": stable,
            "source_fingerprint_before": {"digest": "abc"},
        },
    }


def check_count(root: Path, requirement_id: str) -> int:
    with connect(root) as db:
        return db.execute("SELECT COUNT(*) FROM checks WHERE requirement_id=?", (requirement_id,)).fetchone()[0]


def test_plan_only_does_not_execute_or_change_check_history(orchestration_project, monkeypatch):
    root, req, _ = orchestration_project
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: pytest.fail("plan executed a test"))
    before = check_count(root, req["id"])
    result = orchestrate_verification(root)
    assert result["mode"] == "PLAN_ONLY"
    assert len(result["selected_checks"]) == 1
    assert result["results"][0]["status"] == "PLANNED"
    assert result["counts"] == {"PLANNED": 1}
    assert check_count(root, req["id"]) == before
    detail = get_requirement_detail(root, req["id"])
    event = next(event for event in detail["events"] if event["event_type"] == "ORCHESTRATION_PLAN")
    recorded = json.loads(event["details"])
    assert recorded["plan_inputs"]["approval_provided"] is False
    assert recorded["selected_checks"][0]["test_id"] == "test_access"
    assert "Latest orchestration" in render_report(root)


def test_explicit_approval_runs_baseline_and_records_outcome(orchestration_project):
    root, req, _ = orchestration_project
    result = orchestrate_verification(root, approve=True)
    assert result["mode"] == "APPROVED_RUN"
    assert result["counts"] == {"PASSED": 1}
    assert result["results"][0]["outcome"] == "PASSED"
    assert check_count(root, req["id"]) == 1
    assert result["results"][0]["execution"]["source_state_stable"] is True


def test_stale_fingerprint_is_rerun_but_unknown_historical_fingerprint_is_blocked(orchestration_project, monkeypatch):
    root, req, _ = orchestration_project
    first = orchestrate_verification(root, approve=True)
    assert first["counts"] == {"PASSED": 1}
    (root / "app.py").write_text("ACCESS = False\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: calls.append(a) or fake_result())
    rerun = orchestrate_verification(root, approve=True)
    assert len(calls) == 1
    assert rerun["counts"] == {"PASSED": 1}
    assert rerun["selected_checks"][0]["evidence_freshness"] == "STALE"

    # A legacy automated record without a snapshot cannot be treated as a
    # reliable current baseline and must block execution.
    with connect(root) as db:
        db.execute(
            "INSERT INTO checks(requirement_id,check_name,result,verification_complete,details,ran_at) "
            "VALUES(?,?,?,0,?,?)",
            (req["id"], "test_access", "PASSED",
             json.dumps({"securetrace_test": 1, "origin": "automated", "outcome": "PASSED",
                         "test_file": "tests/test_access.py"}), "9999-01-01T00:00:00+00:00"),
        )
    blocked = orchestrate_verification(root, approve=True)
    assert blocked["counts"] == {"BLOCKED": 1}
    assert "Freshness is UNKNOWN" in blocked["results"][0]["blockers"][-1]
    assert len(calls) == 1


def test_invalid_mapping_is_blocked_before_runner(orchestration_project, monkeypatch):
    root, req, _ = orchestration_project
    with connect(root) as db:
        db.execute("DELETE FROM requirement_tests WHERE requirement_id=?", (req["id"],))
        db.execute(
            "INSERT INTO requirement_tests(requirement_id,test_file,test_id,verification_complete,created_at) "
            "VALUES(?,?,?,1,'now')", (req["id"], "../outside.py", "test_escape"),
        )
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: pytest.fail("invalid mapping ran"))
    result = orchestrate_verification(root, approve=True)
    assert result["counts"] == {"BLOCKED": 1}
    assert result["results"][0]["blockers"]


def test_unreadable_source_blocks_execution(orchestration_project, monkeypatch):
    root, _, _ = orchestration_project
    original_open = Path.open

    def denied(path, *args, **kwargs):
        if path.name == "app.py":
            raise PermissionError("injected unreadable source")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: pytest.fail("unknown source ran"))
    result = orchestrate_verification(root, approve=True)
    assert result["counts"] == {"BLOCKED": 1}
    assert any("UNREADABLE" in item for item in result["results"][0]["blockers"])


def test_duplicate_plan_checks_are_suppressed_unless_explicitly_allowed(orchestration_project, monkeypatch):
    root, _, _ = orchestration_project
    original_plan = orchestration.current_verification_plan

    def duplicated(project_root):
        entry = original_plan(project_root)[0]
        return [entry, dict(entry)]

    calls = []
    monkeypatch.setattr(orchestration, "current_verification_plan", duplicated)
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: calls.append(a) or fake_result())
    planned = orchestrate_verification(root)
    assert len(planned["selected_checks"]) == 1
    assert sum(item["status"] == "SKIPPED_DUPLICATE" for item in planned["results"]) == 1
    executed = orchestrate_verification(root, approve=True, allow_duplicates=True)
    assert len(calls) == 2
    assert executed["counts"] == {"PASSED": 2}


def test_mixed_outcomes_continue_and_are_recorded(orchestration_project, monkeypatch):
    root, req, _ = orchestration_project
    for test_id in ("test_fail", "test_timeout", "test_error"):
        filename = f"tests/{test_id}.py"
        (root / filename).write_text(f"def {test_id}():\n    assert True\n", encoding="utf-8")
        map_requirement_test(root, req["id"], filename, test_id, verification_complete=True)
    outcomes = {"test_access": "PASSED", "test_fail": "FAILED", "test_timeout": "TIMEOUT", "test_error": "ERROR"}
    called = []

    def fake_run(root_arg, requirement_id, test_file, test_id, **kwargs):
        called.append(test_id)
        return fake_result(outcomes[test_id])

    monkeypatch.setattr(orchestration, "run_approved_test", fake_run)
    result = orchestrate_verification(root, approve=True)
    assert len(called) == 4
    assert result["counts"] == {"PASSED": 1, "FAILED": 1, "TIMEOUT": 1, "ERROR": 1}
    assert len(result["results"]) == 4
    assert get_requirement_detail(root, req["id"])["status"] == "REGRESSION"


def test_timeout_error_and_execution_persistence_exception_are_not_passes(orchestration_project, monkeypatch):
    root, req, _ = orchestration_project
    outcomes = iter(["TIMEOUT", "ERROR"])
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: fake_result(next(outcomes)))
    result = orchestrate_verification(root, approve=True)
    assert result["results"][0]["status"] == "TIMEOUT"

    def persistence_failure(*args, **kwargs):
        raise EvidencePersistenceError("ledger write failed")

    monkeypatch.setattr(orchestration, "run_approved_test", persistence_failure)
    second = orchestrate_verification(root, approve=True, rerun_current=True)
    assert second["results"][0]["status"] == "ERROR"
    assert second["results"][0]["outcome"] == "ERROR"


def test_unrecognized_runner_outcome_is_unknown_not_pass(orchestration_project, monkeypatch):
    root, _, _ = orchestration_project
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: fake_result("MAYBE"))
    result = orchestrate_verification(root, approve=True)
    assert result["counts"] == {"UNKNOWN": 1}
    assert "unrecognized execution outcome" in result["results"][0]["blockers"][0]


def test_provenance_persistence_failure_is_reported_without_erasing_run(orchestration_project, monkeypatch):
    root, _, _ = orchestration_project
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: fake_result())
    monkeypatch.setattr(orchestration, "_persist_provenance", lambda *a, **k: ["injected persistence failure"])
    result = orchestrate_verification(root, approve=True)
    assert result["counts"] == {"PASSED": 1}
    assert result["persistence_errors"] == ["injected persistence failure"]


def test_backward_compatible_unmigrated_ledger_plans_without_executing(tmp_path: Path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='old-ledger'\n", encoding="utf-8")
    req = add_requirement(tmp_path, "Legacy requirement", "Existing record")
    with connect(tmp_path) as db:
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='requirement_tests'").fetchone() is None
    monkeypatch.setattr(orchestration, "run_approved_test", lambda *a, **k: pytest.fail("unmapped check ran"))
    result = orchestrate_verification(tmp_path, approve=True)
    assert result["mode"] == "APPROVED_RUN"
    assert result["selected_checks"] == []
    assert result["counts"] == {}
