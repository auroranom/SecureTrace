from __future__ import annotations

from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest

import securetrace.test_runner as runner
import securetrace.cli as cli
from securetrace.dashboard import read_dashboard_data
from securetrace.db import connect
from securetrace.ledger import add_requirement, now_iso, record_check
from securetrace.reporting import render_report
from securetrace.test_runner import (
    EvidencePersistenceError,
    run_approved_test,
    validate_test_target,
)


@pytest.fixture
def project(tmp_path: Path) -> tuple[Path, str]:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='runner-fixture'\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "appointments.py").write_text("def can_cancel(owner, actor): return owner == actor\n", encoding="utf-8")
    requirement = add_requirement(
        tmp_path, "Only owners can cancel", "Reject another user's cancel request.",
        category="authorization", severity="high", file_paths=["app/appointments.py"],
    )
    return tmp_path, requirement["id"]


def write_test(root: Path, name: str, source: str) -> str:
    path = root / "tests" / name
    path.write_text(source, encoding="utf-8")
    return path.relative_to(root).as_posix()


def test_real_passing_test_records_execution_dashboard_and_report(project):
    root, requirement_id = project
    test_file = write_test(root, "test_authorization.py", "def test_owner_only():\n    assert 'owner' == 'owner'\n")

    result = run_approved_test(root, requirement_id, test_file, "test_owner_only", verification_complete=True)

    assert result["outcome"] == "PASSED"
    assert result["execution"]["exit_code"] == 0
    assert result["execution"]["started_at"] and result["execution"]["ended_at"]
    assert result["execution"]["evidence_ref"]
    assert result["status"] == "VERIFIED"
    evidence = root / result["execution"]["evidence_ref"]
    assert evidence.is_file()
    snapshot = read_dashboard_data(root)
    assert snapshot["counts"]["VERIFIED"] == 1
    assert "automatically executed test" in snapshot["report"]
    assert "test_owner_only" in render_report(root)
    assert "Evidence:" in snapshot["report"]


def test_passing_test_without_explicit_completion_is_not_verified(project):
    root, requirement_id = project
    test_file = write_test(root, "test_partial.py", "def test_partial():\n    assert True\n")

    result = run_approved_test(root, requirement_id, test_file, "test_partial")

    assert result["outcome"] == "PASSED"
    assert result["verification_complete"] is False
    assert result["status"] == "IMPLEMENTED"
    assert read_dashboard_data(root)["counts"]["VERIFIED"] == 0


def test_assertion_failure_is_genuine_authorization_regression(project):
    root, requirement_id = project
    test_file = write_test(
        root, "test_authorization_regression.py",
        "def test_other_user_is_denied():\n    assert False, 'another user was allowed to cancel'\n",
    )

    result = run_approved_test(root, requirement_id, test_file, "test_other_user_is_denied", verification_complete=True)

    assert result["outcome"] == "FAILED"
    assert result["execution"]["exit_code"] == 1
    assert result["status"] == "REGRESSION"
    snapshot = read_dashboard_data(root)
    assert snapshot["counts"]["REGRESSION"] == 1
    assert "**Status:** REGRESSION" in snapshot["report"]
    assert "Test outcome: **FAILED**" in render_report(root)


def test_timeout_is_not_a_pass_and_does_not_mark_regression(project):
    root, requirement_id = project
    test_file = write_test(root, "test_slow.py", "import time\ndef test_slow():\n    time.sleep(2)\n")

    result = run_approved_test(root, requirement_id, test_file, "test_slow", timeout_seconds=0.15,
                               verification_complete=True)

    assert result["outcome"] == "TIMEOUT"
    assert result["execution"]["exit_code"] not in (None, 0)
    assert result["verification_complete"] is False
    assert result["status"] == "IDENTIFIED"
    report = read_dashboard_data(root)["report"]
    assert "Test outcome: **TIMEOUT**" in report
    assert "complete verification: no" in report
    assert_no_runner_temps(root)


def test_test_execution_exception_is_error_not_security_failure(project):
    root, requirement_id = project
    test_file = write_test(root, "test_broken.py", "def test_broken():\n    raise RuntimeError('test harness broke')\n")

    result = run_approved_test(root, requirement_id, test_file, "test_broken", verification_complete=True)

    assert result["outcome"] == "ERROR"
    assert result["status"] == "IDENTIFIED"
    assert result["verification_complete"] is False
    assert "Test outcome: **ERROR**" in read_dashboard_data(root)["report"]
    assert_no_runner_temps(root)


def assert_no_runner_temps(root: Path) -> None:
    evidence_dir = root / ".securetrace" / "evidence"
    assert not list(evidence_dir.glob(".pytest-*.xml"))
    assert not list(evidence_dir.glob(".pytest-config-*.ini"))
    assert not list(evidence_dir.glob(".evidence-*.tmp"))


def test_invalid_path_and_path_traversal_are_rejected(project):
    root, _ = project
    with pytest.raises(ValueError, match="safe project-relative"):
        validate_test_target(root, "../outside.py", "test_bad")
    with pytest.raises(ValueError, match="under tests"):
        validate_test_target(root, "app/private_test.py", "test_bad")
    with pytest.raises(ValueError, match="safe project-relative"):
        validate_test_target(root, str(root / "tests" / "test_bad.py"), "test_bad")


def test_symlink_cannot_escape_project_root(project):
    root, _ = project
    outside = root.parent / "outside_test.py"
    outside.write_text("def test_escape(): pass\n", encoding="utf-8")
    link = root / "tests" / "test_escape.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation is unsupported by this environment: {exc}")
    with pytest.raises(ValueError, match="outside the project root"):
        validate_test_target(root, "tests/test_escape.py", "test_escape")


@pytest.mark.parametrize(
    "requirement_id",
    ["SEC-00000000", "SEC-malformed", "SEC-" + "A" * 100],
)
def test_requirement_validation_rejects_before_subprocess(project, monkeypatch, requirement_id):
    root, _ = project
    test_file = write_test(root, "test_never_run.py", "def test_never_run():\n    assert True\n")

    def forbidden_popen(*args, **kwargs):
        raise AssertionError("subprocess must not start for a rejected requirement")

    monkeypatch.setattr(runner.subprocess, "Popen", forbidden_popen)
    with pytest.raises(ValueError, match="Requirement ID|Unknown requirement"):
        run_approved_test(root, requirement_id, test_file, "test_never_run")
    snapshot = read_dashboard_data(root)
    assert snapshot["details"][next(iter(snapshot["details"]))]["checks"] == []
    assert not (root / ".securetrace" / "evidence").exists()


@pytest.mark.parametrize(
    ("test_id", "timeout", "output_limit"),
    [("invalid-name", 5, 100), ("test_valid", 0, 100), ("test_valid", float("nan"), 100),
     ("test_valid", 5, 0), ("test_valid", 5, 16_385)],
)
def test_other_runner_inputs_are_validated_before_launch(project, monkeypatch, test_id, timeout, output_limit):
    root, requirement_id = project
    test_file = write_test(root, "test_validation.py", "def test_valid():\n    assert True\n")

    def forbidden_popen(*args, **kwargs):
        raise AssertionError("subprocess must not start for an invalid runner input")

    monkeypatch.setattr(runner.subprocess, "Popen", forbidden_popen)
    with pytest.raises(ValueError):
        run_approved_test(root, requirement_id, test_file, test_id,
                          timeout_seconds=timeout, max_output_bytes=output_limit)
    assert not (root / ".securetrace" / "evidence").exists()


def test_hostile_pytest_environment_and_parent_config_are_neutralized(project, monkeypatch):
    root, requirement_id = project
    (root / "tests" / "conftest.py").write_text(
        "import pytest\n@pytest.fixture\ndef approved_here():\n    return True\n",
        encoding="utf-8",
    )
    test_file = write_test(root, "test_env.py", "def test_env(approved_here):\n    assert approved_here is True\n")
    (root / "pyproject.toml").write_text(
        "[project]\nname='runner-fixture'\n[tool.pytest.ini_options]\naddopts='--collect-only'\n",
        encoding="utf-8",
    )
    (root / "conftest.py").write_text(
        "raise RuntimeError('parent conftest must not load')\n", encoding="utf-8",
    )
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "definitely_missing_hostile_plugin")
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "0")
    monkeypatch.setenv("PYTHONPATH", "C:/hostile/pythonpath")

    result = run_approved_test(root, requirement_id, test_file, "test_env", verification_complete=True)

    assert result["outcome"] == "PASSED"
    assert "1 passed" in result["output"]
    assert result["execution"]["process_started"] is True
    assert_no_runner_temps(root)


def test_collection_import_error_is_error_not_regression(project):
    root, requirement_id = project
    test_file = write_test(
        root, "test_import_error.py",
        "import securetrace_module_that_does_not_exist\ndef test_import_error():\n    assert True\n",
    )

    result = run_approved_test(root, requirement_id, test_file, "test_import_error", verification_complete=True)

    assert result["outcome"] == "ERROR"
    assert result["execution"]["exit_code"] != 0
    assert result["status"] == "IDENTIFIED"
    assert result["verification_complete"] is False
    assert "Test outcome: **ERROR**" in read_dashboard_data(root)["report"]


def test_process_start_error_is_recorded_as_error_and_cleans_temps(project, monkeypatch):
    root, requirement_id = project
    test_file = write_test(root, "test_start_error.py", "def test_start_error():\n    assert True\n")
    monkeypatch.setattr(
        runner.subprocess, "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("process creation denied")),
    )

    result = run_approved_test(root, requirement_id, test_file, "test_start_error", verification_complete=True)

    assert result["outcome"] == "ERROR"
    assert result["execution"]["process_started"] is False
    assert result["execution"]["runner_error_type"] == "OSError"
    assert result["verification_complete"] is False
    assert result["status"] == "IDENTIFIED"
    assert_no_runner_temps(root)


def test_timeout_kills_child_process_tree(project):
    root, requirement_id = project
    pid_file = root / "child.pid"
    marker = root / "child-survived.txt"
    child_code = (
        f"import time,pathlib; time.sleep(2.5); "
        f"pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    test_file = write_test(
        root, "test_child_timeout.py",
        "import subprocess,sys,time,pathlib\n"
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n"
        "time.sleep(30)\n",
    )

    result = run_approved_test(root, requirement_id, test_file, "test_child_timeout", timeout_seconds=2.0)
    assert result["outcome"] == "TIMEOUT"
    assert result["execution"]["process_tree_cleanup_succeeded"] is True
    assert pid_file.exists(), "the approved test must have started its child before timeout"
    time.sleep(3.0)
    assert not marker.exists(), "a child process survived the runner timeout"
    assert_no_runner_temps(root)


def test_output_and_ledger_persistence_failures_are_explicit(project, monkeypatch):
    root, requirement_id = project
    test_file = write_test(root, "test_persist.py", "def test_persist():\n    assert True\n")
    monkeypatch.setattr(runner, "_save_evidence", lambda *args: (_ for _ in ()).throw(OSError("disk full")))

    result = run_approved_test(root, requirement_id, test_file, "test_persist", verification_complete=True)

    assert result["outcome"] == "ERROR"
    assert result["execution"]["evidence_persisted"] is False
    assert result["execution"]["evidence_ref"] is None
    assert result["persistence_error"]
    assert result["verification_complete"] is False
    assert result["status"] == "IDENTIFIED"
    assert "Test outcome: **ERROR**" in read_dashboard_data(root)["report"]


def test_ledger_write_failure_reports_orphan_evidence(project, monkeypatch):
    root, requirement_id = project
    test_file = write_test(root, "test_orphan.py", "def test_orphan():\n    assert True\n")

    def fail_ledger(*args, **kwargs):
        raise sqlite3.OperationalError("database unavailable")

    monkeypatch.setattr(runner, "record_test_check", fail_ledger)
    with pytest.raises(EvidencePersistenceError, match="Orphan evidence") as caught:
        run_approved_test(root, requirement_id, test_file, "test_orphan", verification_complete=True)

    assert "ledger recording failed" in str(caught.value)
    assert len(list((root / ".securetrace" / "evidence").glob("*.txt"))) == 1
    assert read_dashboard_data(root)["details"][requirement_id]["checks"] == []
    assert_no_runner_temps(root)


def test_cli_reports_ledger_failure_without_success_response(project, monkeypatch, capsys):
    root, requirement_id = project
    test_file = write_test(root, "test_cli_failure.py", "def test_cli_failure():\n    assert True\n")
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(root))
    monkeypatch.setattr(
        sys, "argv",
        ["securetrace", "run-test", "--approve", "--requirement", requirement_id,
         "--test-file", test_file, "--test-id", "test_cli_failure", "--complete"],
    )
    monkeypatch.setattr(
        runner, "run_approved_test",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            EvidencePersistenceError("Execution outcome PASSED; ledger recording failed. Orphan evidence: /tmp/evidence.txt")
        ),
    )

    with pytest.raises(SystemExit) as exited:
        cli.main()

    captured = capsys.readouterr()
    assert exited.value.code == 2
    assert "Evidence persistence error" in captured.err
    assert "Orphan evidence" in captured.err
    assert "PASSED -> VERIFIED" not in captured.out


def test_test_file_modified_during_run_invalidates_result(project, monkeypatch):
    root, requirement_id = project
    test_file = write_test(root, "test_mutated.py", "def test_mutated():\n    assert True\n")
    original_popen = subprocess.Popen

    def mutate_before_start(*args, **kwargs):
        (root / test_file).write_text("def test_mutated():\n    assert True\n# changed\n", encoding="utf-8")
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(runner.subprocess, "Popen", mutate_before_start)
    result = run_approved_test(root, requirement_id, test_file, "test_mutated", verification_complete=True)
    assert result["outcome"] == "ERROR"
    assert result["execution"]["test_file_changed"] is True
    assert result["verification_complete"] is False
    assert result["status"] == "IDENTIFIED"


def test_output_is_bounded_and_common_secrets_are_redacted(project):
    root, requirement_id = project
    test_file = write_test(
        root, "test_noisy.py",
        "def test_noisy():\n    print('password=super-secret ' + 'x' * 20000)\n    assert False\n",
    )

    result = run_approved_test(root, requirement_id, test_file, "test_noisy", max_output_bytes=512)

    assert result["outcome"] == "FAILED"
    assert result["execution"]["output_truncated"] is True
    assert result["execution"]["output_bytes_captured"] <= 512
    assert "super-secret" not in result["output"]
    assert "[REDACTED]" in result["output"]
    saved = (root / result["execution"]["evidence_ref"]).read_text(encoding="utf-8")
    assert "super-secret" not in saved
    assert "output truncated" in saved


def test_manual_recording_remains_backward_compatible_and_labeled(project):
    root, requirement_id = project
    result = record_check(root, requirement_id, "manual-review", True, "Reviewed by a human.",
                          verification_complete=False)
    assert result["result"] == "PASSED"
    assert result["status"] == "IMPLEMENTED"
    report = read_dashboard_data(root)["report"]
    assert "manually recorded check" in report
    assert "automatically executed test" not in report


def test_fixed_sample_authorization_tests_pass_and_vulnerable_control_fails(tmp_path: Path):
    # This test invokes the checked-in, isolated sample as real subprocess tests.
    root = tmp_path
    (root / "pyproject.toml").write_text("[project]\nname='authorization-demo'\n", encoding="utf-8")
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "examples" / "authorization_demo",
        root / "examples" / "authorization_demo",
        ignore=shutil.ignore_patterns(".securetrace", "__pycache__", ".pytest_cache"),
    )
    (root / "tests").mkdir()
    requirement = add_requirement(root, "Demo owner-only cancellation", "Only owners may cancel.",
                                  category="authorization", severity="high")
    passing = run_approved_test(
        root, requirement["id"], "examples/authorization_demo/tests/test_authorization.py",
        "test_other_user_cannot_cancel_appointment", verification_complete=True,
    )
    assert passing["outcome"] == "PASSED"
    failing = run_approved_test(
        root, requirement["id"], "examples/authorization_demo/tests/test_vulnerable_authorization.py",
        "test_other_user_cannot_cancel_appointment_on_vulnerable_control",
    )
    assert failing["outcome"] == "FAILED"
    assert failing["status"] == "REGRESSION"


def test_historical_unmarked_check_rows_remain_manual(project):
    root, requirement_id = project
    with connect(root) as db:
        db.execute(
            """INSERT INTO checks
               (requirement_id, check_name, result, verification_complete, details, ran_at)
               VALUES (?, ?, 'PASSED', 0, ?, ?)""",
            (requirement_id, "pre-runner-check", "Historical manual evidence.", now_iso()),
        )
    snapshot = read_dashboard_data(root)
    assert "manually recorded check" in snapshot["report"]
    assert "Historical manual evidence." in snapshot["report"]
    assert "automatically executed test" not in snapshot["report"]
    assert snapshot["details"][requirement_id]["checks"][0]["details"] == "Historical manual evidence."


def test_manual_record_check_stores_provenance_without_changing_api(project):
    root, requirement_id = project
    result = record_check(root, requirement_id, "old-client-check", False, "Recorded by old API.")
    assert result["result"] == "FAILED"
    assert result["status"] == "REGRESSION"
    row = read_dashboard_data(root)["details"][requirement_id]["checks"][0]
    assert row["provenance"] == "manual"
    assert row["details"] == "Recorded by old API."
