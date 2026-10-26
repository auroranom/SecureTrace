from __future__ import annotations

from pathlib import Path
import pytest

from securetrace.http_probe import HttpProbeSpec, ProbeEvaluationResult, ProbeVerdict
from securetrace.ledger import add_requirement, get_requirement_detail
import securetrace.mcp_server as mcp_server


def test_mark_changed_files_calls_ledger_function(monkeypatch, tmp_path: Path):
    expected_root = tmp_path.resolve()
    expected_paths = ["examples/example.py"]
    expected_affected = [
        {
            "requirement_id": "SEC-TEST",
            "changed_files": expected_paths,
        }
    ]

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(expected_root))

    calls = {}

    def fake_ledger_mark_changed_files(root, changed_paths):
        calls["root"] = root
        calls["changed_paths"] = changed_paths
        return expected_affected

    monkeypatch.setattr(
        mcp_server,
        "ledger_mark_changed_files",
        fake_ledger_mark_changed_files,
    )

    result = mcp_server.mark_changed_files(expected_paths)

    assert calls["root"] == expected_root
    assert calls["changed_paths"] == expected_paths
    assert result == {
        "affected_requirements": expected_affected,
        "count": 1,
    }


def test_probe_endpoint_security_requires_explicit_approval(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    # When approved=False (default), it must return plan without running
    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=False)
    assert result["status"] == "APPROVAL_REQUIRED"
    assert "Explicit user approval is required" in result["message"]
    assert result["plan"]["target_url"] == "http://127.0.0.1:8095/doner"
    assert result["plan"]["requirement_id"] == req_id

    # Ledger must have zero checks recorded
    detail = get_requirement_detail(tmp_path, req_id)
    assert len(detail["checks"]) == 0


def test_probe_endpoint_security_validates_inputs(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    # Non-existent requirement
    with pytest.raises(ValueError, match="Unknown requirement"):
        mcp_server.probe_endpoint_security("SEC-00000000", port=8095)

    # Privileged port or out-of-range port
    with pytest.raises(ValueError, match="unprivileged integer"):
        mcp_server.probe_endpoint_security(req_id, port=80)
    with pytest.raises(ValueError, match="unprivileged integer"):
        mcp_server.probe_endpoint_security(req_id, port=70000)

    # Path traversal / invalid path
    with pytest.raises(ValueError, match="clean project route"):
        mcp_server.probe_endpoint_security(req_id, port=8095, path="/../etc/passwd")
    with pytest.raises(ValueError, match="clean project route"):
        mcp_server.probe_endpoint_security(req_id, port=8095, path="C:\\test")


def test_probe_endpoint_security_records_vulnerable_as_regression(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.VULNERABLE,
        status_code=200,
        explanation="HTTP 200 exposed protected donor table content.",
        safe_headers={"content-type": "text/html"},
        body_byte_count=1234,
        body_sha256="abc123hash",
        matched_indicators=("donor", "table"),
        ledger_outcome="FAILED",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verdict"] == "VULNERABLE"
    assert result["requirement_status"] == "REGRESSION"
    assert result["evidence_recorded"]["ledger_outcome"] == "FAILED"
    assert result["evidence_recorded"]["verification_complete"] is False

    detail = get_requirement_detail(tmp_path, req_id)
    assert detail["status"] == "REGRESSION"
    assert len(detail["checks"]) == 1
    assert detail["checks"][0]["result"] == "FAILED"


def test_probe_endpoint_security_secure_for_this_check_does_not_verify(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.SECURE_FOR_THIS_CHECK,
        status_code=302,
        explanation="Unauthenticated request was redirected to login: '/login'.",
        safe_headers={"location": "/login"},
        body_byte_count=0,
        body_sha256="emptyhash",
        matched_indicators=(),
        ledger_outcome="PASSED",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verdict"] == "SECURE_FOR_THIS_CHECK"
    assert result["evidence_recorded"]["ledger_outcome"] == "PASSED"
    assert result["evidence_recorded"]["verification_complete"] is False

    detail = get_requirement_detail(tmp_path, req_id)
    # Crucial: Must NEVER be VERIFIED from a single endpoint check!
    assert detail["status"] != "VERIFIED"
    assert len(detail["checks"]) == 1
    assert detail["checks"][0]["result"] == "PASSED"
    assert detail["checks"][0]["verification_complete"] == 0


def test_probe_endpoint_security_inconclusive_does_not_modify_status(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.INCONCLUSIVE,
        status_code=500,
        explanation="Server error HTTP 500.",
        safe_headers={},
        body_byte_count=0,
        body_sha256="",
        matched_indicators=(),
        ledger_outcome="ERROR",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    result = mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verdict"] == "INCONCLUSIVE"

    detail = get_requirement_detail(tmp_path, req_id)
    assert detail["status"] == "IDENTIFIED"
    assert len(detail["checks"]) == 1
    assert detail["checks"][0]["result"] == "ERROR"


def test_probe_endpoint_security_never_persists_pii_or_body(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    req = add_requirement(tmp_path, "Admin routes lack auth", "Desc", "authorization", "high")
    req_id = req["id"]

    fake_eval = ProbeEvaluationResult(
        verdict=ProbeVerdict.VULNERABLE,
        status_code=200,
        explanation="HTTP 200 exposed donor table.",
        safe_headers={"content-type": "text/html"},
        body_byte_count=500,
        body_sha256="sensitivehash123",
        matched_indicators=("donor",),
        ledger_outcome="FAILED",
        verification_complete=False,
    )
    monkeypatch.setattr(mcp_server, "dispatch_probe", lambda spec: fake_eval)

    mcp_server.probe_endpoint_security(req_id, port=8095, path="/doner", approved=True)

    detail = get_requirement_detail(tmp_path, req_id)
    check_raw = str(detail["checks"][0])
    events_raw = str(detail["events"])

    # Ensure no PII indicators or body fragments leaked into stored database records
    assert "password" not in check_raw.lower()
    assert "cookie" not in check_raw.lower()
    assert "token" not in check_raw.lower()
    assert "password" not in events_raw.lower()


def test_get_change_impact_identifies_affected_requirement(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "app.py").write_text("print('hello')", encoding="utf-8")
    req = add_requirement(
        tmp_path,
        "Customer auth",
        "Must authenticate",
        category="authentication",
        severity="high",
        file_paths=["app.py"],
    )

    result = mcp_server.get_change_impact(["app.py"])
    assert result["repository"] == str(tmp_path.resolve())
    assert result["changed_files"] == ["app.py"]
    assert len(result["affected_requirements"]) == 1
    req_impact = result["affected_requirements"][0]
    assert req_impact["requirement_id"] == req["id"]
    assert req_impact["title"] == "Customer auth"
    assert req_impact["severity"] == "high"
    assert result["dependency_coverage"] in {"LOCAL_STATIC_IMPORTS", "INCOMPLETE"}
    assert "depend" in result["coverage_limitations"].lower()
    assert "dry-run" in result["notice"].lower()


def test_get_change_impact_identifies_mapped_tests(monkeypatch, tmp_path: Path):
    from securetrace.db import migrate_mappings
    from securetrace.ledger import map_requirement_test

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text("def test_auth(): assert True\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("AUTH = True\n", encoding="utf-8")
    migrate_mappings(tmp_path)

    req = add_requirement(tmp_path, "Auth control", "Verify auth", file_paths=["app.py"])
    map_requirement_test(tmp_path, req["id"], "tests/test_auth.py", "test_auth", verification_complete=True)

    result = mcp_server.get_change_impact(["app.py"])
    assert len(result["affected_requirements"]) == 1
    assert len(result["mapped_tests"]) == 1
    mapped = result["mapped_tests"][0]
    assert mapped["requirement_id"] == req["id"]
    assert mapped["test_file"] == "tests/test_auth.py"
    assert mapped["test_id"] == "test_auth"
    assert mapped["verification_complete"] is True


def test_get_change_impact_multiple_changed_files(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "app.py").write_text("pass", encoding="utf-8")
    (tmp_path / "routes.py").write_text("pass", encoding="utf-8")
    (tmp_path / "secrets.py").write_text("pass", encoding="utf-8")

    req1 = add_requirement(tmp_path, "App control", "App desc", file_paths=["app.py"])
    req2 = add_requirement(tmp_path, "Route control", "Route desc", file_paths=["routes.py"])
    req_unrelated = add_requirement(tmp_path, "Secrets control", "Secret desc", file_paths=["secrets.py"])

    result = mcp_server.get_change_impact(["app.py", "./routes.py", "app.py"])
    assert result["changed_files"] == ["app.py", "routes.py"]
    affected_ids = {r["requirement_id"] for r in result["affected_requirements"]}
    assert affected_ids == {req1["id"], req2["id"]}
    assert req_unrelated["id"] not in affected_ids


def test_get_change_impact_validates_empty_and_invalid_inputs(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))

    # Non-list inputs
    with pytest.raises(ValueError, match="list of project-relative file paths"):
        mcp_server.get_change_impact("app.py")  # type: ignore
    with pytest.raises(ValueError, match="list of project-relative file paths"):
        mcp_server.get_change_impact(None)  # type: ignore
    with pytest.raises(ValueError, match="list of project-relative file paths"):
        mcp_server.get_change_impact(123)  # type: ignore

    # Empty list
    with pytest.raises(ValueError, match="cannot be empty"):
        mcp_server.get_change_impact([])

    # List with invalid elements
    with pytest.raises(ValueError, match="non-empty string"):
        mcp_server.get_change_impact([""])
    with pytest.raises(ValueError, match="non-empty string"):
        mcp_server.get_change_impact(["   "])
    with pytest.raises(ValueError, match="non-empty string"):
        mcp_server.get_change_impact([None])  # type: ignore
    with pytest.raises(ValueError, match="non-empty string"):
        mcp_server.get_change_impact([123])  # type: ignore
    with pytest.raises(ValueError, match="Invalid file path"):
        mcp_server.get_change_impact(["app\x00.py"])

    # Resolving to root directory itself
    with pytest.raises(ValueError, match="project root itself"):
        mcp_server.get_change_impact(["."])


def test_get_change_impact_rejects_paths_escaping_project_root(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))

    # Path traversal with parent directory
    with pytest.raises(ValueError, match="escapes the project root"):
        mcp_server.get_change_impact(["../outside.py"])

    with pytest.raises(ValueError, match="escapes the project root"):
        mcp_server.get_change_impact(["subdir/../../outside.py"])

    # Absolute path outside root
    with pytest.raises(ValueError, match="escapes the project root"):
        mcp_server.get_change_impact(["C:/Windows/System32/calc.exe"])


def test_get_change_impact_is_strictly_read_only(monkeypatch, tmp_path: Path):
    import subprocess
    from securetrace.db import connect

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    test_file = tmp_path / "app.py"
    test_file.write_text("INITIAL_CONTENT = True\n", encoding="utf-8")
    initial_mtime = test_file.stat().st_mtime_ns

    req = add_requirement(tmp_path, "Integrity check", "Check desc", file_paths=["app.py"])

    # Ensure subprocess cannot be executed
    def fail_on_subprocess(*args, **kwargs):
        pytest.fail("Subprocess execution was attempted during change impact analysis!")

    monkeypatch.setattr(subprocess, "Popen", fail_on_subprocess)
    monkeypatch.setattr(subprocess, "run", fail_on_subprocess)

    # Record database counts before
    with connect(tmp_path) as db:
        checks_count_before = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        events_count_before = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        req_status_before = db.execute("SELECT status FROM requirements WHERE id=?", (req["id"],)).fetchone()[0]

    # Run get_change_impact
    result = mcp_server.get_change_impact(["app.py"])
    assert len(result["affected_requirements"]) == 1

    # Verify no database mutations
    with connect(tmp_path) as db:
        checks_count_after = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        events_count_after = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        req_status_after = db.execute("SELECT status FROM requirements WHERE id=?", (req["id"],)).fetchone()[0]

    assert checks_count_after == checks_count_before == 0
    assert events_count_after == events_count_before
    assert req_status_after == req_status_before == "IDENTIFIED"

    # Verify file content and mtime on disk are untouched
    assert test_file.read_text(encoding="utf-8") == "INITIAL_CONTENT = True\n"
    assert test_file.stat().st_mtime_ns == initial_mtime


def test_get_verification_plan_generation(monkeypatch, tmp_path: Path):
    from securetrace.db import migrate_mappings
    from securetrace.ledger import map_requirement_test

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='plan-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_plan.py").write_text("def test_item(): assert True\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    migrate_mappings(tmp_path)

    req = add_requirement(tmp_path, "Plan requirement", "Ensure planning works", file_paths=["app.py"])
    map_requirement_test(tmp_path, req["id"], "tests/test_plan.py", "test_item", verification_complete=True)

    result = mcp_server.get_verification_plan()
    assert result["repository"] == str(tmp_path.resolve())
    assert result["total_checks"] == 1
    assert len(result["plan"]) == 1
    assert result["dependency_coverage"] in {"LOCAL_STATIC_IMPORTS", "INCOMPLETE"}
    assert "depend" in result["coverage_limitations"].lower()
    assert "dry-run" in result["notice"].lower()


def test_get_verification_plan_associations(monkeypatch, tmp_path: Path):
    from securetrace.db import migrate_mappings
    from securetrace.ledger import map_requirement_test

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='plan-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text("def test_auth_check(): assert True\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    migrate_mappings(tmp_path)

    req = add_requirement(tmp_path, "Auth req", "Desc", file_paths=["app.py"])
    map_requirement_test(tmp_path, req["id"], "tests/test_auth.py", "test_auth_check", verification_complete=True)

    result = mcp_server.get_verification_plan(requirement_id=req["id"])
    assert result["requirement_id"] == req["id"]
    assert result["total_checks"] == 1
    item = result["plan"][0]
    assert item["requirement_id"] == req["id"]
    assert item["test_file"] == "tests/test_auth.py"
    assert item["test_id"] == "test_auth_check"
    assert item["mapping_verification_complete"] is True


def test_get_verification_plan_current_vs_stale(monkeypatch, tmp_path: Path):
    from securetrace.db import migrate_mappings
    from securetrace.ledger import map_requirement_test
    from securetrace.test_runner import run_approved_test

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='plan-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_run.py").write_text("def test_run(): assert True\n", encoding="utf-8")
    app_file = tmp_path / "app.py"
    app_file.write_text("INITIAL = True\n", encoding="utf-8")
    migrate_mappings(tmp_path)

    req = add_requirement(tmp_path, "Freshness req", "Desc", file_paths=["app.py"])
    map_requirement_test(tmp_path, req["id"], "tests/test_run.py", "test_run", verification_complete=True)

    # Run test once to create CURRENT evidence baseline
    run_approved_test(tmp_path, req["id"], "tests/test_run.py", "test_run", verification_complete=True)

    # 1. Fresh state
    fresh_plan = mcp_server.get_verification_plan()
    assert fresh_plan["total_checks"] == 1
    assert fresh_plan["eligible_count"] == 0
    assert fresh_plan["plan"][0]["evidence_freshness"] == "CURRENT"
    assert fresh_plan["plan"][0]["selected"] is False

    # 2. Modify app.py to cause STALE state
    app_file.write_text("MODIFIED = True\n", encoding="utf-8")

    stale_plan = mcp_server.get_verification_plan()
    assert stale_plan["total_checks"] == 1
    assert stale_plan["eligible_count"] == 1
    assert len(stale_plan["eligible_checks"]) == 1
    assert stale_plan["plan"][0]["evidence_freshness"] == "STALE"
    assert stale_plan["plan"][0]["selected"] is True
    assert "differ from the recorded execution fingerprint" in stale_plan["plan"][0]["reason"]


def test_get_verification_plan_empty_and_missing_requirements(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))

    # Empty project (no requirements)
    empty_result = mcp_server.get_verification_plan()
    assert empty_result["total_checks"] == 0
    assert empty_result["plan"] == []
    assert empty_result["eligible_checks"] == []

    # Requirement exists without mapped tests
    req = add_requirement(tmp_path, "Unmapped req", "Desc", file_paths=["app.py"])
    unmapped_result = mcp_server.get_verification_plan()
    assert unmapped_result["total_checks"] == 0
    assert unmapped_result["plan"] == []

    # Non-existent requirement filter
    with pytest.raises(ValueError, match="Unknown requirement"):
        mcp_server.get_verification_plan(requirement_id="SEC-NONEXISTENT")

    # Invalid requirement ID parameter
    with pytest.raises(ValueError, match="non-empty string"):
        mcp_server.get_verification_plan(requirement_id="")
    with pytest.raises(ValueError, match="non-empty string"):
        mcp_server.get_verification_plan(requirement_id="   ")


def test_get_verification_plan_is_strictly_read_only(monkeypatch, tmp_path: Path):
    import subprocess
    from securetrace.db import connect, migrate_mappings
    from securetrace.ledger import map_requirement_test

    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='plan-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_read.py").write_text("def test_read(): assert True\n", encoding="utf-8")
    app_file = tmp_path / "app.py"
    app_file.write_text("CONTENT = 1\n", encoding="utf-8")
    initial_mtime = app_file.stat().st_mtime_ns
    migrate_mappings(tmp_path)

    req = add_requirement(tmp_path, "Read only check", "Desc", file_paths=["app.py"])
    map_requirement_test(tmp_path, req["id"], "tests/test_read.py", "test_read", verification_complete=True)

    # Ensure subprocess is not invoked
    def fail_on_subprocess(*args, **kwargs):
        pytest.fail("Subprocess was invoked during verification planning!")

    monkeypatch.setattr(subprocess, "Popen", fail_on_subprocess)
    monkeypatch.setattr(subprocess, "run", fail_on_subprocess)

    with connect(tmp_path) as db:
        checks_before = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        events_before = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        status_before = db.execute("SELECT status FROM requirements WHERE id=?", (req["id"],)).fetchone()[0]

    result = mcp_server.get_verification_plan()
    assert result["total_checks"] == 1

    with connect(tmp_path) as db:
        checks_after = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        events_after = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        status_after = db.execute("SELECT status FROM requirements WHERE id=?", (req["id"],)).fetchone()[0]

    assert checks_after == checks_before == 0
    assert events_after == events_before
    assert status_after == status_before == "IDENTIFIED"
    assert app_file.read_text(encoding="utf-8") == "CONTENT = 1\n"
    assert app_file.stat().st_mtime_ns == initial_mtime


def test_get_verification_plan_preserves_existing_tools():
    registered_tools = set(mcp_server.mcp._tool_manager._tools.keys())
    expected_tools = {
        "list_security_requirements",
        "add_security_requirement",
        "record_security_check",
        "mark_changed_files",
        "get_security_report",
        "get_change_impact",
        "get_verification_plan",
        "probe_endpoint_security",
    }
    assert expected_tools.issubset(registered_tools)
    assert len(expected_tools) == 8


