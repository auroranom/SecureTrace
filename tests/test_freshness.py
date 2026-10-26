from pathlib import Path

from securetrace.db import connect
from securetrace.freshness import assess_mapping_freshness, fingerprint_source_state
from securetrace.ledger import (
    add_requirement, analyze_change_impact, current_verification_plan,
    get_requirement_detail, list_requirement_tests, map_requirement_test,
    record_check,
)
from securetrace.reporting import render_report
from securetrace.test_runner import run_approved_test


def setup_project(root: Path, *, files=("app.py",)):
    (root / "pyproject.toml").write_text("[project]\nname='freshness-demo'\n", encoding="utf-8")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_access.py").write_text("def test_access():\n    assert True\n", encoding="utf-8")
    (root / "app.py").write_text("ACCESS = True\n", encoding="utf-8")
    requirement = add_requirement(root, "Owner access", "Only owners may access data.", file_paths=list(files))
    from securetrace.db import migrate_mappings
    migrate_mappings(root)
    mapping = map_requirement_test(root, requirement["id"], "tests/test_access.py", "test_access", verification_complete=True)
    return requirement, mapping


def execute(root: Path, requirement: dict):
    result = run_approved_test(root, requirement["id"], "tests/test_access.py", "test_access", verification_complete=True)
    assert result["outcome"] == "PASSED"
    assert result["execution"]["source_fingerprint_before"]["complete"] is True
    assert result["execution"]["source_state_stable"] is True
    return result


def test_unchanged_content_is_current_even_if_timestamp_changes(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    execute(tmp_path, requirement)
    (tmp_path / "app.py").touch()
    plan = current_verification_plan(tmp_path)
    assert plan[0]["evidence_freshness"] == "CURRENT"
    assert plan[0]["selected"] is False


def test_modified_content_is_stale_and_plan_has_selection_reason(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    execute(tmp_path, requirement)
    (tmp_path / "app.py").write_text("ACCESS = False\n", encoding="utf-8")
    plan = current_verification_plan(tmp_path)[0]
    assert plan["requirement_id"] == requirement["id"]
    assert plan["test_file"] == "tests/test_access.py"
    assert plan["test_id"] == "test_access"
    assert plan["evidence_freshness"] == "STALE"
    assert plan["selected"] is True
    assert "contents differ" in plan["reason"]
    assert plan["blockers"] == []
    report = render_report(tmp_path)
    assert "Verification Plan" in report
    assert "Evidence freshness: **STALE**" in report


def test_modified_approved_test_file_is_in_impact_and_fingerprint(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    execute(tmp_path, requirement)
    test_file = tmp_path / "tests" / "test_access.py"
    test_file.write_text("def test_access():\n    assert 1 == 1\n", encoding="utf-8")
    impact = analyze_change_impact(tmp_path, ["tests/test_access.py"])
    assert len(impact["eligible_reruns"]) == 1
    assert impact["eligible_reruns"][0]["requirement_id"] == requirement["id"]
    assert impact["eligible_reruns"][0]["evidence_freshness"] == "STALE"


def test_deleted_relevant_file_is_unknown_with_blocker(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    execute(tmp_path, requirement)
    (tmp_path / "app.py").unlink()
    plan = current_verification_plan(tmp_path)[0]
    assert plan["evidence_freshness"] == "UNKNOWN"
    assert any("app.py: MISSING" in blocker for blocker in plan["blockers"])
    assert plan["selected"] is True


def test_added_linked_file_after_run_invalidates_recorded_path_set(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    execute(tmp_path, requirement)
    new_file = tmp_path / "new_policy.py"
    new_file.write_text("POLICY = 'new'\n", encoding="utf-8")
    with connect(tmp_path) as db:
        db.execute("INSERT INTO requirement_files(requirement_id,file_path) VALUES(?,?)",
                   (requirement["id"], "new_policy.py"))
    plan = current_verification_plan(tmp_path)[0]
    assert plan["evidence_freshness"] == "STALE"
    assert plan["selected"] is True


def test_untracked_relevant_file_is_fingerprinted_and_changes_make_stale(tmp_path: Path):
    untracked = tmp_path / "untracked_policy.py"
    untracked.write_text("POLICY = 'initial'\n", encoding="utf-8")
    requirement, _ = setup_project(tmp_path, files=("app.py", "untracked_policy.py"))
    execute(tmp_path, requirement)
    snapshot = get_requirement_detail(tmp_path, requirement["id"])["checks"][0]
    import json
    metadata = json.loads(snapshot["details"])
    assert metadata["source_fingerprint_before"]["files"]["untracked_policy.py"]["state"] == "PRESENT"
    untracked.write_text("POLICY = 'changed'\n", encoding="utf-8")
    assert current_verification_plan(tmp_path)[0]["evidence_freshness"] == "STALE"


def test_unreadable_relevant_file_is_unknown_when_permission_error_can_be_simulated(tmp_path: Path, monkeypatch):
    requirement, mapping = setup_project(tmp_path)
    execute(tmp_path, requirement)
    original_open = Path.open

    def denied(path, *args, **kwargs):
        if path.name == "app.py":
            raise PermissionError("denied for test")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    current = fingerprint_source_state(tmp_path, ["app.py", "tests/test_access.py"])
    assert current["files"]["app.py"]["state"] == "UNREADABLE"
    plan = assess_mapping_freshness(tmp_path, requirement, mapping,
                                    get_requirement_detail(tmp_path, requirement["id"])["checks"])
    assert plan["evidence_freshness"] == "UNKNOWN"
    assert any("app.py: UNREADABLE" in blocker for blocker in plan["blockers"])


def test_shared_file_selects_each_linked_requirement(tmp_path: Path):
    first, _ = setup_project(tmp_path)
    second = add_requirement(tmp_path, "Audit access", "Audit access controls.", file_paths=["app.py"])
    map_requirement_test(tmp_path, second["id"], "tests/test_access.py", "test_access", verification_complete=True)
    impact = analyze_change_impact(tmp_path, ["app.py"])
    assert {item["requirement_id"] for item in impact["verification_plan"]} == {first["id"], second["id"]}
    assert len(impact["eligible_reruns"]) == 2


def test_unrelated_file_does_not_change_freshness_or_select_a_check(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    execute(tmp_path, requirement)
    (tmp_path / "unrelated.py").write_text("X = 1\n", encoding="utf-8")
    assert analyze_change_impact(tmp_path, ["unrelated.py"])["verification_plan"] == []
    plan = current_verification_plan(tmp_path)[0]
    assert plan["evidence_freshness"] == "CURRENT"
    assert plan["selected"] is False


def test_legacy_and_manual_evidence_have_unknown_freshness_without_rewriting_history(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    manual = record_check(tmp_path, requirement["id"], "manual-review", passed=True,
                          verification_complete=True, details="reviewed by owner")
    plan = current_verification_plan(tmp_path)[0]
    assert plan["evidence_freshness"] == "UNKNOWN"
    assert "No automated execution evidence" in plan["reason"]
    checks = get_requirement_detail(tmp_path, requirement["id"])["checks"]
    assert len(checks) == 1
    assert checks[0]["details"] == "reviewed by owner"
    assert checks[0]["provenance"] == "manual"


def test_changed_fingerprint_preserves_original_execution_record(tmp_path: Path):
    requirement, _ = setup_project(tmp_path)
    result = execute(tmp_path, requirement)
    original = result["execution"]["source_fingerprint_before"]["digest"]
    (tmp_path / "app.py").write_text("ACCESS = 'modified'\n", encoding="utf-8")
    checks = get_requirement_detail(tmp_path, requirement["id"])["checks"]
    import json
    old_metadata = json.loads(checks[0]["details"])
    assert old_metadata["source_fingerprint_before"]["digest"] == original
    assert len(checks) == 1
    assert current_verification_plan(tmp_path)[0]["evidence_freshness"] == "STALE"
