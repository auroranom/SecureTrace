from pathlib import Path

import pytest

from securetrace.db import connect, migrate_mappings
from securetrace.ledger import (
    add_requirement, analyze_change_impact, list_requirement_tests,
    map_requirement_test, mark_changed_files,
)
from securetrace.test_runner import run_approved_test


@pytest.fixture
def mapped_project(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='impact-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_access.py").write_text(
        "def test_access():\n    assert True\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("ACCESS = True\n", encoding="utf-8")
    migrate_mappings(tmp_path)
    return tmp_path


def test_requirement_maps_only_valid_approved_test(mapped_project: Path):
    req = add_requirement(mapped_project, "Owner access", "Only owners may access records.", file_paths=["app.py"])
    mapped = map_requirement_test(mapped_project, req["id"], "tests/test_access.py", "test_access", verification_complete=True)
    assert mapped["test_file"] == "tests/test_access.py"
    assert mapped["verification_complete"] is True
    assert list_requirement_tests(mapped_project, req["id"])[0]["test_id"] == "test_access"
    with pytest.raises(ValueError, match="safe project-relative"):
        map_requirement_test(mapped_project, req["id"], "../outside.py", "test_escape")
    with pytest.raises(ValueError, match="not mapped"):
        run_approved_test(mapped_project, req["id"], "tests/test_access.py", "test_other")


def test_change_impact_is_linked_deterministic_and_does_not_execute(mapped_project: Path, monkeypatch):
    import securetrace.test_runner as runner
    monkeypatch.setattr(runner, "subprocess", type("NoSubprocess", (), {"Popen": staticmethod(lambda *a, **k: pytest.fail("executed automatically"))}))
    first = add_requirement(mapped_project, "Owner access", "Check owner", file_paths=["app.py"])
    second = add_requirement(mapped_project, "Audit access", "Audit owner", file_paths=["app.py"])
    unrelated = add_requirement(mapped_project, "Secrets", "Protect keys", file_paths=["secrets.py"])
    for req in (first, second):
        map_requirement_test(mapped_project, req["id"], "tests/test_access.py", "test_access")
    impact = analyze_change_impact(mapped_project, ["app.py"])
    assert [r["requirement_id"] for r in impact["requirements"]] == sorted([first["id"], second["id"]])
    assert len(impact["eligible_reruns"]) == 2
    assert all(row["test_id"] == "test_access" for row in impact["eligible_reruns"])
    assert not any(row["requirement_id"] == unrelated["id"] for row in impact["requirements"])
    changed = mark_changed_files(mapped_project, ["app.py"])
    assert len(changed) == 2
    assert all(row["evidence_stale"] is False for row in changed)
    assert all(row["historical_runs_preserved"] == 0 for row in changed)


def test_stale_history_retained_and_rerun_adds_new_evidence(mapped_project: Path):
    req = add_requirement(mapped_project, "Owner access", "Only owner", file_paths=["app.py"])
    map_requirement_test(mapped_project, req["id"], "tests/test_access.py", "test_access", verification_complete=True)
    first = run_approved_test(mapped_project, req["id"], "tests/test_access.py", "test_access", verification_complete=True)
    assert first["outcome"] == "PASSED"
    proposal = analyze_change_impact(mapped_project, ["app.py"])
    assert proposal["requirements"][0]["evidence_freshness"] == "CURRENT"
    assert proposal["eligible_reruns"] == []
    stale = mark_changed_files(mapped_project, ["app.py"])[0]
    assert stale["evidence_freshness"] == "CURRENT"
    assert stale["evidence_stale"] is False
    assert stale["historical_runs_preserved"] == 1
    second = run_approved_test(mapped_project, req["id"], "tests/test_access.py", "test_access", verification_complete=True)
    assert second["status"] == "VERIFIED"
    from securetrace.ledger import get_requirement_detail
    detail = get_requirement_detail(mapped_project, req["id"])
    assert len(detail["checks"]) == 2
    assert detail["checks"][0]["result"] == "PASSED"
    assert detail["checks"][1]["result"] == "PASSED"


def test_mapping_migration_is_explicit_and_backward_compatible(tmp_path: Path):
    add_requirement(tmp_path, "Legacy", "Existing requirement")
    with connect(tmp_path) as db:
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='requirement_tests'").fetchone() is None
    migrate_mappings(tmp_path)
    with connect(tmp_path) as db:
        assert db.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM requirement_tests").fetchone()[0] == 0
