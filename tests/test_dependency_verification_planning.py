"""Tests for Phase 3.4: Dependency-Aware Verification Planning."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pytest

from securetrace.db import connect, migrate_mappings
from securetrace.dependencies import build_local_dependency_graph
from securetrace.freshness import assess_mapping_freshness, build_verification_plan
from securetrace.ledger import (
    add_requirement,
    map_requirement_test,
    analyze_change_impact,
    current_verification_plan,
)
from securetrace.test_runner import run_approved_test
from securetrace.mcp_server import get_change_impact, get_verification_plan


@pytest.fixture
def plan_repo(tmp_path: Path) -> Path:
    """Create a minimal project repository with dependency structure."""
    with connect(tmp_path):
        pass
    migrate_mappings(tmp_path)

    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test-proj'\nversion = '0.1.0'\n", encoding="utf-8")

    # Create source modules
    (tmp_path / "models.py").write_text("class User:\n    pass\n", encoding="utf-8")
    (tmp_path / "auth.py").write_text("import models\ndef check_auth():\n    return True\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import auth\ndef run():\n    return auth.check_auth()\n", encoding="utf-8")
    (tmp_path / "unrelated.py").write_text("def log():\n    pass\n", encoding="utf-8")

    # Create tests
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "__init__.py").write_text("", encoding="utf-8")
    (test_dir / "fixtures.py").write_text("FIXTURE_USER = 'admin'\n", encoding="utf-8")
    (test_dir / "test_app.py").write_text(
        "import app\nfrom tests import fixtures\ndef test_owner_access():\n    assert app.run() is True\n",
        encoding="utf-8",
    )

    return tmp_path


def test_scenario_1_directly_changed_file_selects_mapped_check(plan_repo: Path):
    """Scenario 1: A directly changed requirement-linked file selects its mapped check."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["status"] == "VERIFIED"

    # Modify app.py directly on disk
    (plan_repo / "app.py").write_text("import auth\ndef run():\n    return False\n", encoding="utf-8")

    impact = analyze_change_impact(plan_repo, ["app.py"])
    assert len(impact["requirements"]) == 1
    req_impact = impact["requirements"][0]
    assert len(req_impact["verification_plan"]) == 1
    plan_entry = req_impact["verification_plan"][0]

    assert plan_entry["selected"] is True
    assert plan_entry["selection_basis"] == "DIRECT_MAPPING"
    assert plan_entry["evidence_freshness"] == "STALE"
    assert plan_entry["direct_evidence_freshness"] == "STALE"
    assert len(impact["eligible_reruns"]) == 1


def test_scenario_2_transitive_dependency_change_selects_affected_check(plan_repo: Path):
    """Scenario 2: A transitive dependency change selects the affected check."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["status"] == "VERIFIED"

    # Neither app.py nor test_app.py changed on disk, but models.py is prospective change
    impact = analyze_change_impact(plan_repo, ["models.py"])
    assert "auth.py" in impact["inferred_dependent_files"]
    assert "app.py" in impact["inferred_dependent_files"]
    assert len(impact["requirements"]) == 1

    req_impact = impact["requirements"][0]
    plan_entry = req_impact["verification_plan"][0]

    assert plan_entry["selected"] is True
    assert plan_entry["selection_basis"] == "INFERRED_DEPENDENCY"
    assert plan_entry["evidence_freshness"] == "STALE"
    assert plan_entry["direct_evidence_freshness"] == "CURRENT"
    assert "models.py" in plan_entry["affected_dependencies"]
    assert any("models.py -> auth.py -> app.py" in chain for chain in plan_entry["dependency_chains"])
    assert len(impact["eligible_reruns"]) == 1


def test_scenario_3_dependency_change_affecting_test_included_in_eligible_reruns(plan_repo: Path):
    """Scenario 3: A dependency change affecting a mapped test is included in eligible_reruns."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["status"] == "VERIFIED"

    # Changing fixtures.py which is imported by tests/test_app.py
    impact = analyze_change_impact(plan_repo, ["tests/fixtures.py"])
    assert "tests/test_app.py" in impact["inferred_dependent_files"]
    assert len(impact["requirements"]) == 1

    plan_entry = impact["requirements"][0]["verification_plan"][0]
    assert plan_entry["selected"] is True
    assert plan_entry["selection_basis"] == "INFERRED_DEPENDENCY"
    assert len(impact["eligible_reruns"]) == 1
    assert impact["eligible_reruns"][0]["test_id"] == "test_owner_access"


def test_scenario_4_direct_change_takes_precedence_over_inferred_dependency(plan_repo: Path):
    """Scenario 4: Direct changes take precedence over inferred dependency selection when both apply."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["status"] == "VERIFIED"

    # Modify app.py directly on disk
    (plan_repo / "app.py").write_text("import auth\n# direct change\n", encoding="utf-8")

    # Pass both app.py (direct) and auth.py (dependency)
    impact = analyze_change_impact(plan_repo, ["app.py", "auth.py"])
    plan_entry = impact["requirements"][0]["verification_plan"][0]

    assert plan_entry["selected"] is True
    assert plan_entry["selection_basis"] == "DIRECT_MAPPING"
    assert plan_entry["evidence_freshness"] == "STALE"


def test_scenario_5_current_fingerprint_does_not_suppress_failed_result(plan_repo: Path):
    """Scenario 5: A current fingerprint does not suppress selection when the latest result failed."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)

    # Break test so it fails
    (plan_repo / "tests" / "test_app.py").write_text(
        "import app\ndef test_owner_access():\n    assert False\n",
        encoding="utf-8",
    )
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["outcome"] == "FAILED"

    # Direct files on disk match the recorded run (fingerprint is CURRENT), but outcome was FAILED
    plan = current_verification_plan(plan_repo)
    assert len(plan) == 1
    entry = plan[0]

    assert entry["direct_evidence_freshness"] == "CURRENT"
    assert entry["selected"] is True
    assert entry["selection_basis"] == "UNVERIFIED_BASELINE"
    assert "FAILED" in entry["reason"]


def test_scenario_6_incomplete_verification_mapping_remains_selected_or_blocked(plan_repo: Path):
    """Scenario 6: An incomplete verification mapping remains selected or blocked as before."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=False)

    plan = current_verification_plan(plan_repo)
    assert len(plan) == 1
    entry = plan[0]

    assert entry["selected"] is True
    assert entry["selection_basis"] == "UNVERIFIED_BASELINE"
    assert any("not designated as complete verification" in b for b in entry["blockers"])


def test_scenario_7_stale_direct_fingerprint_preserves_stale_behavior(plan_repo: Path):
    """Scenario 7: A stale direct fingerprint preserves existing stale-evidence behavior."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["status"] == "VERIFIED"

    # Modify app.py on disk
    (plan_repo / "app.py").write_text("import auth\n# Modified on disk\n", encoding="utf-8")

    plan = current_verification_plan(plan_repo)
    assert len(plan) == 1
    entry = plan[0]

    assert entry["direct_evidence_freshness"] == "STALE"
    assert entry["evidence_freshness"] == "STALE"
    assert entry["selected"] is True
    assert entry["selection_basis"] == "DIRECT_MAPPING"


def test_scenario_8_unrelated_file_does_not_affect_unrelated_requirement(plan_repo: Path):
    """Scenario 8: An unrelated file does not affect an unrelated requirement."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)

    impact = analyze_change_impact(plan_repo, ["unrelated.py"])
    assert len(impact["requirements"]) == 0
    assert len(impact["eligible_reruns"]) == 0


def test_scenario_9_circular_dependency_terminates_deterministically(plan_repo: Path):
    """Scenario 9: A dependency chain containing a cycle terminates deterministically."""
    (plan_repo / "cycle_a.py").write_text("import cycle_b\n", encoding="utf-8")
    (plan_repo / "cycle_b.py").write_text("import cycle_a\n", encoding="utf-8")
    (plan_repo / "app.py").write_text("import cycle_a\n", encoding="utf-8")

    graph = build_local_dependency_graph(plan_repo)
    deps = graph.get_transitive_dependencies("app.py")
    assert "cycle_a.py" in deps
    assert "cycle_b.py" in deps

    # Should not raise RecursionError or hang
    impact = analyze_change_impact(plan_repo, ["cycle_b.py"])
    assert "app.py" in impact["inferred_dependent_files"]


def test_scenario_10_dynamic_import_uncertainty_is_surfaced(plan_repo: Path):
    """Scenario 10: Dynamic-import uncertainty is surfaced and does not imply complete coverage."""
    (plan_repo / "app.py").write_text(
        "import importlib\nmod = importlib.import_module('auth')\n",
        encoding="utf-8",
    )
    req = add_requirement(plan_repo, "Dynamic req", "Dynamic test", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)

    impact = analyze_change_impact(plan_repo, ["app.py"])
    assert impact["dependency_coverage"] == "PARTIAL_LOCAL_STATIC"
    assert any("import_module" in u["uncertainty"] for u in impact["uncertainties"] if isinstance(u, dict) and "uncertainty" in u)


def test_scenario_11_missing_dependency_produces_blockers(plan_repo: Path):
    """Scenario 11: Missing, unreadable, or invalid dependency files produce clear uncertainty or blockers."""
    (plan_repo / "app.py").write_text("import nonexistent_local\n", encoding="utf-8")
    req = add_requirement(plan_repo, "Missing dep req", "Missing dep", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)

    # Let graph treat it as unresolved local
    plan = current_verification_plan(plan_repo)
    assert len(plan) == 1
    # Dependency graph notes uncertainty
    assert plan[0]["dependency_coverage"] == "PARTIAL_LOCAL_STATIC"


def test_scenario_12_traversal_limits_fail_safely(plan_repo: Path):
    """Scenario 12: Traversal limits fail safely."""
    # Create chain of 30 files
    for i in range(30):
        nxt = f"mod_{i+1}" if i < 29 else "auth"
        (plan_repo / f"mod_{i}.py").write_text(f"import {nxt}\n", encoding="utf-8")
    (plan_repo / "app.py").write_text("import mod_0\n", encoding="utf-8")

    graph = build_local_dependency_graph(plan_repo)
    deps, paths = graph.get_transitive_dependencies_with_paths("app.py", max_depth=5)
    # Should be bounded by max_depth
    assert len(deps) <= 5


def test_scenario_13_current_verification_plan_preserves_baseline_and_reports_dependencies(plan_repo: Path):
    """Scenario 13: current_verification_plan() preserves baseline selection behavior and reports discovered dependencies without inventing a change event."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    res = run_approved_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)
    assert res["status"] == "VERIFIED"

    plan = current_verification_plan(plan_repo)
    assert len(plan) == 1
    entry = plan[0]

    assert entry["selected"] is False
    assert entry["selection_basis"] == "NONE"
    assert entry["evidence_freshness"] == "CURRENT"
    assert entry["direct_evidence_freshness"] == "CURRENT"
    assert "auth.py" in entry["discovered_dependencies"]
    assert "models.py" in entry["discovered_dependencies"]
    # No change event invented
    assert entry["affected_dependencies"] == []
    assert entry["dependency_chains"] == []


def test_scenario_14_mcp_response_fields_backward_compatible(plan_repo: Path, monkeypatch):
    """Scenario 14: Existing MCP response fields remain backward compatible."""
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(plan_repo))
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)

    impact = get_change_impact(file_paths=["models.py"])
    assert "repository" in impact
    assert "changed_files" in impact
    assert "inferred_dependent_files" in impact
    assert "affected_requirements" in impact
    assert "mapped_tests" in impact
    assert "verification_plan" in impact
    assert "eligible_reruns" in impact
    assert "dependency_coverage" in impact
    assert "coverage_limitations" in impact
    assert "notice" in impact

    # Check plan item within get_change_impact
    item = impact["verification_plan"][0]
    assert "selection_basis" in item
    assert "direct_evidence_freshness" in item
    assert "affected_dependencies" in item
    assert "dependency_chains" in item
    assert "discovered_dependencies" in item

    plan_resp = get_verification_plan()
    assert "plan" in plan_resp
    assert "eligible_checks" in plan_resp
    assert "dependency_coverage" in plan_resp
    assert plan_resp["dependency_coverage"] == "LOCAL_STATIC_IMPORTS"


def test_scenario_15_read_only_guarantee_for_planning_and_impact(plan_repo: Path):
    """Scenario 15: Both impact analysis and planning preserve read-only behavior."""
    req = add_requirement(plan_repo, "Owner access", "Verify owner", file_paths=["app.py"])
    map_requirement_test(plan_repo, req["id"], "tests/test_app.py", "test_owner_access", verification_complete=True)

    with connect(plan_repo) as db:
        req_count = db.execute("SELECT COUNT(*) FROM requirements").fetchone()[0]
        check_count = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        event_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        file_count = db.execute("SELECT COUNT(*) FROM requirement_files").fetchone()[0]
        test_count = db.execute("SELECT COUNT(*) FROM requirement_tests").fetchone()[0]

    app_mtime_before = (plan_repo / "app.py").stat().st_mtime_ns

    # Invoke analysis and planning multiple times
    analyze_change_impact(plan_repo, ["models.py"])
    current_verification_plan(plan_repo)
    get_change_impact(file_paths=["auth.py"])
    get_verification_plan()

    with connect(plan_repo) as db:
        assert db.execute("SELECT COUNT(*) FROM requirements").fetchone()[0] == req_count
        assert db.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == check_count
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == event_count
        assert db.execute("SELECT COUNT(*) FROM requirement_files").fetchone()[0] == file_count
        assert db.execute("SELECT COUNT(*) FROM requirement_tests").fetchone()[0] == test_count

    assert (plan_repo / "app.py").stat().st_mtime_ns == app_mtime_before
