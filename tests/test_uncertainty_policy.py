"""Phase 3: incomplete dependency analysis must never be read as proof of no impact.

Every test uses an isolated tmp_path project; nothing touches the real
.securetrace database or examples/authorization_demo/app.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from securetrace import dependencies
from securetrace.approval import evaluate_proposal, load_proposal
from securetrace.db import connect, migrate_mappings
from securetrace.hooks import handle_pre_tool_use
from securetrace.ledger import add_requirement

AUTH = "def can_cancel(actor_id, owner_id):\n    return bool(actor_id) and actor_id == owner_id\n"


def _project(tmp_path: Path, linked: str = "auth.py") -> str:
    (tmp_path / "auth.py").write_text(AUTH, encoding="utf-8")
    (tmp_path / "notes.py").write_text("X = 1\n", encoding="utf-8")
    migrate_mappings(tmp_path)
    return add_requirement(
        tmp_path, "Only owners cancel", "Owner check", category="authorization",
        severity="high", file_paths=[linked],
    )["id"]


def _write_payload(root: Path, name: str, content: str) -> dict:
    return {
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": name, "CodeContent": content}},
        "workspacePaths": [str(root)],
    }


def test_complete_analysis_no_affected_requirement_allows(tmp_path):
    _project(tmp_path)
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    assert p.decision == "ALLOW"
    assert p.analysis_status == "COMPLETE_NO_IMPACT"
    assert handle_pre_tool_use(_write_payload(tmp_path, "notes.py", "X = 2\n"))["decision"] == "allow"


def test_complete_analysis_affected_requirement_forces_review(tmp_path):
    req = _project(tmp_path)
    p = evaluate_proposal(tmp_path, "auth.py", content=AUTH + "# c\n")
    assert p.decision == "FORCE_ASK"
    assert p.analysis_status == "CONFIRMED_AFFECTED"
    assert [r["id"] for r in p.affected_requirements] == [req]
    assert handle_pre_tool_use(_write_payload(tmp_path, "auth.py", AUTH + "# c\n"))["decision"] == "force_ask"


def test_unparseable_protected_file_makes_impact_unknown(tmp_path):
    """A linked file we cannot parse might import the changed file: unknown != safe."""
    req = _project(tmp_path)
    (tmp_path / "auth.py").write_text("def broken(:\n", encoding="utf-8")
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    assert p.dependency_coverage == "PARTIAL_LOCAL_STATIC"
    assert p.affected_requirements == []
    assert p.decision == "FORCE_ASK"
    assert p.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT"
    assert [r["id"] for r in p.possibly_affected_requirements] == [req]
    assert "could not" in p.warning_text.lower() and req in p.warning_text
    out = handle_pre_tool_use(_write_payload(tmp_path, "notes.py", "X = 2\n"))
    assert out["decision"] == "force_ask"
    assert "could not" in out["reason"].lower()


def test_unrelated_incomplete_file_does_not_force_review(tmp_path):
    """Developer ergonomics: a broken file outside every requirement's reach is irrelevant."""
    _project(tmp_path)
    (tmp_path / "scratch.py").write_text("def broken(:\n", encoding="utf-8")
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    assert p.dependency_coverage == "PARTIAL_LOCAL_STATIC"      # still reported honestly
    assert p.decision == "ALLOW"
    assert p.analysis_status == "COMPLETE_NO_IMPACT"
    assert handle_pre_tool_use(_write_payload(tmp_path, "notes.py", "X = 2\n"))["decision"] == "allow"


def test_unresolved_local_import_in_protected_file_forces_review_only_for_matching_new_module(tmp_path):
    req = _project(tmp_path)
    (tmp_path / "auth.py").write_text("from helpers import check\n" + AUTH, encoding="utf-8")
    # Creating helpers.py would satisfy the unresolved import of a protected file.
    p = evaluate_proposal(tmp_path, "helpers.py", content="def check():\n    return True\n")
    assert p.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT"
    assert p.decision == "FORCE_ASK"
    assert [r["id"] for r in p.possibly_affected_requirements] == [req]
    # A file the unresolved import cannot refer to stays allowed.
    q = evaluate_proposal(tmp_path, "notes.py", content="X = 3\n")
    assert q.decision == "ALLOW"


def test_transitive_unparseable_intermediate_forces_review(tmp_path):
    """protected -> mid (syntax error): mid may import the changed file."""
    req = _project(tmp_path)
    (tmp_path / "auth.py").write_text("import mid\n" + AUTH, encoding="utf-8")
    (tmp_path / "mid.py").write_text("def broken(:\n", encoding="utf-8")
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    assert p.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT"
    assert [r["id"] for r in p.possibly_affected_requirements] == [req]


def test_dynamic_import_in_protected_file_forces_review(tmp_path):
    _project(tmp_path)
    (tmp_path / "auth.py").write_text("import importlib\nm = importlib.import_module('x')\n" + AUTH, encoding="utf-8")
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    assert p.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT"
    assert p.decision == "FORCE_ASK"


def test_truncated_traversal_is_reported_as_uncertainty(tmp_path, monkeypatch):
    _project(tmp_path, linked="m3.py")
    (tmp_path / "m1.py").write_text("import notes\n", encoding="utf-8")
    (tmp_path / "m2.py").write_text("import m1\n", encoding="utf-8")
    (tmp_path / "m3.py").write_text("import m2\n", encoding="utf-8")
    monkeypatch.setattr(dependencies, "MAX_TRAVERSAL_DEPTH", 1)
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    # depth cap hides m3 (protected): must not be reported as "no impact"
    assert p.decision == "FORCE_ASK"
    assert p.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT"


def test_no_registered_requirements_never_forces_review(tmp_path):
    (tmp_path / "x.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "notes.py").write_text("X = 1\n", encoding="utf-8")
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    assert p.decision == "ALLOW"


def test_dependency_analysis_exception_fails_closed_in_hook(tmp_path, monkeypatch):
    _project(tmp_path)

    def boom(root):
        raise RuntimeError("graph exploded")

    monkeypatch.setattr(dependencies, "build_local_dependency_graph", boom)
    with pytest.raises(RuntimeError):
        evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    out = handle_pre_tool_use(_write_payload(tmp_path, "notes.py", "X = 2\n"))
    assert out["decision"] == "deny"
    assert "failed" in out["reason"].lower()


def test_uncertain_proposal_persists_status_and_old_records_load(tmp_path):
    _project(tmp_path)
    (tmp_path / "auth.py").write_text("def broken(:\n", encoding="utf-8")
    p = evaluate_proposal(tmp_path, "notes.py", content="X = 2\n")
    again = load_proposal(tmp_path, p.proposal_id)
    assert again.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT"
    # Backward compatibility: a record written before Phase 3 has no new keys.
    import json
    f = tmp_path / ".securetrace" / "proposals" / f"{p.proposal_id}.json"
    data = json.loads(f.read_text())
    for k in ("analysis_status", "possibly_affected_requirements", "encoding", "audit_errors"):
        data.pop(k, None)
    data["future_unknown_field"] = 1
    f.write_text(json.dumps(data))
    legacy = load_proposal(tmp_path, p.proposal_id)
    assert legacy is not None and legacy.analysis_status == ""
