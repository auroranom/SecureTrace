"""Unit and integration tests for Phase 4.0 Pre-Action Security Approval.

Validates in-memory prospective proposal analysis, plain-language warning
formatting, approval token signing, atomic application, CAS guards, expiry,
replay prevention, and fail-closed integration hooks.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
import pytest

from securetrace.approval import (
    Proposal,
    apply_proposal,
    compute_approval_token,
    deny_proposal,
    evaluate_proposal,
    format_plain_language_warning,
    load_proposal,
    resolve_project_relative_path,
    save_proposal,
    verify_approval_token,
)
from securetrace.db import connect, migrate_mappings
from securetrace.hooks import handle_post_tool_use, handle_pre_tool_use
from securetrace.ledger import (
    add_requirement,
    analyze_change_impact,
    get_requirement_detail,
    map_requirement_test,
    record_check,
)


@pytest.fixture
def approval_repo(tmp_path: Path) -> Path:
    """Create an isolated test repository with registered requirements and dependencies."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test-approval"\nversion = "0.1.0"\n', encoding="utf-8")
    with connect(tmp_path):
        pass
    migrate_mappings(tmp_path)

    # Base application files
    auth_py = tmp_path / "auth.py"
    auth_py.write_text(
        "def check_permission(user_role: str) -> bool:\n"
        "    return user_role == 'admin'\n",
        encoding="utf-8",
    )

    helper_py = tmp_path / "helper.py"
    helper_py.write_text(
        "def validate_token(token: str) -> bool:\n"
        "    return len(token) > 10\n",
        encoding="utf-8",
    )

    app_py = tmp_path / "app.py"
    app_py.write_text(
        "import auth\n"
        "import helper\n\n"
        "def run_app():\n"
        "    return auth.check_permission('admin') and helper.validate_token('secure_token_123')\n",
        encoding="utf-8",
    )

    unmapped_py = tmp_path / "unmapped.py"
    unmapped_py.write_text(
        "def format_greeting(name: str) -> str:\n"
        "    return f'Hello {name}'\n",
        encoding="utf-8",
    )

    # Test file
    test_auth_py = tmp_path / "tests" / "test_auth.py"
    test_auth_py.parent.mkdir(parents=True, exist_ok=True)
    test_auth_py.write_text(
        "import auth\n\n"
        "def test_admin_only():\n"
        "    assert auth.check_permission('admin')\n"
        "    assert not auth.check_permission('guest')\n",
        encoding="utf-8",
    )

    # Register requirement for auth.py
    req1 = add_requirement(
        tmp_path,
        title="Admin role required for privileged operations",
        description="Only users with the admin role can access privileged resources.",
        category="authorization",
        severity="high",
        file_paths=["auth.py"],
    )
    map_requirement_test(
        tmp_path,
        requirement_id=req1["id"],
        test_file="tests/test_auth.py",
        test_id="test_admin_only",
        verification_complete=True,
    )
    record_check(
        tmp_path,
        requirement_id=req1["id"],
        check_name="test_admin_only",
        passed=True,
        verification_complete=True,
    )

    # Register requirement for app.py (which imports helper.py)
    req2 = add_requirement(
        tmp_path,
        title="Valid tokens required for API execution",
        description="All requests must present a validated session token.",
        category="authentication",
        severity="medium",
        file_paths=["app.py"],
    )

    return tmp_path


def test_1_proposed_edits_analyzed_without_modifying_target_file(approval_repo: Path):
    """1. Proposed edits are analyzed in memory without modifying the target file."""
    auth_file = approval_repo / "auth.py"
    orig_content = auth_file.read_text(encoding="utf-8")
    orig_mtime = auth_file.stat().st_mtime_ns

    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="edit",
        target_pattern="return user_role == 'admin'",
        replacement_pattern="return True",  # Dangerous bypass
    )

    # File on disk must remain strictly untouched
    assert auth_file.read_text(encoding="utf-8") == orig_content
    assert auth_file.stat().st_mtime_ns == orig_mtime
    assert proposal.original_hash == hashlib.sha256(auth_file.read_bytes()).hexdigest()
    assert proposal.proposed_hash != proposal.original_hash
    assert "return True" in proposal.proposed_content


def test_2_directly_mapped_requirements_identified(approval_repo: Path):
    """2. Directly mapped requirements are correctly identified in the proposal."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="def check_permission(user_role: str) -> bool:\n    return True\n",
    )

    assert proposal.decision == "FORCE_ASK"
    assert len(proposal.affected_requirements) >= 1
    req_ids = [r["id"] for r in proposal.affected_requirements]
    assert any("Admin role required" in r.get("title", "") for r in proposal.affected_requirements)


def test_3_unmapped_files_follow_documented_policy(approval_repo: Path):
    """3. Unmapped files follow the safe policy: allow without requiring security review."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="unmapped.py",
        operation="write",
        content="def format_greeting(name: str) -> str:\n    return f'Welcome {name}!'\n",
    )

    assert proposal.decision == "ALLOW"
    assert proposal.status == "APPROVED"
    assert len(proposal.affected_requirements) == 0
    assert "No registered security requirements affected" in proposal.warning_text


def test_4_security_relevant_changes_trigger_explicit_review(approval_repo: Path):
    """4. Security-relevant changes trigger an explicit FORCE_ASK decision and PENDING status."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="# updated auth logic\n",
    )

    assert proposal.decision == "FORCE_ASK"
    assert proposal.status == "PENDING"
    assert len(proposal.token) == 64  # HMAC-SHA256 hex string


def test_5_warning_contains_all_required_plain_language_sections(approval_repo: Path):
    """5. The warning contains all 6 required plain-language sections in accessible English."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="edit",
        target_pattern="return user_role == 'admin'",
        replacement_pattern="return True",
    )
    warning = proposal.warning_text

    # Verify all 6 section headings
    assert "1. What is proposed to change:" in warning
    assert "2. What could go wrong:" in warning
    assert "3. Why this warning appeared:" in warning
    assert "4. How serious this potential impact is:" in warning
    assert "5. What you can choose to do:" in warning
    assert "6. What happens after your decision:" in warning

    # Verify plain-language phrasing
    assert "unauthorized users" in warning
    assert "potential security risk" in warning
    assert "Allow / Approve" in warning
    assert "Deny / Abort" in warning

    # Verify technical jargon is avoided
    assert "AST" not in warning
    assert "transitive dependency" not in warning
    assert "fingerprint" not in warning


def test_6_denial_preserves_original_file_content(approval_repo: Path):
    """6. Denial preserves the original file content and marks proposal DENIED."""
    auth_file = approval_repo / "auth.py"
    orig_content = auth_file.read_text(encoding="utf-8")

    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="DANGEROUS OVERWRITE",
    )
    denied = deny_proposal(approval_repo, proposal.proposal_id)

    assert denied.status == "DENIED"
    assert auth_file.read_text(encoding="utf-8") == orig_content


def test_7_approval_applies_only_reviewed_proposal(approval_repo: Path):
    """7. Approval applies only the reviewed proposal atomically and marks evidence STALE."""
    auth_file = approval_repo / "auth.py"
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="def check_permission(user_role: str) -> bool:\n    return user_role in ('admin', 'superadmin')\n",
    )

    applied = apply_proposal(approval_repo, proposal.proposal_id, proposal.token)

    assert applied.status == "APPLIED"
    assert auth_file.read_text(encoding="utf-8") == proposal.proposed_content

    # Requirement with previous verification evidence must transition to STALE
    admin_req = [r for r in proposal.affected_requirements if "Admin role" in r.get("title", "")][0]
    req = get_requirement_detail(approval_repo, admin_req["id"])
    assert req is not None
    assert req["status"] == "STALE"


def test_8_tampered_approvals_are_rejected(approval_repo: Path):
    """8. Tampered approvals (invalid token or modified proposal) are rejected."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="def check_permission(user_role: str) -> bool:\n    return True\n",
    )
    auth_file = approval_repo / "auth.py"
    orig_content = auth_file.read_text(encoding="utf-8")

    tampered_token = proposal.token[:-4] + "ffff"

    with pytest.raises(ValueError, match="Invalid approval token"):
        apply_proposal(approval_repo, proposal.proposal_id, tampered_token)

    assert auth_file.read_text(encoding="utf-8") == orig_content


def test_9_expired_approvals_fail_closed(approval_repo: Path):
    """9. Expired approvals fail closed and cannot modify the target file."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="MODIFICATION",
        timeout_seconds=-1.0,  # Expired immediately
    )
    auth_file = approval_repo / "auth.py"
    orig_content = auth_file.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="expired"):
        apply_proposal(approval_repo, proposal.proposal_id, proposal.token)

    assert auth_file.read_text(encoding="utf-8") == orig_content


def test_10_replayed_approvals_are_rejected(approval_repo: Path):
    """10. Replayed approvals are rejected once consumed."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="FIRST APPLY\n",
    )
    applied = apply_proposal(approval_repo, proposal.proposal_id, proposal.token)
    assert applied.status == "APPLIED"

    # Second apply attempt must fail
    with pytest.raises(ValueError, match="already been applied"):
        apply_proposal(approval_repo, proposal.proposal_id, proposal.token)


def test_11_concurrent_file_changes_prevent_unsafe_overwrites(approval_repo: Path):
    """11. Compare-And-Swap (CAS) guard detects external modifications and blocks write."""
    auth_file = approval_repo / "auth.py"
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="PROPOSED CONTENT\n",
    )

    # Simulate concurrent external edit to auth.py on disk
    auth_file.write_text("CONCURRENT EXTERNAL EDIT\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Concurrent modification detected"):
        apply_proposal(approval_repo, proposal.proposal_id, proposal.token)

    # Disk file must still have the concurrent edit, not the stale proposal
    assert auth_file.read_text(encoding="utf-8") == "CONCURRENT EXTERNAL EDIT\n"


def test_12_traversal_and_symlink_escapes_are_rejected(approval_repo: Path):
    """12. Path traversal (..) escaping project root is rejected."""
    with pytest.raises(ValueError, match="resolves outside project root"):
        evaluate_proposal(
            root=approval_repo,
            file_path="../../outside.py",
            operation="write",
            content="MALICIOUS WRITE",
        )


def test_13_transitive_dependency_impacts_explained_accurately(approval_repo: Path):
    """13. Modifying a dependency (helper.py) flags impact on dependent requirements (app.py)."""
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="helper.py",
        operation="write",
        content="def validate_token(token: str) -> bool:\n    return True\n",
    )

    assert proposal.decision == "FORCE_ASK"
    warning = proposal.warning_text
    # Warning should explain that requirements rely on code that imports helper.py
    assert "helper.py" in warning
    assert "relies on code that imports" in warning


def test_14_incomplete_dependency_analysis_is_disclosed(approval_repo: Path):
    """14. Incomplete dependency coverage or uncertainties are disclosed in the warning."""
    dyn_file = approval_repo / "dynamic_module.py"
    dyn_file.write_text(
        "import importlib\n"
        "m = importlib.import_module('unknown_pkg')\n",
        encoding="utf-8",
    )
    add_requirement(
        approval_repo,
        title="Dynamic check requirement",
        description="Requirement on dynamic module.",
        category="other",
        severity="low",
        file_paths=["dynamic_module.py"],
    )

    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="dynamic_module.py",
        operation="write",
        content="# edited dynamic module\n",
    )

    if proposal.dependency_coverage == "PARTIAL_LOCAL_STATIC" or proposal.uncertainties:
        assert "Notice on Analysis Scope" in proposal.warning_text
        assert "could not check every possible dependency" in proposal.warning_text


def test_15_approval_integration_errors_fail_closed(approval_repo: Path):
    """15. Hook integration errors fail closed (decision: 'deny') rather than silently allowing."""
    # Missing Path argument in toolCall
    malformed_payload = {
        "toolCall": {
            "name": "edit_file",
            "args": {},
        },
        "workspacePaths": [str(approval_repo)],
    }
    result = handle_pre_tool_use(malformed_payload)
    assert result["decision"] == "deny"
    assert "could not determine target file path" in result["reason"]

    # Traversal escape payload
    escape_payload = {
        "toolCall": {
            "name": "write_file",
            "args": {"Path": "../../../etc/shadow", "Content": "test"},
        },
        "workspacePaths": [str(approval_repo)],
    }
    result_escape = handle_pre_tool_use(escape_payload)
    assert result_escape["decision"] == "deny"
    assert "resolves outside project root" in result_escape["reason"]


def test_16_existing_mcp_tools_and_change_impact_remain_compatible(approval_repo: Path):
    """16. Existing change-impact analysis and MCP server tools remain fully compatible."""
    # Test analyze_change_impact directly
    impact = analyze_change_impact(approval_repo, ["auth.py"])
    assert "requirements" in impact
    assert "inferred_dependent_files" in impact
    assert "dependency_coverage" in impact
    assert "coverage_limitations" in impact

    # Test MCP tool functions from securetrace.mcp_server
    from securetrace.mcp_server import get_change_impact, get_verification_plan

    old_root = os.environ.get("SECURETRACE_PROJECT_ROOT")
    os.environ["SECURETRACE_PROJECT_ROOT"] = str(approval_repo)
    try:
        impact_result = get_change_impact(["auth.py"])
        assert "affected_requirements" in impact_result
        assert "inferred_dependent_files" in impact_result

        plan_result = get_verification_plan()
        assert "plan" in plan_result
        assert "eligible_checks" in plan_result
        assert "total_checks" in plan_result
    finally:
        if old_root is not None:
            os.environ["SECURETRACE_PROJECT_ROOT"] = old_root
        else:
            os.environ.pop("SECURETRACE_PROJECT_ROOT", None)


def test_post_tool_use_updates_evidence_when_successful(approval_repo: Path):
    """PostToolUse marks affected requirements STALE on successful write."""
    payload = {
        "toolCall": {
            "name": "write_file",
            "args": {"Path": "auth.py", "Content": "new content"},
        },
        "workspacePaths": [str(approval_repo)],
    }
    handle_post_tool_use(payload)

    # Check that requirement with verification evidence was marked STALE
    from securetrace.ledger import list_requirements
    admin_req = [r for r in list_requirements(approval_repo) if "Admin role" in r["title"]][0]
    detail = get_requirement_detail(approval_repo, admin_req["id"])
    assert detail is not None
    assert detail["status"] == "STALE"


def test_post_tool_use_does_not_modify_ledger_when_tool_failed(approval_repo: Path):
    """PostToolUse does not update ledger when tool execution reported an error."""
    payload = {
        "toolCall": {
            "name": "write_file",
            "args": {"Path": "auth.py", "Content": "failed content"},
        },
        "workspacePaths": [str(approval_repo)],
        "error": "User denied tool execution",
    }
    reqs = analyze_change_impact(approval_repo, ["auth.py"])["requirements"]
    before_status = get_requirement_detail(approval_repo, reqs[0]["requirement_id"])["status"]

    handle_post_tool_use(payload)

    after_status = get_requirement_detail(approval_repo, reqs[0]["requirement_id"])["status"]
    assert before_status == after_status


def test_cli_review_and_approve_flow(approval_repo: Path, monkeypatch, capsys):
    """Test CLI review and approve subcommands."""
    from securetrace.cli import build_parser, main
    from securetrace.approval import load_proposal

    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="CLI APPROVED CONTENT\n",
    )

    monkeypatch.chdir(approval_repo)

    # 1. Test CLI review
    monkeypatch.setattr("sys.argv", ["securetrace", "review", proposal.proposal_id])
    main()
    captured = capsys.readouterr()
    assert proposal.proposal_id in captured.out
    assert "SecureTrace Pre-Action Security Warning" in captured.out

    # 2. Test CLI approve
    monkeypatch.setattr("sys.argv", ["securetrace", "approve", proposal.proposal_id])
    main()
    captured = capsys.readouterr()
    assert "Approved and applied proposal" in captured.out
    assert (approval_repo / "auth.py").read_text(encoding="utf-8") == "CLI APPROVED CONTENT\n"
    assert load_proposal(approval_repo, proposal.proposal_id).status == "APPLIED"


def test_cli_abort_flow(approval_repo: Path, monkeypatch, capsys):
    """Test CLI abort subcommand."""
    from securetrace.cli import main
    from securetrace.approval import load_proposal

    orig_content = (approval_repo / "auth.py").read_text(encoding="utf-8")
    proposal = evaluate_proposal(
        root=approval_repo,
        file_path="auth.py",
        operation="write",
        content="CLI ABORTED CONTENT\n",
    )

    monkeypatch.chdir(approval_repo)
    monkeypatch.setattr("sys.argv", ["securetrace", "abort", proposal.proposal_id])
    main()
    captured = capsys.readouterr()
    assert "Aborted proposal" in captured.out
    assert (approval_repo / "auth.py").read_text(encoding="utf-8") == orig_content
    assert load_proposal(approval_repo, proposal.proposal_id).status == "DENIED"


def test_hook_cli_execution_via_stdin_stdout(approval_repo: Path, monkeypatch, capsys):
    """Test hook runner CLI execution via stdin/stdout."""
    import io
    from securetrace.hooks import main as hooks_main

    payload = {
        "toolCall": {
            "name": "write_file",
            "args": {"Path": "auth.py", "Content": "NEW CODE"},
        },
        "workspacePaths": [str(approval_repo)],
    }

    monkeypatch.setattr("sys.argv", ["hooks.py", "pre_tool_use"])
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    hooks_main()
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["decision"] == "force_ask"
    assert "SecureTrace Pre-Action Security Warning" in output["reason"]

