"""Tests for the Antigravity-facing pre/post-action flow.

Test levels (kept distinct on purpose):
  * UNIT: engine and ledger functions called directly.
  * SIMULATED HOOK: ``python -m securetrace.hooks`` fed a JSON payload on stdin.
    This proves the hook's parsing and output only. It is NOT proof that
    Antigravity discovers the hook, sends this payload, or shows a prompt.
No test here is a live end-to-end test against a running Antigravity session.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from securetrace.approval import (
    evaluate_proposal,
    find_reviewed_proposal_for_write,
    load_proposal,
    save_proposal,
    sweep_unresolved_reviews,
)
from securetrace.db import connect, migrate_mappings
from securetrace.hook_install import FILE_TOOL_MATCHER, install_hooks
from securetrace.hooks import handle_post_tool_use, handle_pre_tool_use
from securetrace.ledger import (
    add_requirement,
    get_requirement_detail,
    mark_changed_files,
    record_check,
)

OWNER_CHECK = "return bool(actor_id) and actor_id == appointment_owner_id"
APP_SOURCE = (
    "def can_cancel(actor_id, appointment_owner_id):\n"
    f"    {OWNER_CHECK}\n"
)


@pytest.fixture
def repo(tmp_path: Path):
    app = tmp_path / "app.py"
    app.write_text(APP_SOURCE, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    migrate_mappings(tmp_path)
    req = add_requirement(
        tmp_path, "Only appointment owners can cancel",
        "An authenticated user must not cancel an appointment owned by another user.",
        category="authorization", severity="high", file_paths=["app.py"],
    )
    req_id = req["id"]
    record_check(tmp_path, req_id, "owner-check", True, verification_complete=True)
    return tmp_path, req_id


def _payload(root: Path, name: str, args: dict) -> dict:
    return {"toolCall": {"name": name, "args": args}, "workspacePaths": [str(root)]}


def _events(root: Path, event_type: str | None = None, req_id: str | None = None):
    with connect(root) as db:
        rows = db.execute("SELECT * FROM events ORDER BY id").fetchall()
    return [
        dict(r) for r in rows
        if (event_type is None or r["event_type"] == event_type)
        and (req_id is None or r["requirement_id"] == req_id)
    ]


# ---------------------------------------------------------------- A. engine


def test_replace_file_content_on_protected_file_forces_ask_with_real_requirement(repo):
    root, req_id = repo
    app = root / "app.py"
    before = (app.read_bytes(), app.stat().st_mtime_ns)

    result = handle_pre_tool_use(_payload(root, "replace_file_content", {
        "TargetFile": str(app), "TargetContent": OWNER_CHECK, "ReplacementContent": "return True",
    }))

    assert result["decision"] == "force_ask"
    reason = result["reason"]
    assert req_id in reason
    assert "Only appointment owners can cancel" in reason
    assert "HIGH" in reason
    assert "must not cancel an appointment owned by another user" in reason  # registered description
    assert "does not mean a vulnerability has been found" in reason
    assert "Try another approach" in reason
    assert (app.read_bytes(), app.stat().st_mtime_ns) == before  # evaluation never touches the target


def test_write_to_file_and_multi_replace_are_intercepted(repo):
    root, req_id = repo
    app = root / "app.py"
    r1 = handle_pre_tool_use(_payload(root, "write_to_file", {
        "TargetFile": str(app), "CodeContent": "def can_cancel(a, b):\n    return True\n", "Overwrite": True,
    }))
    r2 = handle_pre_tool_use(_payload(root, "multi_replace_file_content", {
        "TargetFile": str(app),
        "ReplacementChunks": [{"TargetContent": "can_cancel", "ReplacementContent": "may_cancel"}],
    }))
    assert r1["decision"] == "force_ask" and req_id in r1["reason"]
    assert r2["decision"] == "force_ask" and req_id in r2["reason"]
    assert app.read_text(encoding="utf-8") == APP_SOURCE


def test_legacy_tool_names_still_work(repo):
    root, req_id = repo
    result = handle_pre_tool_use(_payload(root, "edit_file", {
        "Path": str(root / "app.py"), "Target": OWNER_CHECK, "Replacement": "return True",
    }))
    assert result["decision"] == "force_ask" and req_id in result["reason"]


def test_unrelated_file_is_allowed_and_non_file_tools_ignored(repo):
    root, _ = repo
    assert handle_pre_tool_use(_payload(root, "replace_file_content", {
        "TargetFile": str(root / "notes.txt"), "TargetContent": "hello", "ReplacementContent": "bye",
    })) == {"decision": "allow"}
    assert handle_pre_tool_use(_payload(root, "run_command", {"CommandLine": "ls"})) == {"decision": "allow"}


def test_no_op_change_is_not_flagged(repo):
    root, _ = repo
    result = handle_pre_tool_use(_payload(root, "write_to_file", {
        "TargetFile": str(root / "app.py"), "CodeContent": APP_SOURCE, "Overwrite": True,
    }))
    assert result["decision"] == "allow"


def test_unsafe_and_uninterpretable_proposals_fail_closed(repo, tmp_path_factory):
    root, _ = repo
    outside = tmp_path_factory.mktemp("outside") / "evil.py"
    for args in (
        {"TargetFile": str(outside), "CodeContent": "x"},
        {"TargetFile": "../../etc/passwd", "CodeContent": "x"},
    ):
        out = handle_pre_tool_use(_payload(root, "write_to_file", args))
        assert out["decision"] == "deny"
    assert not outside.exists()

    missing_target = handle_pre_tool_use(_payload(root, "replace_file_content", {
        "TargetFile": str(root / "app.py"), "ReplacementContent": "x"}))
    assert missing_target["decision"] == "deny"
    no_path = handle_pre_tool_use(_payload(root, "write_to_file", {"CodeContent": "x"}))
    assert no_path["decision"] == "deny"
    bad_chunks = handle_pre_tool_use(_payload(root, "multi_replace_file_content", {
        "TargetFile": str(root / "app.py"), "ReplacementChunks": "nope"}))
    assert bad_chunks["decision"] == "deny"
    assert (root / "app.py").read_text(encoding="utf-8") == APP_SOURCE


def test_target_text_not_found_is_denied_not_silently_allowed(repo):
    root, _ = repo
    out = handle_pre_tool_use(_payload(root, "replace_file_content", {
        "TargetFile": str(root / "app.py"), "TargetContent": "does not exist", "ReplacementContent": "x"}))
    assert out["decision"] == "deny"


# ------------------------------------------------ B. post-change / audit


def test_approved_write_marks_evidence_stale_and_records_audit_trail(repo):
    root, req_id = repo
    app = root / "app.py"
    assert get_requirement_detail(root, req_id)["status"] == "VERIFIED"
    args = {"TargetFile": str(app), "TargetContent": OWNER_CHECK, "ReplacementContent": "return True"}

    pre = handle_pre_tool_use(_payload(root, "replace_file_content", args))
    assert pre["decision"] == "force_ask"
    assert get_requirement_detail(root, req_id)["status"] == "VERIFIED"  # nothing changes before the write

    app.write_text(APP_SOURCE.replace(OWNER_CHECK, "return True"), encoding="utf-8")  # host applies the approved edit
    handle_post_tool_use(_payload(root, "replace_file_content", args))

    assert get_requirement_detail(root, req_id)["status"] == "STALE"
    assert len(_events(root, "SECURITY_REVIEW_REQUESTED", req_id)) == 1
    assert len(_events(root, "CHANGE_APPLIED_AFTER_REVIEW", req_id)) == 1
    assert len(_events(root, "LINKED_FILE_CHANGED", req_id)) == 1
    assert "APPROVAL_DENIED" not in {e["event_type"] for e in _events(root)}  # never invented
    assert req_id in _events(root, "TOOL_WRITE_COMPLETED")[0]["details"]


def test_stale_requirement_is_not_revived_by_a_later_passing_incomplete_check(repo):
    root, req_id = repo
    mark_changed_files(root, ["app.py"])
    app = root / "app.py"
    app.write_text(APP_SOURCE + "# edit\n", encoding="utf-8")
    mark_changed_files(root, ["app.py"])
    record_check(root, req_id, "partial", True, verification_complete=False)
    assert get_requirement_detail(root, req_id)["status"] != "VERIFIED"


def test_write_that_differs_from_reviewed_proposal_is_not_reported_as_that_proposal(repo):
    root, req_id = repo
    app = root / "app.py"
    args = {"TargetFile": str(app), "TargetContent": OWNER_CHECK, "ReplacementContent": "return True"}
    handle_pre_tool_use(_payload(root, "replace_file_content", args))
    app.write_text("something else entirely\n", encoding="utf-8")
    handle_post_tool_use(_payload(root, "replace_file_content", args))
    assert _events(root, "CHANGE_APPLIED_AFTER_REVIEW") == []
    assert get_requirement_detail(root, req_id)["status"] == "STALE"
    assert "No matching security review" in _events(root, "TOOL_WRITE_COMPLETED")[0]["details"]


def test_failed_tool_call_does_not_mark_anything_stale(repo):
    root, req_id = repo
    out = handle_post_tool_use({**_payload(root, "replace_file_content", {"TargetFile": str(root / "app.py")}),
                                "error": "user rejected"})
    assert out == {}
    assert get_requirement_detail(root, req_id)["status"] == "VERIFIED"


def test_expired_review_with_no_write_is_recorded_as_unobserved_not_denied(repo):
    root, req_id = repo
    proposal = evaluate_proposal(root, "app.py", "edit", target_pattern=OWNER_CHECK, replacement_pattern="return True")
    closed = sweep_unresolved_reviews(root, now=time.time() + 10_000)
    assert closed == [proposal.proposal_id]
    assert load_proposal(root, proposal.proposal_id).status == "EXPIRED"
    types = {e["event_type"] for e in _events(root)}
    assert "REVIEW_NO_WRITE_OBSERVED" in types and "APPROVAL_DENIED" not in types
    assert sweep_unresolved_reviews(root, now=time.time() + 20_000) == []  # idempotent


def test_find_reviewed_proposal_requires_exact_content_match(repo):
    root, _ = repo
    proposal = evaluate_proposal(root, "app.py", "edit", target_pattern=OWNER_CHECK, replacement_pattern="return True")
    assert find_reviewed_proposal_for_write(root, "app.py") is None  # disk still has original content
    (root / "app.py").write_text(proposal.proposed_content, encoding="utf-8")
    assert find_reviewed_proposal_for_write(root, "app.py").proposal_id == proposal.proposal_id


def test_duplicate_linked_file_changed_events_are_suppressed(repo):
    root, req_id = repo
    mark_changed_files(root, ["app.py"])
    mark_changed_files(root, ["app.py"])  # e.g. watcher + hook reporting the same save
    assert len(_events(root, "LINKED_FILE_CHANGED", req_id)) == 1


def test_different_change_sets_are_not_collapsed(repo):
    root, req_id = repo
    mark_changed_files(root, ["app.py"])
    mark_changed_files(root, ["other.py"])  # unlinked: no event, and must not erase the first
    assert len(_events(root, "LINKED_FILE_CHANGED", req_id)) == 1


# ------------------------------------------------------- C. hook install


def test_install_hooks_writes_correct_config_without_bom_and_preserves_others(tmp_path: Path):
    agents = tmp_path / ".agents"
    agents.mkdir()
    existing = {"other-hook": {"Stop": [{"type": "command", "command": "echo hi"}]}}
    (agents / "hooks.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(existing).encode())

    written = install_hooks(tmp_path, python_exe="/opt/my env/bin/python")

    raw = written.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    config = json.loads(raw)
    assert config["other-hook"] == existing["other-hook"]
    pre = config["securetrace-approval"]["PreToolUse"][0]
    assert pre["matcher"] == FILE_TOOL_MATCHER == "edit_file|write_file|write_to_file|replace_file_content|multi_replace_file_content"
    assert pre["hooks"][0]["command"] == '"/opt/my env/bin/python" -m securetrace.hooks pre_tool_use'
    assert config["securetrace-approval"]["PostToolUse"][0]["hooks"][0]["command"].endswith("post_tool_use")
    assert (agents / "hooks.json.securetrace-backup").is_file()
    install_hooks(tmp_path, python_exe="/opt/my env/bin/python")  # idempotent
    assert json.loads(written.read_text())["other-hook"] == existing["other-hook"]


def test_install_hooks_refuses_invalid_existing_json(tmp_path: Path):
    (tmp_path / ".agents").mkdir()
    (tmp_path / ".agents" / "hooks.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        install_hooks(tmp_path)




def test_install_hooks_windows_path_with_spaces_generates_wrapper(tmp_path: Path):
    win_python = r"D:\My Workspace\venv\Scripts\python.exe"
    written = install_hooks(tmp_path, python_exe=win_python)
    config = json.loads(written.read_text(encoding="utf-8"))
    pre = config["securetrace-approval"]["PreToolUse"][0]
    assert pre["matcher"] == FILE_TOOL_MATCHER
    cmd = pre["hooks"][0]["command"]
    assert "securetrace_hook.cmd pre_tool_use" in cmd
    assert '"' not in cmd  # No double quotes to prevent Go os/exec cmd.exe escaping issues
    wrapper = tmp_path / ".agents" / "securetrace_hook.cmd"
    assert wrapper.is_file()
    wrapper_text = wrapper.read_text(encoding="ascii")
    assert win_python in wrapper_text
    assert "%*" in wrapper_text

def test_repository_hooks_json_matches_real_antigravity_tools():
    cfg_path = Path(__file__).resolve().parent.parent / ".agents" / "hooks.json"
    raw = cfg_path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    entry = json.loads(raw)["securetrace-approval"]
    assert entry["PreToolUse"][0]["matcher"] == FILE_TOOL_MATCHER


# --------------------------------------------- D. MCP alternative context


def test_review_context_tool_returns_requirement_and_is_read_only(repo, monkeypatch):
    from securetrace import mcp_server

    root, req_id = repo
    monkeypatch.setenv("SECURETRACE_PROJECT_ROOT", str(root))
    assert mcp_server.get_security_review_context()["found"] is False

    proposal = evaluate_proposal(root, "app.py", "edit", target_pattern=OWNER_CHECK, replacement_pattern="return True")
    before = (root / "app.py").read_bytes()
    ctx = mcp_server.get_security_review_context()
    assert ctx["found"] and ctx["proposal_id"] == proposal.proposal_id
    assert ctx["affected_requirements"][0]["id"] == req_id
    assert ctx["affected_requirements"][0]["severity"] == "high"
    assert req_id in ctx["instruction_for_agent"]
    assert "not a confirmed vulnerability" in ctx["instruction_for_agent"]
    assert (root / "app.py").read_bytes() == before
    assert load_proposal(root, proposal.proposal_id).status == "PENDING"  # nothing approved or denied


# ------------------------------------- E. SIMULATED hook process (not live)


def test_simulated_hook_process_emits_force_ask_json(repo):
    root, req_id = repo
    payload = _payload(root, "replace_file_content", {
        "TargetFile": str(root / "app.py"), "TargetContent": OWNER_CHECK, "ReplacementContent": "return True"})
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        [str(Path(__file__).resolve().parent.parent), os.environ.get("PYTHONPATH", "")])}
    proc = subprocess.run([sys.executable, "-m", "securetrace.hooks", "pre_tool_use"],
                          input=json.dumps(payload), capture_output=True, text=True, env=env, cwd=str(root))
    out = json.loads(proc.stdout)
    assert out["decision"] == "force_ask" and req_id in out["reason"]
    garbage = subprocess.run([sys.executable, "-m", "securetrace.hooks", "pre_tool_use"],
                             input="not json", capture_output=True, text=True, env=env, cwd=str(root))
    assert json.loads(garbage.stdout)["decision"] == "deny"
