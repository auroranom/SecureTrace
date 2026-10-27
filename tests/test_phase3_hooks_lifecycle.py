"""Phase 3: native hook contract, proposal lifecycle, and audit accuracy.

SIMULATED-HOOK tests only: they feed JSON payloads to the handlers (or ``python -m
securetrace.hooks``). They prove SecureTrace's own parsing, policy and recording; they
do NOT prove that Antigravity sends these payloads, discovers the hook, or surfaces
the prompt. Everything runs in tmp_path; the real .securetrace DB and
examples/authorization_demo/app.py are never touched.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from securetrace import approval
from securetrace.approval import (
    Proposal, apply_proposal, deny_proposal, evaluate_proposal, load_proposal, save_proposal,
    sweep_unresolved_reviews,
)
from securetrace.db import connect, migrate_mappings
from securetrace.hook_install import FILE_TOOL_MATCHER
from securetrace import hooks
from securetrace.hooks import FILE_WRITE_TOOLS, handle_post_tool_use, handle_pre_tool_use
from securetrace.ledger import add_requirement, get_requirement_detail, record_check

SRC = "def can_cancel(actor_id, owner_id):\n    return bool(actor_id) and actor_id == owner_id\n"
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text(SRC, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    migrate_mappings(tmp_path)
    req = add_requirement(tmp_path, "Owner only", "Owner check", category="authorization",
                          severity="high", file_paths=["app.py"])["id"]
    record_check(tmp_path, req, "owner-check", True, verification_complete=True)
    return tmp_path, req


def payload(root, name, args):
    return {"toolCall": {"name": name, "args": args}, "workspacePaths": [str(root)]}


def events(root, etype=None):
    with connect(root) as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM events ORDER BY id")]
    return [r for r in rows if etype is None or r["event_type"] == etype]


def write_args(root, rel, content):
    return {"TargetFile": str(root / rel), "CodeContent": content}


NEW = SRC + "# reviewed change\n"


# ---------------------------------------------------------------- 4. tool coverage
def test_hook_matcher_and_implementation_agree():
    assert set(FILE_TOOL_MATCHER.split("|")) == set(FILE_WRITE_TOOLS)
    cfg = json.loads((REPO_ROOT / ".agents" / "hooks.json").read_text(encoding="utf-8"))
    for event in ("PreToolUse", "PostToolUse"):
        for entry in cfg["securetrace-approval"][event]:
            assert set(entry["matcher"].split("|")) == set(FILE_WRITE_TOOLS)


TOOL_ARGS = {
    "write_to_file": lambda r: {"TargetFile": str(r / "app.py"), "CodeContent": NEW},
    "write_file": lambda r: {"path": str(r / "app.py"), "content": NEW},
    "replace_file_content": lambda r: {"TargetFile": str(r / "app.py"), "TargetContent": "bool(actor_id) and ", "ReplacementContent": ""},
    "edit_file": lambda r: {"path": str(r / "app.py"), "target": "bool(actor_id) and ", "replacement": ""},
    "multi_replace_file_content": lambda r: {"TargetFile": str(r / "app.py"), "ReplacementChunks": [
        {"TargetContent": "bool(actor_id) and ", "ReplacementContent": ""}]},
}


@pytest.mark.parametrize("tool", sorted(FILE_WRITE_TOOLS))
def test_every_supported_tool_on_protected_file_requires_review(repo, tool):
    root, req = repo
    out = handle_pre_tool_use(payload(root, tool, TOOL_ARGS[tool](root)))
    assert out["decision"] == "force_ask", out
    assert req in out["reason"]
    assert any(e["requirement_id"] == req for e in events(root, "SECURITY_REVIEW_REQUESTED"))


@pytest.mark.parametrize("tool", sorted(FILE_WRITE_TOOLS))
def test_every_supported_tool_on_unprotected_file_is_allowed(repo, tool):
    root, _ = repo
    args = {k: (str(root / "notes.txt") if isinstance(v, str) and v.endswith("app.py") else v)
            for k, v in TOOL_ARGS[tool](root).items()}
    if "TargetContent" in args or "target" in args:
        args = {**args, **({"TargetContent": "hello", "ReplacementContent": "bye"} if "TargetContent" in args else {"target": "hello", "replacement": "bye"})}
    if "ReplacementChunks" in args:
        args["ReplacementChunks"] = [{"TargetContent": "hello", "ReplacementContent": "bye"}]
    if "CodeContent" in args or "content" in args:
        args = {k: ("bye\n" if k in ("CodeContent", "content") else v) for k, v in args.items()}
    assert handle_pre_tool_use(payload(root, tool, args))["decision"] == "allow"


def test_unsupported_tool_is_allowed_by_design(repo):
    """Documented boundary: only the file tools in the matcher are assessed (shell is NOT intercepted)."""
    root, _ = repo
    assert handle_pre_tool_use(payload(root, "run_command", {"CommandLine": "rm app.py"}))["decision"] == "allow"


# ---------------------------------------------------------------- 4F/10: malformed -> deny
@pytest.mark.parametrize("bad", [
    None, [], "x", {}, {"toolCall": "write_to_file"}, {"toolCall": {}}, {"toolCall": {"name": 5}},
    {"toolCall": {"name": None, "args": {}}},
])
def test_malformed_envelope_is_denied(bad):
    assert handle_pre_tool_use(bad)["decision"] == "deny"


@pytest.mark.parametrize("args", [
    [], "app.py", {}, {"TargetFile": ""}, {"TargetFile": 7},
    {"TargetFile": "app.py"},                              # write without content
    {"TargetFile": "app.py", "CodeContent": 123},          # wrong type
    {"TargetFile": "app.py", "CodeContent": None},
])
def test_malformed_protected_write_fails_closed(repo, args):
    root, _ = repo
    before = (root / "app.py").read_bytes()
    out = handle_pre_tool_use(payload(root, "write_to_file", args))
    assert out["decision"] == "deny", out
    assert (root / "app.py").read_bytes() == before


@pytest.mark.parametrize("tool,args", [
    ("replace_file_content", {"TargetFile": "app.py"}),
    ("replace_file_content", {"TargetFile": "app.py", "TargetContent": 5}),
    ("replace_file_content", {"TargetFile": "app.py", "TargetContent": "x", "ReplacementContent": 5}),
    ("replace_file_content", {"TargetFile": "app.py", "TargetContent": "NOT PRESENT"}),
    ("multi_replace_file_content", {"TargetFile": "app.py"}),
    ("multi_replace_file_content", {"TargetFile": "app.py", "ReplacementChunks": []}),
    ("multi_replace_file_content", {"TargetFile": "app.py", "ReplacementChunks": ["x"]}),
    ("multi_replace_file_content", {"TargetFile": "app.py", "ReplacementChunks": [{"ReplacementContent": "y"}]}),
])
def test_malformed_edit_payloads_fail_closed(repo, tool, args):
    root, _ = repo
    assert handle_pre_tool_use(payload(root, tool, args))["decision"] == "deny"


def test_path_traversal_and_outside_workspace_denied(repo):
    root, _ = repo
    for target in ("../outside.py", str(root.parent / "outside.py")):
        out = handle_pre_tool_use(payload(root, "write_to_file", {"TargetFile": target, "CodeContent": "x"}))
        assert out["decision"] == "deny"


def test_invalid_json_on_stdin_denies_pre_and_is_empty_for_post(repo):
    root, _ = repo
    def run(action):
        return subprocess.run([sys.executable, "-m", "securetrace.hooks", action], input="{not json",
                              capture_output=True, text=True, cwd=REPO_ROOT, timeout=30)
    assert json.loads(run("pre_tool_use").stdout)["decision"] == "deny"
    assert json.loads(run("post_tool_use").stdout) == {}


def test_hook_subprocess_roundtrip_matches_in_process(repo):
    root, _ = repo
    p = payload(root, "write_to_file", write_args(root, "app.py", NEW))
    out = subprocess.run([sys.executable, "-m", "securetrace.hooks", "pre_tool_use"], input=json.dumps(p),
                         capture_output=True, text=True, cwd=REPO_ROOT, timeout=30)
    assert json.loads(out.stdout)["decision"] == "force_ask"


def test_unreadable_target_fails_closed(repo, monkeypatch):
    root, _ = repo
    def boom(path):
        raise PermissionError("denied")
    monkeypatch.setattr(approval, "_read_disk_file_bytes", boom)
    assert handle_pre_tool_use(payload(root, "write_to_file", write_args(root, "app.py", NEW)))["decision"] == "deny"


def test_corrupt_ledger_fails_closed_even_for_unprotected_file(repo):
    root, _ = repo
    (root / ".securetrace" / "securetrace.db").write_bytes(b"this is not sqlite" * 50)
    out = handle_pre_tool_use(payload(root, "write_to_file", write_args(root, "notes.txt", "x\n")))
    assert out["decision"] == "deny" and "doctor" in out["reason"]


def test_assessment_exception_fails_closed(repo, monkeypatch):
    root, _ = repo
    monkeypatch.setattr(hooks, "evaluate_proposal", lambda **k: (_ for _ in ()).throw(RuntimeError("kaboom")))
    out = handle_pre_tool_use(payload(root, "write_to_file", write_args(root, "app.py", NEW)))
    assert out["decision"] == "deny" and "kaboom" in out["reason"]


def test_unknown_decision_value_is_not_treated_as_allow(repo, monkeypatch):
    root, _ = repo
    bogus = Proposal(proposal_id="PROP-X", file_path="app.py", canonical_path="x", operation="write",
                     original_hash="", proposed_hash="", proposed_content="", created_at=0, expires_at=1,
                     token="", decision="MAYBE", status="PENDING", warning_text="")
    monkeypatch.setattr(hooks, "evaluate_proposal", lambda **k: bogus)
    assert handle_pre_tool_use(payload(root, "write_to_file", write_args(root, "app.py", NEW)))["decision"] == "deny"


def test_audit_failure_in_pre_hook_still_forces_review_and_says_so(repo, monkeypatch):
    root, _ = repo
    def boom(*a, **k):
        raise OSError("database is locked")
    monkeypatch.setattr(approval, "record_event", boom)
    out = handle_pre_tool_use(payload(root, "write_to_file", write_args(root, "app.py", NEW)))
    assert out["decision"] == "force_ask"                  # never downgraded to allow
    assert "audit trail is incomplete" in out["reason"]
    assert "database is locked" in (root / ".securetrace" / "diagnostics.log").read_text()


# ---------------------------------------------------------------- 4/5: post-action observation
def _review(root, content=NEW):
    out = handle_pre_tool_use(payload(root, "write_to_file", write_args(root, "app.py", content)))
    assert out["decision"] == "force_ask"
    return [p for p in _all(root)][-1]


def _all(root):
    d = root / ".securetrace" / "proposals"
    return sorted((load_proposal(root, f.stem) for f in d.glob("PROP-*.json")), key=lambda p: p.created_at)


def _host_write(root, rel, content):
    """Simulate the HOST completing a write: exact bytes, no newline translation.

    The post-action hook matches on the SHA-256 of the proposed bytes, so the simulated write must
    put exactly those bytes on disk. ``Path.write_text`` without ``newline=""`` would turn every
    "\\n" into "\\r\\n" on Windows and (correctly) be reported as a mismatch.
    """
    (root / rel).write_bytes(content.encode("utf-8"))


def _post(root, **extra):
    return handle_post_tool_use({**payload(root, "write_to_file", write_args(root, "app.py", NEW)), **extra})


def test_post_completed_write_is_matched_to_exactly_that_proposal(repo):
    root, req = repo
    prop = _review(root)
    _host_write(root, "app.py", NEW)
    assert _post(root) == {}
    assert load_proposal(root, prop.proposal_id).status == "APPLIED_BY_HOST"
    ev = events(root, "CHANGE_APPLIED_AFTER_REVIEW")
    assert len(ev) == 1 and ev[0]["requirement_id"] == req and prop.proposal_id in ev[0]["details"]
    assert get_requirement_detail(root, req)["status"] == "STALE"
    # No claim of a host-confirmed decision.
    assert "does not report the user's decision" in ev[0]["details"]
    assert not events(root, "APPROVAL_DENIED") and not events(root, "APPROVAL_APPROVED")


def test_post_when_file_did_not_change_records_no_write(repo):
    root, req = repo
    prop = _review(root)
    _post(root)                                              # host says completed; disk unchanged
    assert load_proposal(root, prop.proposal_id).status == "PENDING"
    assert events(root, "TOOL_COMPLETED_NO_FILE_CHANGE") and not events(root, "CHANGE_APPLIED_AFTER_REVIEW")


def test_post_when_operation_failed(repo):
    root, _ = repo
    prop = _review(root)
    _post(root, error="host: permission denied")
    assert load_proposal(root, prop.proposal_id).status == "PENDING"
    assert events(root, "TOOL_WRITE_FAILED") and not events(root, "TOOL_WRITE_COMPLETED")


def test_intervening_modification_is_not_recorded_as_reviewed_change(repo):
    root, req = repo
    prop = _review(root)
    _host_write(root, "app.py", NEW + "import os  # sneaked in\n")
    _post(root)
    assert load_proposal(root, prop.proposal_id).status == "PENDING"
    assert events(root, "WRITE_DID_NOT_MATCH_REVIEW") and not events(root, "CHANGE_APPLIED_AFTER_REVIEW")
    assert get_requirement_detail(root, req)["status"] == "STALE"       # evidence still invalidated


def test_multiple_identical_pending_proposals_are_ambiguous_not_guessed(repo):
    root, _ = repo
    a, b = _review(root), _review(root)
    assert a.proposal_id != b.proposal_id
    _host_write(root, "app.py", NEW)
    _post(root)
    assert {load_proposal(root, p.proposal_id).status for p in (a, b)} == {"PENDING"}
    amb = events(root, "WRITE_REVIEW_AMBIGUOUS")
    assert amb and a.proposal_id in amb[0]["details"] and b.proposal_id in amb[0]["details"]


def test_two_different_proposals_same_target_only_the_matching_one_is_applied(repo):
    root, _ = repo
    a = _review(root, SRC + "# one\n")
    b = _review(root, SRC + "# two\n")
    _host_write(root, "app.py", SRC + "# two\n")
    _post(root)
    assert load_proposal(root, a.proposal_id).status == "PENDING"
    assert load_proposal(root, b.proposal_id).status == "APPLIED_BY_HOST"


def test_duplicate_post_callback_does_not_double_apply(repo):
    root, _ = repo
    prop = _review(root)
    _host_write(root, "app.py", NEW)
    _post(root); _post(root)
    assert len(events(root, "CHANGE_APPLIED_AFTER_REVIEW")) == 1
    assert load_proposal(root, prop.proposal_id).status == "APPLIED_BY_HOST"


def test_proposal_for_a_different_target_never_matches(repo):
    root, _ = repo
    prop = _review(root)
    _host_write(root, "notes.txt", NEW)            # same bytes, different file
    handle_post_tool_use(payload(root, "write_to_file", write_args(root, "notes.txt", NEW)))
    assert load_proposal(root, prop.proposal_id).status == "PENDING"
    assert not events(root, "CHANGE_APPLIED_AFTER_REVIEW")


def test_late_write_after_review_expiry_is_labelled_not_hidden(repo):
    root, _ = repo
    prop = _review(root)
    sweep_unresolved_reviews(root, now=prop.expires_at + 1)
    assert load_proposal(root, prop.proposal_id).status == "EXPIRED"
    _host_write(root, "app.py", NEW)
    _post(root)
    ev = events(root, "CHANGE_APPLIED_AFTER_REVIEW")
    assert ev and "expired" in ev[0]["details"]


@pytest.mark.parametrize("bad_args", [None, [], {}, {"TargetFile": 3}])
def test_post_with_missing_or_ambiguous_evidence_is_diagnosable_and_returns_empty(repo, bad_args, capsys):
    root, _ = repo
    before = len(events(root))
    out = handle_post_tool_use({"toolCall": {"name": "write_to_file", "args": bad_args}, "workspacePaths": [str(root)]})
    assert out == {}
    assert "SecureTrace post-action warning" in capsys.readouterr().err
    assert len(events(root)) == before                                  # nothing falsely recorded


def test_post_freshness_failure_is_observable_and_host_unaffected(repo, monkeypatch, capsys):
    root, _ = repo
    monkeypatch.setattr(hooks, "mark_changed_files", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("freshness broke")))
    _host_write(root, "app.py", NEW)
    assert _post(root) == {}
    assert events(root, "FRESHNESS_UPDATE_FAILED")
    assert "freshness broke" in (root / ".securetrace" / "diagnostics.log").read_text()
    assert "freshness broke" in capsys.readouterr().err


def test_post_audit_failure_is_diagnosable_and_host_unaffected(repo, monkeypatch, capsys):
    root, _ = repo
    prop = _review(root)
    _host_write(root, "app.py", NEW)
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(hooks, "record_event", boom)
    monkeypatch.setattr(approval, "record_event", boom)
    assert _post(root) == {}                                            # never raises into the host
    log = (root / ".securetrace" / "diagnostics.log").read_text()
    assert "disk full" in log and "post-action handling failed" in log or "not recorded" in log
    assert "SecureTrace post-action warning" in capsys.readouterr().err


# ---------------------------------------------------------------- 5. lifecycle (standalone path)
def test_host_denial_without_callback_is_never_recorded_as_denied(repo):
    """The host gives no structured denial. Expiry with no write must say 'no write observed', not DENIED."""
    root, _ = repo
    prop = _review(root)
    closed = sweep_unresolved_reviews(root, now=prop.expires_at + 1)
    assert closed == [prop.proposal_id]
    assert load_proposal(root, prop.proposal_id).status == "EXPIRED"
    assert events(root, "REVIEW_NO_WRITE_OBSERVED") and not events(root, "APPROVAL_DENIED")
    assert sweep_unresolved_reviews(root, now=prop.expires_at + 2) == []     # idempotent


def test_sweep_does_not_erase_history(repo):
    root, _ = repo
    prop = _review(root)
    n = len(events(root))
    sweep_unresolved_reviews(root, now=prop.expires_at + 1)
    assert len(events(root)) > n and (root / ".securetrace" / "proposals" / f"{prop.proposal_id}.json").is_file()


def test_standalone_apply_success_records_one_event_per_requirement(repo):
    root, req = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    assert p.status == "PENDING" and events(root, "APPROVAL_APPLIED") == []
    done = apply_proposal(root, p.proposal_id, p.token)
    assert done.status == "APPLIED" and (root / "app.py").read_text() == NEW
    ev = events(root, "APPROVAL_APPLIED")
    assert [e["requirement_id"] for e in ev] == [req]
    assert done.audit_errors == []
    assert get_requirement_detail(root, req)["status"] == "STALE"


def test_replay_is_rejected_and_recorded(repo):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    apply_proposal(root, p.proposal_id, p.token)
    with pytest.raises(ValueError, match="Replay rejected"):
        apply_proposal(root, p.proposal_id, p.token)
    assert len(events(root, "APPROVAL_APPLIED")) == 1 and events(root, "APPROVAL_APPLY_REJECTED")


def test_approval_token_is_required_and_bound_to_proposal(repo):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    q = evaluate_proposal(root, "app.py", content=SRC + "# other\n")
    for bad in ("", "deadbeef", q.token):
        with pytest.raises(ValueError, match="Invalid approval token"):
            apply_proposal(root, p.proposal_id, bad)
    assert (root / "app.py").read_text() == SRC


def test_unknown_proposal_id(repo):
    root, _ = repo
    with pytest.raises(ValueError, match="not found"):
        apply_proposal(root, "PROP-DOESNOTEXIST", "x")
    with pytest.raises(ValueError, match="not found"):
        deny_proposal(root, "PROP-DOESNOTEXIST")


def test_proposal_retargeted_to_other_file_is_rejected(repo):
    """Proposal ID associated with the wrong target: editing file_path in the record breaks the token."""
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    f = root / ".securetrace" / "proposals" / f"{p.proposal_id}.json"
    data = json.loads(f.read_text()); data["file_path"] = "notes.txt"; data["canonical_path"] = str(root / "notes.txt")
    f.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Invalid approval token"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "notes.txt").read_text() == "hello\n"


def test_tampered_proposed_content_is_rejected_even_with_valid_token(repo):
    """The token binds hashes, not the stored text: apply must re-hash the content it is about to write."""
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    f = root / ".securetrace" / "proposals" / f"{p.proposal_id}.json"
    data = json.loads(f.read_text()); data["proposed_content"] = "import os; os.system('x')\n"
    f.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="integrity"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == SRC


def test_expired_proposal_is_not_applied_and_expiry_is_not_a_denial(repo):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW, timeout_seconds=-1)
    with pytest.raises(ValueError, match="expired"):
        apply_proposal(root, p.proposal_id, p.token)
    assert load_proposal(root, p.proposal_id).status == "EXPIRED"
    assert events(root, "APPROVAL_EXPIRED") and not events(root, "APPROVAL_DENIED")
    assert (root / "app.py").read_text() == SRC


def test_denied_proposal_cannot_be_applied_and_deny_is_idempotent(repo):
    root, req = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    deny_proposal(root, p.proposal_id); deny_proposal(root, p.proposal_id)
    assert [e["requirement_id"] for e in events(root, "APPROVAL_DENIED")] == [req]
    with pytest.raises(ValueError, match="denied"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == SRC


def test_cannot_deny_an_applied_proposal(repo):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    apply_proposal(root, p.proposal_id, p.token)
    with pytest.raises(ValueError, match="already been applied"):
        deny_proposal(root, p.proposal_id)


def test_failed_application_is_recorded_and_leaves_original(repo):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    _host_write(root, "app.py", SRC + "# someone else\n")
    with pytest.raises(ValueError, match="Concurrent modification"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == SRC + "# someone else\n"
    assert events(root, "APPROVAL_APPLY_REJECTED") and not events(root, "APPROVAL_APPLIED")
    assert load_proposal(root, p.proposal_id).status == "PENDING"


def test_post_apply_audit_failure_is_reported_not_hidden(repo, monkeypatch):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    def boom(*a, **k):
        raise OSError("ledger unavailable")
    monkeypatch.setattr(approval, "record_event", boom)
    done = apply_proposal(root, p.proposal_id, p.token)        # the file write cannot be undone, so no raise
    assert (root / "app.py").read_text() == NEW and done.status == "APPLIED"
    assert any("ledger unavailable" in e for e in done.audit_errors)
    assert load_proposal(root, p.proposal_id).audit_errors     # persisted for later inspection


def test_freshness_failure_after_apply_is_reported(repo, monkeypatch):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    monkeypatch.setattr(approval, "mark_changed_files", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stale-update broke")))
    done = apply_proposal(root, p.proposal_id, p.token)
    assert any("freshness" in e.lower() and "stale-update broke" in e for e in done.audit_errors)


def test_concurrent_apply_of_one_proposal_applies_exactly_once(repo):
    root, _ = repo
    p = evaluate_proposal(root, "app.py", content=NEW)
    results, barrier = [], threading.Barrier(6)
    def go():
        barrier.wait()
        try:
            apply_proposal(root, p.proposal_id, p.token); results.append("ok")
        except ValueError as exc:
            results.append(str(exc)[:40])
    threads = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert results.count("ok") == 1, results
    assert (root / "app.py").read_text() == NEW
    assert len(events(root, "APPROVAL_APPLIED")) == 1
    assert not list((root / ".securetrace" / "locks").glob("*.lock"))   # no stuck locks


def test_historical_records_and_events_remain_readable(repo):
    """A pre-Phase-3 proposal JSON (no new keys) and old event names still load and display."""
    root, req = repo
    legacy = {"proposal_id": "PROP-LEGACY000001", "file_path": "app.py", "canonical_path": str(root / "app.py"),
              "operation": "write", "original_hash": "", "proposed_hash": "", "proposed_content": "",
              "created_at": 1.0, "expires_at": 2.0, "token": "t", "decision": "FORCE_ASK", "status": "EXPIRED",
              "warning_text": "old"}
    (root / ".securetrace" / "proposals").mkdir(parents=True, exist_ok=True)
    (root / ".securetrace" / "proposals" / "PROP-LEGACY000001.json").write_text(json.dumps(legacy))
    old = load_proposal(root, "PROP-LEGACY000001")
    assert old.status == "EXPIRED" and old.analysis_status == "" and old.encoding == "utf-8"
    from securetrace.ledger import record_event
    record_event(root, req, "SOME_FUTURE_OR_OLD_EVENT", "kept verbatim")
    assert get_requirement_detail(root, req)
    assert events(root, "SOME_FUTURE_OR_OLD_EVENT")[0]["details"] == "kept verbatim"
    assert sweep_unresolved_reviews(root) == []                         # EXPIRED legacy records are left alone


def test_opening_existing_database_preserves_history(repo):
    root, req = repo
    before = events(root)
    for _ in range(3):
        migrate_mappings(root)
        with connect(root):
            pass
    assert [e["id"] for e in events(root)][:len(before)] == [e["id"] for e in before]
