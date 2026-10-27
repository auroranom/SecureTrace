"""Phase 3: filesystem safety for the MEDIATED application path (apply_proposal).

Scope honesty: these tests exercise SecureTrace's own write path on POSIX (symlinks,
modes, hard links) in tmp_path. They do not and cannot prove protection against other
programs writing the file (editors, shells, the host), and the unavoidable window
between the final re-check and os.replace is not closable portably (see README
"Filesystem threat model"); the race tests below simulate a writer that strikes at the
most inconvenient moment that IS observable, and show the newer content is never lost.
"""
from __future__ import annotations

import os
import stat
import tempfile
import threading
from pathlib import Path

import pytest

from securetrace import approval
from securetrace.approval import apply_proposal, evaluate_proposal, resolve_project_relative_path
from securetrace.db import migrate_mappings
from securetrace.ledger import add_requirement

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission/symlink/hard-link semantics")


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported/permitted in this environment")


@pytest.fixture
def root(tmp_path):
    proj = tmp_path / "proj dir"          # a space on purpose
    proj.mkdir()
    (proj / "app.py").write_text("A = 1\n", encoding="utf-8")
    (proj / "other.py").write_text("B = 1\n", encoding="utf-8")
    migrate_mappings(proj)
    add_requirement(proj, "r", "d", category="authorization", severity="high", file_paths=["app.py"])
    return proj


def _leftovers(root: Path):
    return [p for p in root.rglob("*") if p.name.startswith(".sec_tmp_")]


# ------------------------------------------------------------------ path containment
def test_relative_and_absolute_paths_inside_project(root):
    rel, res = resolve_project_relative_path(root, "app.py")
    assert rel == "app.py" and res == (root / "app.py").resolve()
    assert resolve_project_relative_path(root, str(root / "app.py"))[0] == "app.py"
    (root / "sub").mkdir()
    assert resolve_project_relative_path(root, "sub/../app.py")[0] == "app.py"     # normalises, still inside
    assert resolve_project_relative_path(root, "sub/new_file.py")[0] == "sub/new_file.py"  # not-yet-existing


@pytest.mark.parametrize("bad", ["../x.py", "sub/../../x.py", "", "   ", "a\x00b.py"])
def test_traversal_and_invalid_paths_rejected(root, bad):
    (root / "sub").mkdir(exist_ok=True)
    with pytest.raises(ValueError):
        resolve_project_relative_path(root, bad)


def test_absolute_path_outside_project_rejected(root, tmp_path):
    with pytest.raises(ValueError):
        resolve_project_relative_path(root, str(tmp_path / "elsewhere.py"))


@posix_only
def test_symlink_pointing_outside_project_rejected(root, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n")
    _symlink(root / "escape.py", outside)
    with pytest.raises(ValueError):
        resolve_project_relative_path(root, "escape.py")
    with pytest.raises(ValueError):
        evaluate_proposal(root, "escape.py", content="x = 1\n")
    assert outside.read_text() == "SECRET = 1\n"


@posix_only
def test_symlink_inside_project_resolves_to_real_file_and_is_preserved(root):
    _symlink(root / "alias.py", root / "app.py")
    rel, res = resolve_project_relative_path(root, "alias.py")
    assert res == (root / "app.py").resolve()
    p = evaluate_proposal(root, "alias.py", content="A = 2\n")
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / "alias.py").is_symlink()                      # link kept; real target rewritten
    assert (root / "app.py").read_text() == "A = 2\n"


@posix_only
def test_symlink_retargeted_after_assessment_cannot_redirect_the_write(root):
    """Proposals bind to the RESOLVED file at review time, so re-pointing the alias is harmless:
    the reviewed file receives the reviewed content and the new target is never touched."""
    _symlink(root / "alias.py", root / "app.py")
    p = evaluate_proposal(root, "alias.py", content="A = 2\n")
    assert p.file_path == "app.py"
    (root / "alias.py").unlink()
    _symlink(root / "alias.py", root / "other.py")
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / "other.py").read_text() == "B = 1\n"          # never touched
    assert (root / "app.py").read_text() == "A = 2\n"           # the reviewed file


@posix_only
def test_symlink_retargeted_outside_project_after_assessment_cannot_escape(root, tmp_path):
    _symlink(root / "alias.py", root / "app.py")
    p = evaluate_proposal(root, "alias.py", content="A = 2\n")
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n")
    (root / "alias.py").unlink()
    _symlink(root / "alias.py", outside)
    apply_proposal(root, p.proposal_id, p.token)
    assert outside.read_text() == "SECRET = 1\n"
    assert (root / "app.py").read_text() == "A = 2\n"


@posix_only
def test_reviewed_file_replaced_by_symlink_after_assessment_is_refused(root, tmp_path):
    """The reviewed path itself is swapped for a symlink to another in-project file: identity changed."""
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    (root / "app.py").unlink()
    _symlink(root / "app.py", root / "other.py")
    with pytest.raises(ValueError, match="Target identity changed"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "other.py").read_text() == "B = 1\n"


@posix_only
def test_parent_directory_swapped_for_symlink_after_assessment_is_refused(root):
    (root / "pkg").mkdir()
    (root / "pkg" / "m.py").write_text("M = 1\n")
    (root / "evil").mkdir()
    (root / "evil" / "m.py").write_text("M = 1\n")                   # identical bytes: only identity differs
    p = evaluate_proposal(root, "pkg/m.py", content="M = 2\n")
    (root / "pkg" / "m.py").unlink(); (root / "pkg").rmdir()
    _symlink(root / "pkg", root / "evil")
    with pytest.raises(ValueError, match="Target identity changed"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "evil" / "m.py").read_text() == "M = 1\n"


# ------------------------------------------------------------------ races / CAS
def test_target_modified_after_review_is_never_silently_overwritten(root):
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    (root / "app.py").write_text("A = 99  # newer\n")
    with pytest.raises(ValueError, match="Concurrent modification"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == "A = 99  # newer\n"
    assert not _leftovers(root)


def test_target_replaced_between_validation_and_write_keeps_newer_content(root, monkeypatch):
    """A writer strikes right after our temp file exists, i.e. after the first CAS check passed."""
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    real = tempfile.mkstemp
    def racing_mkstemp(*a, **k):
        fd, path = real(*a, **k)
        (root / "app.py").write_text("A = 'racer'\n")
        return fd, path
    monkeypatch.setattr(approval.tempfile, "mkstemp", racing_mkstemp)
    with pytest.raises(ValueError, match="changed between validation and write|Concurrent|changed"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == "A = 'racer'\n"
    assert not _leftovers(root)


def test_failure_during_replace_cleans_temp_and_preserves_original(root, monkeypatch):
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    def boom(src, dst):
        raise OSError("simulated replace failure")
    monkeypatch.setattr(approval.os, "replace", boom)
    with pytest.raises(OSError):
        apply_proposal(root, p.proposal_id, p.token)
    monkeypatch.undo()
    assert (root / "app.py").read_text() == "A = 1\n" and not _leftovers(root)


def test_two_proposals_for_same_file_exactly_one_wins(root):
    a = evaluate_proposal(root, "app.py", content="A = 'a'\n")
    b = evaluate_proposal(root, "app.py", content="A = 'b'\n")
    outcomes, barrier = [], threading.Barrier(2)
    def go(p):
        barrier.wait()
        try:
            apply_proposal(root, p.proposal_id, p.token); outcomes.append("ok")
        except ValueError as exc:
            outcomes.append("blocked")
    ts = [threading.Thread(target=go, args=(p,)) for p in (a, b)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sorted(outcomes) == ["blocked", "ok"]
    assert (root / "app.py").read_text() in ("A = 'a'\n", "A = 'b'\n")
    assert not _leftovers(root)


def test_stale_lock_from_crashed_process_does_not_deadlock(root):
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    lock_dir = root / ".securetrace" / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    import hashlib
    lock = lock_dir / (hashlib.sha256(p.canonical_path.encode()).hexdigest()[:24] + ".lock")
    lock.write_text("99999 0")
    old = lock.stat().st_mtime - 3600
    os.utime(lock, (old, old))
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == "A = 2\n"


def test_live_lock_blocks_with_clear_error_not_a_silent_overwrite(root, monkeypatch):
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    monkeypatch.setattr(approval, "LOCK_WAIT_SECONDS", 0.2)
    import hashlib
    lock_dir = root / ".securetrace" / "locks"; lock_dir.mkdir(parents=True, exist_ok=True)
    (lock_dir / (hashlib.sha256(p.canonical_path.encode()).hexdigest()[:24] + ".lock")).write_text("1 1")
    with pytest.raises(ValueError, match="holds the lock"):
        apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == "A = 1\n"


# ------------------------------------------------------------------ metadata / encoding
@posix_only
def test_existing_file_permissions_are_preserved(root):
    os.chmod(root / "app.py", 0o751)
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    apply_proposal(root, p.proposal_id, p.token)
    assert stat.S_IMODE((root / "app.py").stat().st_mode) == 0o751


@posix_only
def test_new_file_gets_normal_mode_not_mkstemp_0600(root):
    p = evaluate_proposal(root, "created.py", content="X = 1\n")
    apply_proposal(root, p.proposal_id, p.token)
    assert stat.S_IMODE((root / "created.py").stat().st_mode) == 0o644


def test_non_utf8_file_keeps_untouched_bytes(root):
    raw = b"# caf\xe9 \xff\nA = 1\n"
    (root / "latin.py").write_bytes(raw)
    p = evaluate_proposal(root, "latin.py", operation="edit", target_pattern="A = 1", replacement_pattern="A = 2")
    assert p.encoding == "latin-1"
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / "latin.py").read_bytes() == b"# caf\xe9 \xff\nA = 2\n"          # \xe9 and \xff intact


def test_non_utf8_file_refuses_unrepresentable_replacement(root):
    (root / "latin.py").write_bytes(b"# caf\xe9\nA = 1\n")
    with pytest.raises(ValueError, match="cannot be represented"):
        evaluate_proposal(root, "latin.py", operation="edit", target_pattern="A = 1", replacement_pattern="A = '\u4e2d'")
    assert (root / "latin.py").read_bytes() == b"# caf\xe9\nA = 1\n"


def test_crlf_and_bom_are_preserved(root):
    raw = b"\xef\xbb\xbfA = 1\r\nB = 2\r\n"
    (root / "win.py").write_bytes(raw)
    p = evaluate_proposal(root, "win.py", operation="edit", target_pattern="B = 2", replacement_pattern="B = 3")
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / "win.py").read_bytes() == b"\xef\xbb\xbfA = 1\r\nB = 3\r\n"


@posix_only
def test_hard_link_is_broken_by_atomic_replace_and_other_link_keeps_old_content(root):
    """Documented trade-off: replace-by-rename gives the target a new inode; other names keep the old bytes."""
    try:
        os.link(root / "app.py", root / "app_hardlink.py")
    except OSError:
        pytest.skip("hard links not supported here")
    p = evaluate_proposal(root, "app.py", content="A = 2\n")
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / "app.py").read_text() == "A = 2\n"
    assert (root / "app_hardlink.py").read_text() == "A = 1\n"


def test_project_path_with_spaces_and_unicode_name(root):
    name = "módulo núcleo.py"
    (root / name).write_text("Z = 1\n", encoding="utf-8")
    p = evaluate_proposal(root, name, content="Z = 2\n")
    apply_proposal(root, p.proposal_id, p.token)
    assert (root / name).read_text(encoding="utf-8") == "Z = 2\n"
