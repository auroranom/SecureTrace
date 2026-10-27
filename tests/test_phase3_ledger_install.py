"""Phase 3: ledger/freshness semantics and installation behaviour (tmp dirs only)."""
from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from securetrace import dependencies, doctor
from securetrace.db import LedgerError, connect, migrate_mappings
from securetrace.hook_install import (
    FILE_TOOL_MATCHER, HOOK_NAME, build_hook_entry, install_hooks,
)
from securetrace.ledger import (
    add_requirement, get_requirement_detail, mark_changed_files, normalize_path, record_check, record_event,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _events(root, etype):
    with connect(root) as db:
        return [dict(r) for r in db.execute("SELECT * FROM events WHERE event_type=?", (etype,))]


# ------------------------------------------------------------------ ledger
def test_first_run_initialisation_and_no_overwrite(tmp_path):
    assert not (tmp_path / ".securetrace").exists()
    with connect(tmp_path) as db:
        db.execute("INSERT INTO events(requirement_id,event_type,details,created_at) VALUES(NULL,'KEEP','x','t')")
    first = (tmp_path / ".securetrace" / "securetrace.db").read_bytes()
    for _ in range(3):
        with connect(tmp_path):
            pass
        migrate_mappings(tmp_path)
    assert len(_events(tmp_path, "KEEP")) == 1


def test_corrupt_ledger_gives_actionable_error_and_is_left_untouched(tmp_path):
    db = tmp_path / ".securetrace" / "securetrace.db"
    db.parent.mkdir()
    junk = b"not a database" * 100
    db.write_bytes(junk)
    with pytest.raises(LedgerError, match="NOT been modified"):
        with connect(tmp_path):
            pass
    assert db.read_bytes() == junk                       # never replaced or truncated
    assert isinstance(LedgerError("x"), sqlite3.DatabaseError)


@pytest.mark.parametrize("bad", ["/etc/passwd", "../x.py", "a/../../x.py", "C:\\x.py", "C:/x.py", "a\x00b"])
def test_requirement_registration_rejects_non_project_relative_paths(tmp_path, bad):
    with pytest.raises(ValueError):
        add_requirement(tmp_path, "t", "d", file_paths=[bad])


def test_registration_normalises_paths_deterministically(tmp_path):
    r = add_requirement(tmp_path, "t", "d", file_paths=["./a//b.py", "a/b.py", "a\\b.py", "a/./b.py"])
    assert r["file_paths"] == ["a/b.py"]
    assert normalize_path("./x\\y//z.py") == "x/y/z.py"


def _transitive_project(tmp_path):
    (tmp_path / "app.py").write_text("import mid\n")
    (tmp_path / "mid.py").write_text("import leaf\n")
    (tmp_path / "leaf.py").write_text("V = 1\n")
    (tmp_path / "unrelated.py").write_text("U = 1\n")
    migrate_mappings(tmp_path)
    req = add_requirement(tmp_path, "t", "d", category="authorization", severity="high", file_paths=["app.py"])["id"]
    record_check(tmp_path, req, "c", True, verification_complete=True)
    return req


def test_unrelated_modification_does_not_stale_evidence(tmp_path):
    req = _transitive_project(tmp_path)
    (tmp_path / "unrelated.py").write_text("U = 2\n")
    assert mark_changed_files(tmp_path, ["unrelated.py"]) == []
    assert get_requirement_detail(tmp_path, req)["status"] == "VERIFIED"


def test_direct_change_stales_evidence(tmp_path):
    req = _transitive_project(tmp_path)
    mark_changed_files(tmp_path, ["app.py"])
    assert get_requirement_detail(tmp_path, req)["status"] == "STALE"


@pytest.mark.parametrize("changed", ["mid.py", "leaf.py"])
def test_direct_and_transitive_dependency_changes_stale_evidence(tmp_path, changed):
    """Regression: only directly linked files used to invalidate evidence; imports of imports did not."""
    req = _transitive_project(tmp_path)
    (tmp_path / changed).write_text("V = 2\n" if changed == "leaf.py" else "import leaf\n# edited\n")
    results = mark_changed_files(tmp_path, [changed])
    assert [r["requirement_id"] for r in results] == [req]
    assert get_requirement_detail(tmp_path, req)["status"] == "STALE"
    assert _events(tmp_path, "LINKED_FILE_CHANGED")


def test_transitive_graph_failure_still_invalidates_direct_and_is_not_reported_as_success(tmp_path, monkeypatch):
    req = _transitive_project(tmp_path)
    monkeypatch.setattr(dependencies, "build_local_dependency_graph", lambda root: (_ for _ in ()).throw(RuntimeError("graph down")))
    with pytest.raises(RuntimeError, match="incomplete"):
        mark_changed_files(tmp_path, ["app.py"])
    assert get_requirement_detail(tmp_path, req)["status"] == "STALE"   # direct part was still applied


def test_duplicate_events_within_window_are_suppressed_without_rewriting_history(tmp_path):
    assert record_event(tmp_path, None, "X", "same", dedupe_seconds=60) is True
    assert record_event(tmp_path, None, "X", "same", dedupe_seconds=60) is False
    assert record_event(tmp_path, None, "X", "different", dedupe_seconds=60) is True
    assert len(_events(tmp_path, "X")) == 2


def test_event_write_is_atomic_on_failure(tmp_path):
    with pytest.raises(RuntimeError):
        with connect(tmp_path) as db:
            db.execute("INSERT INTO events(requirement_id,event_type,details,created_at) VALUES(NULL,'HALF','x','t')")
            raise RuntimeError("boom")
    assert _events(tmp_path, "HALF") == []


# ------------------------------------------------------------------ installation
def test_install_creates_valid_config_with_matching_matcher(tmp_path):
    out = install_hooks(tmp_path, sys.executable)
    cfg = json.loads(out.read_text(encoding="utf-8"))
    for event in ("PreToolUse", "PostToolUse"):
        assert cfg[HOOK_NAME][event][0]["matcher"] == FILE_TOOL_MATCHER


def test_install_preserves_other_hooks_and_never_overwrites_first_backup(tmp_path):
    (tmp_path / ".agents").mkdir()
    cfg = tmp_path / ".agents" / "hooks.json"
    cfg.write_text(json.dumps({"mine": {"keep": True}}), encoding="utf-8")
    install_hooks(tmp_path, sys.executable)
    first_backup = (tmp_path / ".agents" / "hooks.json.securetrace-backup").read_text()
    assert json.loads(first_backup) == {"mine": {"keep": True}}
    install_hooks(tmp_path, sys.executable)                   # second install must not clobber backup #1
    assert (tmp_path / ".agents" / "hooks.json.securetrace-backup").read_text() == first_backup
    assert json.loads(cfg.read_text())["mine"] == {"keep": True}
    assert len(list((tmp_path / ".agents").glob("hooks.json.securetrace-backup*"))) == 2


def test_install_refuses_invalid_existing_json_without_modifying_it(tmp_path):
    (tmp_path / ".agents").mkdir()
    cfg = tmp_path / ".agents" / "hooks.json"
    cfg.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        install_hooks(tmp_path, sys.executable)
    assert cfg.read_text() == "{broken"


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell quoting")
def test_posix_command_quoting_roundtrips_awkward_interpreter_paths():
    for exe in ("/opt/My Python/bin/python", "/opt/q'uote/python", "/opt/$HOME/py`x`/python", '/opt/dq"/python'):
        cmd = build_hook_entry(exe)["PreToolUse"][0]["hooks"][0]["command"]
        assert shlex.split(cmd) == [exe, "-m", "securetrace.hooks", "pre_tool_use"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink/shell")
def test_generated_hook_command_actually_runs_from_a_path_with_spaces_and_special_chars(tmp_path):
    """End-to-end on POSIX: install, then execute the generated command string through a shell."""
    fancy = tmp_path / "My Py $dir"
    fancy.mkdir()
    exe = fancy / "python"
    try:
        exe.symlink_to(Path(sys.executable))
    except OSError:
        pytest.skip("symlinks unavailable")
    project = tmp_path / "work space"
    project.mkdir()
    (project / "n.txt").write_text("a\n")
    cfg = json.loads(install_hooks(project, str(exe)).read_text())
    cmd = cfg[HOOK_NAME]["PreToolUse"][0]["hooks"][0]["command"]
    payload = {"toolCall": {"name": "write_to_file", "args": {"TargetFile": "n.txt", "CodeContent": "b\n"}},
               "workspacePaths": [str(project)]}
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    out = subprocess.run(cmd, shell=True, input=json.dumps(payload), capture_output=True, text=True, cwd=project, env=env, timeout=60)
    assert json.loads(out.stdout)["decision"] == "allow", (out.stdout, out.stderr)   # no requirements registered -> no-impact allow


def test_windows_path_with_spaces_uses_wrapper_with_crlf_and_percent_escaping(tmp_path):
    """String-level check of Windows output (generated on any OS); NOT executed under cmd.exe here."""
    exe = r"C:\Program Files\Python 311\100%\python.exe"
    out = install_hooks(tmp_path, exe)
    wrapper = (tmp_path / ".agents" / "securetrace_hook.cmd").read_bytes()
    assert wrapper == b'@"C:\\Program Files\\Python 311\\100%%\\python.exe" -m securetrace.hooks %*\r\n'
    cmd = json.loads(out.read_text())[HOOK_NAME]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.startswith("call .agents\\securetrace_hook.cmd pre_tool_use")
    assert "Program Files" not in cmd                         # nothing with spaces left for cmd/Go to mis-quote


def test_windows_non_ascii_path_with_spaces_fails_clearly_instead_of_writing_a_bad_wrapper(tmp_path):
    with pytest.raises(ValueError, match="non-ASCII"):
        install_hooks(tmp_path, "C:\\Users\\Zoë Müller\\py env\\python.exe")
    assert not (tmp_path / ".agents" / "securetrace_hook.cmd").exists()


# ------------------------------------------------------------------ doctor
def test_doctor_reports_real_state_and_does_not_modify(tmp_path):
    checks = doctor.run_checks(tmp_path)
    by = {c.name: c for c in checks}
    assert by["ledger"].status == "WARN" and "does not exist" in by["ledger"].detail
    assert by["hooks.json"].status == "WARN"
    assert not (tmp_path / ".securetrace").exists() and not (tmp_path / ".agents").exists()   # read-only


def test_doctor_detects_unusable_hook_interpreter_and_corrupt_ledger(tmp_path):
    install_hooks(tmp_path, str(tmp_path / "nope" / "python"))
    (tmp_path / ".securetrace").mkdir()
    (tmp_path / ".securetrace" / "securetrace.db").write_bytes(b"garbage" * 200)
    by = {c.name: c for c in doctor.run_checks(tmp_path)}
    assert by["ledger"].status == "FAIL"
    assert by["hook PreToolUse"].status == "FAIL" and "not found" in by["hook PreToolUse"].detail


def test_doctor_ok_when_hook_interpreter_can_import_package(tmp_path):
    migrate_mappings(tmp_path)
    install_hooks(tmp_path, sys.executable)
    env_path = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(REPO_ROOT) + (os.pathsep + env_path if env_path else "")
    try:
        by = {c.name: c for c in doctor.run_checks(tmp_path)}
    finally:
        os.environ.pop("PYTHONPATH") if env_path is None else os.environ.__setitem__("PYTHONPATH", env_path)
    assert by["hook PreToolUse"].status == "OK" and by["ledger"].status == "OK"


def test_cli_doctor_exit_code_reflects_failures(tmp_path):
    (tmp_path / ".securetrace").mkdir()
    (tmp_path / ".securetrace" / "securetrace.db").write_bytes(b"garbage" * 200)
    env = {**os.environ, "SECURETRACE_PROJECT_ROOT": str(tmp_path), "PYTHONPATH": str(REPO_ROOT)}
    r = subprocess.run([sys.executable, "-m", "securetrace.cli", "doctor"], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)
    assert r.returncode == 1 and "[FAIL] ledger" in r.stdout


def test_importing_package_does_not_require_windows_only_modules():
    """winotify is Windows-only; the CLI/MCP/monitor modules must import on every platform."""
    code = "import securetrace.cli, securetrace.monitor, securetrace.mcp_server"
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO_ROOT, timeout=60)
    assert r.returncode == 0, r.stderr
