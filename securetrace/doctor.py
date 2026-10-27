"""``securetrace doctor``: real, read-only installation and runtime diagnostics.

Every check performs the thing it reports on (opens the DB, imports the package with the
interpreter the hook will use, parses hooks.json). It never creates, repairs or deletes
anything, and it never reports OK for a check it could not perform.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
from dataclasses import dataclass

from .hook_install import FILE_TOOL_MATCHER, HOOK_NAME, WRAPPER_BAT_NAME

MIN_PYTHON = (3, 11)


@dataclass
class Check:
    status: str   # OK | WARN | FAIL
    name: str
    detail: str
    remedy: str = ""

    def line(self) -> str:
        text = f"[{self.status:<4}] {self.name}: {self.detail}"
        return text + (f"\n         -> {self.remedy}" if self.remedy and self.status != "OK" else "")


def _hook_interpreter(project: Path, command: str) -> tuple[str | None, str]:
    """Extract the interpreter a configured hook command will run. Returns (path, note)."""
    if WRAPPER_BAT_NAME in command:
        wrapper = project / ".agents" / WRAPPER_BAT_NAME
        if not wrapper.is_file():
            return None, f"command uses {WRAPPER_BAT_NAME} but {wrapper} does not exist"
        first = wrapper.read_text(encoding="ascii", errors="replace").strip().splitlines()[0]
        if first.startswith('@"') and '"' in first[2:]:
            return first[2:].split('"', 1)[0].replace("%%", "%"), "via wrapper"
        return None, f"cannot parse interpreter from {wrapper}"
    try:
        parts = shlex.split(command, posix=(os.name != "nt"))
    except ValueError as exc:
        return None, f"cannot parse command ({exc})"
    return (parts[0].strip('"') if parts else None), "direct"


def run_checks(project: Path) -> list[Check]:
    checks: list[Check] = []
    add = checks.append

    if sys.version_info >= MIN_PYTHON:
        add(Check("OK", "python", f"{sys.version.split()[0]} at {sys.executable}"))
    else:
        add(Check("FAIL", "python", f"{sys.version.split()[0]} is older than {'.'.join(map(str, MIN_PYTHON))}",
                  "Use Python 3.11+ (see pyproject.toml requires-python)."))

    for module, why in (("watchdog", "`securetrace watch`"), ("mcp", "the MCP server (`securetrace-mcp`)"), ("pytest", "`securetrace run-test` and the test suite")):
        if importlib.util.find_spec(module):
            add(Check("OK", f"dependency {module}", "importable"))
        else:
            add(Check("WARN", f"dependency {module}", f"not installed; needed for {why}", "pip install -e \".[dev]\" from the repository root."))

    if not project.is_dir():
        add(Check("FAIL", "project root", f"{project} is not a directory", "Run from the project, or set SECURETRACE_PROJECT_ROOT."))
        return checks
    add(Check("OK", "project root", str(project)))
    if not (project / "pyproject.toml").is_file():
        add(Check("WARN", "pyproject.toml", "missing at project root", "`securetrace map-test` requires it (test targets are validated against the project)."))

    st_dir = project / ".securetrace"
    db_path = st_dir / "securetrace.db"
    if not db_path.exists():
        add(Check("WARN", "ledger", f"{db_path} does not exist yet", "Run `securetrace init`. It is created on first use and never overwritten."))
    else:
        try:
            con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5)
            try:
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0] if "events" in tables else 0
            finally:
                con.close()
            missing = {"requirements", "requirement_files", "events"} - tables
            if missing:
                add(Check("FAIL", "ledger", f"opened but missing tables {sorted(missing)}", "Back it up, then run `securetrace init`."))
            else:
                add(Check("OK", "ledger", f"readable ({events} audit events)"))
                if "requirement_tests" not in tables:
                    add(Check("WARN", "ledger schema", "requirement_tests table absent", "Run `securetrace migrate` (additive) to enable test mapping."))
        except sqlite3.DatabaseError as exc:
            add(Check("FAIL", "ledger", f"cannot be opened: {exc}", "Do NOT delete it (audit history). Restore from backup or move it aside deliberately."))
        if not os.access(st_dir, os.W_OK):
            add(Check("FAIL", "ledger directory", f"{st_dir} is not writable", "Hooks cannot record reviews; fix directory permissions."))

    cfg_path = project / ".agents" / "hooks.json"
    if not cfg_path.is_file():
        add(Check("WARN", "hooks.json", f"{cfg_path} not found", "Run `securetrace install-hooks`."))
    else:
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            entry = cfg[HOOK_NAME]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            add(Check("FAIL", "hooks.json", f"invalid or missing '{HOOK_NAME}' entry ({type(exc).__name__})", "Run `securetrace install-hooks` (your file is backed up first)."))
        else:
            for event in ("PreToolUse", "PostToolUse"):
                try:
                    group = entry[event][0]
                    command = group["hooks"][0]["command"]
                except (KeyError, IndexError, TypeError):
                    add(Check("FAIL", f"hooks.json {event}", "entry missing or malformed", "Run `securetrace install-hooks`."))
                    continue
                if set(group.get("matcher", "").split("|")) != set(FILE_TOOL_MATCHER.split("|")):
                    add(Check("WARN", f"hooks.json {event}", "matcher differs from the tools SecureTrace implements", "Re-run `securetrace install-hooks`."))
                exe, how = _hook_interpreter(project, command)
                if not exe:
                    add(Check("FAIL", f"hook {event}", how, "Re-run `securetrace install-hooks`."))
                elif not Path(exe).is_file():
                    add(Check("FAIL", f"hook {event}", f"interpreter not found: {exe} ({how})", "Re-run `securetrace install-hooks --python <path>` from the right environment."))
                else:
                    try:
                        out = subprocess.run([exe, "-c", "import securetrace,sys;print(securetrace.__file__)"],
                                             cwd=project, capture_output=True, text=True, timeout=30)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        add(Check("FAIL", f"hook {event}", f"could not run {exe}: {exc}"))
                        continue
                    if out.returncode == 0:
                        add(Check("OK", f"hook {event}", f"{exe} imports securetrace ({out.stdout.strip()})"))
                    else:
                        add(Check("FAIL", f"hook {event}", f"{exe} cannot import securetrace: {out.stderr.strip().splitlines()[-1] if out.stderr.strip() else 'unknown error'}",
                                  "pip install -e . in that interpreter's environment. A hook that cannot start is host-defined behaviour and may not block edits."))

    log = st_dir / "diagnostics.log"
    if log.is_file():
        lines = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        if lines:
            add(Check("WARN", "diagnostics.log", f"{len(lines)} recorded problem(s); latest: {lines[-1][:200]}", f"Inspect {log}."))
    return checks


def main(project: Path) -> int:
    checks = run_checks(project)
    for c in checks:
        print(c.line())
    failed = sum(c.status == "FAIL" for c in checks)
    warned = sum(c.status == "WARN" for c in checks)
    print(f"\n{len(checks)} checks: {failed} failed, {warned} warning(s).")
    print("Note: doctor cannot verify that Antigravity discovers or runs the hook; that needs a live session.")
    return 1 if failed else 0
