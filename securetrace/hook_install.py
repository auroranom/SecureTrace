"""Generate and merge the Antigravity ``.agents/hooks.json`` entry for SecureTrace.

Configures PreToolUse and PostToolUse lifecycle hooks to evaluate proposed file
writes and edits across all supported Antigravity file-editing tool names.
This module writes the entry from the interpreter that is actually running, so
the hook uses the intended Python environment. On Windows, if the interpreter
path contains whitespace, a batch wrapper is written to avoid Go's os/exec
quote-escaping bug when launching cmd.exe /c.
"""
from __future__ import annotations

import json
from pathlib import Path
import shlex
import shutil
import sys
import time

HOOK_NAME = "securetrace-approval"
# Antigravity's file-editing tools. Shell commands are deliberately not matched.
FILE_TOOL_MATCHER = "edit_file|write_file|write_to_file|replace_file_content|multi_replace_file_content"
HOOK_TIMEOUT_SECONDS = 30  # Antigravity's documented default; evaluation is local and fast.
WRAPPER_BAT_NAME = "securetrace_hook.cmd"


def _is_windows_path(path_str: str) -> bool:
    """Determine if the interpreter path is a Windows executable path."""
    if path_str.startswith("/"):
        return False
    return sys.platform == "win32" or "\\" in path_str or (len(path_str) > 1 and path_str[1] == ":") or path_str.lower().endswith(".exe")


def _command(python_exe: str, action: str, use_wrapper: bool = False) -> str:
    if use_wrapper:
        return f"call .agents\\{WRAPPER_BAT_NAME} {action} 2>nul || call {WRAPPER_BAT_NAME} {action}"
    if _is_windows_path(python_exe):
        # Windows: cmd.exe quoting. Paths with spaces go through the wrapper instead (see build_hook_entry).
        exe = f'"{python_exe}"' if any(c.isspace() for c in python_exe) else python_exe
    else:
        if any(c in python_exe for c in '$`"\\\'!') or "\n" in python_exe:
            exe = shlex.quote(python_exe)   # characters a POSIX shell would interpret even inside "..."
        else:
            exe = f'"{python_exe}"' if any(c.isspace() for c in python_exe) else python_exe
    return f"{exe} -m securetrace.hooks {action}"


def build_hook_entry(python_exe: str | None = None, use_wrapper: bool = False) -> dict:
    exe = python_exe or sys.executable
    if not use_wrapper and _is_windows_path(exe) and any(c.isspace() for c in exe):
        use_wrapper = True

    def group(action: str) -> list[dict]:
        return [{
            "matcher": FILE_TOOL_MATCHER,
            "hooks": [{"type": "command", "command": _command(exe, action, use_wrapper=use_wrapper), "timeout": HOOK_TIMEOUT_SECONDS}],
        }]
    return {"PreToolUse": group("pre_tool_use"), "PostToolUse": group("post_tool_use")}


def install_hooks(project_dir: Path, python_exe: str | None = None) -> Path:
    """Merge the SecureTrace hook into ``<project_dir>/.agents/hooks.json``.

    Other named hooks are preserved, an existing file is backed up first, and
    the result is written as UTF-8 without a byte-order mark. On Windows with
    spaces in the Python path, writes a batch wrapper to ensure clean execution.
    """
    exe = python_exe or sys.executable
    agents_dir = project_dir.resolve() / ".agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    target = agents_dir / "hooks.json"

    if not exe:
        raise ValueError("Could not determine the Python interpreter (sys.executable is empty); pass --python.")
    use_wrapper = _is_windows_path(exe) and any(c.isspace() for c in exe)
    if use_wrapper:
        # A batch file is ASCII-only here. Rather than emit a wrapper that cmd.exe would misread
        # (unverified code-page behaviour), refuse non-ASCII interpreter paths with a clear remedy.
        try:
            exe.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"The Python path contains non-ASCII characters and contains spaces ({exe!r}); the Windows hook "
                "wrapper cannot represent it reliably. Create the virtual environment at an ASCII path without "
                "spaces, or pass --python with such an interpreter."
            ) from exc
        escaped = exe.replace("%", "%%")   # '%' would otherwise be expanded by cmd.exe
        wrapper_content = f'@"{escaped}" -m securetrace.hooks %*\r\n'
        wrapper_target = agents_dir / WRAPPER_BAT_NAME
        wrapper_target.write_text(wrapper_content, encoding="ascii", newline="")
        try:
            (project_dir.resolve() / WRAPPER_BAT_NAME).write_text(wrapper_content, encoding="ascii", newline="")
        except OSError:
            pass

    config: dict = {}
    if target.is_file():
        try:
            config = json.loads(target.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{target} is not valid JSON; fix or remove it first: {exc}") from exc
        if not isinstance(config, dict):
            raise ValueError(f"{target} must contain a JSON object")
        # Never overwrite an earlier backup: the first one holds the user's original file.
        backup = target.with_name("hooks.json.securetrace-backup")
        if backup.exists():
            backup = target.with_name(f"hooks.json.securetrace-backup-{int(time.time())}")
        shutil.copyfile(target, backup)
    config[HOOK_NAME] = build_hook_entry(exe, use_wrapper=use_wrapper)
    tmp = target.with_name("hooks.json.tmp")
    tmp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    tmp.replace(target)   # atomic: a crash cannot leave a half-written hooks.json
    return target


if __name__ == "__main__":
    written = install_hooks(Path.cwd())
    print(f"Installed hooks to {written}")
