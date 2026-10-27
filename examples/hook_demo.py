"""Feed two sample PreToolUse payloads to the SecureTrace hook against examples/authorization_demo.

Prerequisites (see README "Demonstration"): the package is importable (`pip install -e .`),
and a requirement linked to app.py is registered in examples/authorization_demo/.securetrace
(that directory is gitignored, so a fresh clone starts without one).

This only SIMULATES the host: it sends JSON to `python -m securetrace.hooks pre_tool_use`.
It never writes app.py (PreToolUse evaluation is in-memory) and does not involve Antigravity.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

DEMO = Path(__file__).resolve().parent / "authorization_demo"


def call_hook(args: dict) -> dict:
    payload = {"toolCall": {"name": "replace_file_content", "args": args}, "workspacePaths": [str(DEMO)]}
    result = subprocess.run([sys.executable, "-m", "securetrace.hooks", "pre_tool_use"],
                            input=json.dumps(payload), capture_output=True, text=True, timeout=60)
    if result.returncode != 0 or not result.stdout.strip():
        raise SystemExit(f"hook failed (exit {result.returncode}): {result.stderr.strip()}")
    return json.loads(result.stdout)


def main() -> None:
    risky = call_hook({
        "TargetFile": str(DEMO / "app.py"),
        "TargetContent": "return bool(actor_id) and actor_id == appointment_owner_id",
        "ReplacementContent": "return True",
    })
    print("1) Weakening the ownership check ->", risky["decision"])
    print("   " + risky.get("reason", "(no reason)").splitlines()[0])
    harmless = call_hook({
        "TargetFile": str(DEMO / "pyproject.toml"),
        "TargetContent": "name",
        "ReplacementContent": "name",
    })
    print("2) No-op edit to an unlinked file   ->", harmless["decision"])


if __name__ == "__main__":
    main()
