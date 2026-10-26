"""Local Semgrep CE evidence provider; this subprocess is not a sandbox."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import threading
import time
import uuid

from .db import connect
from .ledger import list_requirements
from .test_runner import _runner_environment, _terminate_process_tree, sanitize_output

MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 500
MAX_FINDING_MESSAGE = 1000
MAX_TIMEOUT_SECONDS = 600
MAX_RULESET_BYTES = 1024 * 1024


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def validate_project_and_ruleset(root: Path, config_path: str) -> tuple[Path, Path, str]:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir() or not (root / "pyproject.toml").is_file():
        raise ValueError("Scan root must be a local project directory containing pyproject.toml")
    if not isinstance(config_path, str) or not config_path.strip():
        raise ValueError("A project-relative Semgrep YAML ruleset is required")
    raw = config_path.strip().replace("\\", "/")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or "\x00" in raw or (len(raw) > 1 and raw[1] == ":"):
        raise ValueError("Semgrep ruleset path must remain inside the project root")
    ruleset = root.joinpath(*path.parts).resolve(strict=True)
    try:
        ruleset.relative_to(root)
    except ValueError as exc:
        raise ValueError("Semgrep ruleset resolves outside the project root") from exc
    if not ruleset.is_file() or ruleset.suffix.lower() not in {".yml", ".yaml"}:
        raise ValueError("Semgrep ruleset must be a YAML file inside the project root")
    content = ruleset.read_bytes()
    if len(content) > MAX_RULESET_BYTES:
        raise ValueError("Semgrep ruleset exceeds the 1 MiB limit")
    if re.search(rb"(?im)^\s*extends\s*:", content):
        raise ValueError("Remote or inherited Semgrep rulesets are not supported; use one local rules file")
    digest = hashlib.sha256(content).hexdigest()
    return root, ruleset, digest


def _check_symlinks(root: Path) -> list[str]:
    """Block out-of-root symlinks so a recursive scan cannot escape its target."""
    escaped: list[str] = []
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        names[:] = [name for name in names if name not in {".securetrace", ".git"}]
        for name in [*names, *files]:
            candidate = current / name
            if candidate.is_symlink():
                try:
                    candidate.resolve(strict=True).relative_to(root)
                except (OSError, ValueError):
                    escaped.append(candidate.relative_to(root).as_posix())
    return sorted(escaped)


def _bounded_process(argv: list[str], cwd: Path, timeout_seconds: float) -> dict:
    """Run fixed argv without a shell and retain only bounded combined output."""
    captured: list[bytes] = []
    truncated = [False]
    options: dict = {}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        options["start_new_session"] = True
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=_runner_environment(), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, shell=False, **options,
        )
    except OSError as exc:
        return {"exit_code": None, "output": "", "truncated": False,
                "timed_out": False, "error": type(exc).__name__}
    assert process.stdout is not None

    def drain() -> None:
        used = 0
        while True:
            chunk = process.stdout.read(8192)
            if not chunk:
                return
            if used < MAX_OUTPUT_BYTES:
                kept = chunk[:MAX_OUTPUT_BYTES - used]
                captured.append(kept)
                used += len(kept)
                if len(kept) < len(chunk):
                    truncated[0] = True
            else:
                truncated[0] = True

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code, _ = _terminate_process_tree(process)
        reader.join(timeout=2)
        if reader.is_alive():
            if process.poll() is None:
                exit_code, _ = _terminate_process_tree(process)
            truncated[0] = True
            reader.join(timeout=1)
    except OSError as exc:
        exit_code = process.poll()
        return {"exit_code": exit_code, "output": "", "truncated": False,
                "timed_out": False, "error": type(exc).__name__}
    finally:
        process.stdout.close()
    raw = b"".join(captured).decode("utf-8", errors="replace")
    return {"exit_code": exit_code, "output": sanitize_output(raw), "truncated": truncated[0],
            "timed_out": timed_out, "error": None}


def _relative_finding_path(root: Path, raw: object) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=False)
        return resolved.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None


def _clean_findings(root: Path, payload: dict, requirements: list[dict]) -> tuple[list[dict], bool]:
    links: dict[str, list[str]] = {}
    for requirement in requirements:
        for linked_path in requirement.get("file_paths", []):
            normalized = str(linked_path).replace("\\", "/").removeprefix("./")
            links.setdefault(normalized, []).append(requirement["id"])
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        raise ValueError("Semgrep JSON has no results list")
    findings: list[dict] = []
    invalid_path = False
    for item in raw_results[:MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        rel_path = _relative_finding_path(root, item.get("path"))
        if rel_path is None:
            invalid_path = True
            rel_path = "[outside-or-invalid-path]"
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        end = item.get("end") if isinstance(item.get("end"), dict) else {}
        message = " ".join(sanitize_output(str(extra.get("message", ""))).split())[:MAX_FINDING_MESSAGE]
        findings.append({
            "check_id": " ".join(sanitize_output(str(item.get("check_id", "unknown"))).split())[:300],
            "path": rel_path,
            "start_line": start.get("line") if isinstance(start.get("line"), int) else None,
            "end_line": end.get("line") if isinstance(end.get("line"), int) else None,
            "severity": " ".join(sanitize_output(str(extra.get("severity", "UNKNOWN"))).split())[:30],
            "message": message,
            "requirement_ids": sorted(links.get(rel_path, [])),
        })
    if len(raw_results) > MAX_FINDINGS:
        invalid_path = True  # force INCOMPLETE; stored list is deliberately bounded
    return findings, invalid_path


def _persist(root: Path, metadata: dict) -> None:
    with connect(root) as db:
        db.execute(
            "INSERT INTO events(requirement_id,event_type,details,created_at) VALUES(NULL,'SEMGREP_SCAN',?,?)",
            (json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True), metadata["ended_at"]),
        )


def run_semgrep_scan(
    root: Path,
    config_path: str,
    *,
    timeout_seconds: float = 120,
    approve: bool = False,
) -> dict:
    """Plan unless explicitly approved; scan only this local project root."""
    root, ruleset, ruleset_sha256 = validate_project_and_ruleset(root, config_path)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS} seconds")
    base = {
        "provider": "semgrep", "scan_id": uuid.uuid4().hex,
        "target": ".", "ruleset": ruleset.relative_to(root).as_posix(),
        "ruleset_sha256": ruleset_sha256, "timeout_seconds": timeout_seconds,
    }
    if not approve:
        return {**base, "status": "PLANNED", "findings": [], "executed": False}

    executable = shutil.which("semgrep")
    if not executable:
        metadata = {**base, "status": "ERROR", "error": "Semgrep executable is not installed or not on PATH.",
                    "scanner_version": None, "started_at": _timestamp(), "ended_at": _timestamp(),
                    "duration_seconds": 0, "exit_code": None, "findings": [], "unmapped_count": 0}
        _persist(root, metadata)
        return {**metadata, "executed": False}

    started_at = _timestamp()
    start_clock = time.monotonic()
    deadline = start_clock + float(timeout_seconds)
    version_result = _bounded_process([executable, "--version"], root, min(float(timeout_seconds), 15))
    version = " ".join(version_result["output"].split())[:200]
    if version_result["timed_out"] or version_result["exit_code"] != 0 or version_result["truncated"]:
        scan_result = {"exit_code": version_result["exit_code"], "timed_out": version_result["timed_out"],
                       "truncated": version_result["truncated"], "error": "Semgrep version command failed.",
                       "output": version}
    else:
        escaped = _check_symlinks(root)
        if escaped:
            scan_result = {"exit_code": None, "timed_out": False, "truncated": False,
                           "error": "Out-of-root symlinks prevent a safe local scan: " + ", ".join(escaped[:20]),
                           "output": ""}
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                scan_result = {"exit_code": None, "timed_out": True, "truncated": False,
                               "error": None, "output": ""}
            else:
                argv = [executable, "scan", "--json", "--metrics=off", "--config", str(ruleset),
                        "--exclude", ".securetrace", "--exclude", ".git", str(root)]
                scan_result = _bounded_process(argv, root, remaining)

    ended_at = _timestamp()
    payload: dict = {}
    findings: list[dict] = []
    status = "ERROR"
    error = scan_result.get("error")
    if scan_result.get("timed_out"):
        status = "TIMEOUT"
    elif error:
        status = "ERROR"
    elif scan_result.get("truncated"):
        status = "INCOMPLETE"
        error = "Semgrep output exceeded the capture limit."
    else:
        try:
            payload = json.loads(scan_result["output"])
            findings, invalid_path = _clean_findings(root, payload, list_requirements(root))
            errors = payload.get("errors", [])
            paths = payload.get("paths", {})
            skipped = paths.get("skipped", []) if isinstance(paths, dict) else []
            scanned = paths.get("scanned", []) if isinstance(paths, dict) else []
            if errors and not scanned:
                status = "ERROR"
                error = "Semgrep could not scan any targets."
            elif invalid_path or errors or skipped or not scanned:
                status = "INCOMPLETE"
                error = "Semgrep reported truncated, skipped, invalid, or unscanned targets."
            elif scan_result["exit_code"] not in {0, 1}:
                status = "ERROR"
                error = "Semgrep exited with an error status."
            elif scan_result["exit_code"] == 1 and not findings:
                status = "ERROR"
                error = "Semgrep returned a findings exit status without structured findings."
            else:
                status = "FINDINGS" if findings else "CLEAN"
        except (json.JSONDecodeError, ValueError, TypeError):
            status = "ERROR"
            error = "Semgrep did not return valid structured JSON."

    metadata = {
        **base, "status": status, "scanner_version": version or None,
        "started_at": started_at, "ended_at": ended_at,
        "duration_seconds": round(time.monotonic() - start_clock, 3),
        "exit_code": scan_result.get("exit_code"),
        "findings": findings, "finding_count": len(findings),
        "unmapped_count": sum(not item["requirement_ids"] for item in findings),
        "error": " ".join(sanitize_output(error).split())[:1000] if error else None,
        "executed": True,
    }
    _persist(root, metadata)
    return metadata
