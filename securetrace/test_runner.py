"""Run one explicitly approved pytest function inside the local project.

This runner is not a sandbox. Approved test code runs as the current user and
can use that user's filesystem, network, and process permissions.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import BinaryIO
import xml.etree.ElementTree as ET

from .ledger import get_requirement_detail, list_requirement_tests, record_test_check
from .freshness import fingerprint_source_state
from .adapters import get_adapter

DEFAULT_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 600
MAX_OUTPUT_BYTES = 16_384
_TEST_ID = re.compile(r"test_[A-Za-z0-9_]+\Z")
_REQUIREMENT_ID = re.compile(r"SEC-[A-F0-9]{8}\Z")
_SECRET_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|secret|password|token)\s*[:=]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
)


class EvidencePersistenceError(RuntimeError):
    """Execution ran, but its evidence could not be committed to the ledger."""


def _runner_environment() -> dict[str, str]:
    """Keep only OS/runtime variables needed to start a local Python process."""
    if os.name == "nt":
        allowed = {
            "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE",
            "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
        }
    else:
        allowed = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    # Explicitly force this even if the parent supplied a hostile value.
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return env


def _test_fingerprint(path: Path) -> tuple[int, int, int, str]:
    """Capture path identity and content to detect replacement during a run."""
    stat = path.stat()
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    return stat.st_dev, stat.st_ino, stat.st_size, digest


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> tuple[int | None, bool]:
    """Terminate pytest and descendants with bounded, platform-specific cleanup."""
    cleanup_requested = False
    if os.name == "nt":
        cleanup_requested = _terminate_windows_descendants(process.pid)
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            cleanup_requested = True
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
        # The leader may exit on SIGTERM while a descendant ignores it and
        # keeps the pipe open, so escalate for the whole process group anyway.
        try:
            os.killpg(process.pid, signal.SIGKILL)
            cleanup_requested = True
        except (ProcessLookupError, PermissionError, OSError):
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass

    try:
        exit_code = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            exit_code = process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            return None, False
    if os.name != "nt" and cleanup_requested:
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return exit_code, True
            except (PermissionError, OSError):
                return exit_code, False
            time.sleep(0.025)
        return exit_code, False
    return exit_code, cleanup_requested


def _terminate_windows_descendants(root_pid: int) -> bool:
    """Use Toolhelp + TerminateProcess; taskkill can be blocked by host policy."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_TERMINATE = 0x0001
    SYNCHRONIZE = 0x00100000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    cleanup_deadline = time.monotonic() + 1.5
    # Re-snapshot a few times to catch children created during enumeration.
    for _ in range(3):
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            return False
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            parent_by_pid: dict[int, int] = {}
            if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    parent_by_pid[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
            descendants: set[int] = set()
            changed = True
            while changed:
                changed = False
                for pid, parent_pid in parent_by_pid.items():
                    if pid != root_pid and (parent_pid == root_pid or parent_pid in descendants) and pid not in descendants:
                        descendants.add(pid)
                        changed = True
        finally:
            kernel32.CloseHandle(snapshot)

        if not descendants:
            break
        for pid in list(descendants)[:512]:
            if time.monotonic() >= cleanup_deadline:
                break
            handle = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
            if not handle:
                continue
            try:
                if kernel32.TerminateProcess(handle, 1):
                    remaining_ms = max(0, min(50, int((cleanup_deadline - time.monotonic()) * 1000)))
                    kernel32.WaitForSingleObject(handle, remaining_ms)
            finally:
                kernel32.CloseHandle(handle)
    # A failed TerminateProcess can race with a child exiting naturally. Verify
    # the tree is actually gone instead of treating attempted termination as
    # successful cleanup.
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return False
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        parent_by_pid: dict[int, int] = {}
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                parent_by_pid[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
        remaining: set[int] = set()
        changed = True
        while changed:
            changed = False
            for pid, parent_pid in parent_by_pid.items():
                if pid != root_pid and (parent_pid == root_pid or parent_pid in remaining) and pid not in remaining:
                    remaining.add(pid)
                    changed = True
        return not remaining
    finally:
        kernel32.CloseHandle(snapshot)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sanitize_output(value: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def validate_test_target(root: Path, test_file: str, test_id: str) -> tuple[Path, str]:
    """Resolve a test file and test function strictly beneath approved dirs."""
    return get_adapter(root).validate_target(root, test_file, test_id)


def _drain(pipe: BinaryIO, capture: list[bytes], limit: int, truncated: list[bool]) -> None:
    used = 0
    while True:
        chunk = pipe.read(4096)
        if not chunk:
            return
        if used < limit:
            kept = chunk[: limit - used]
            capture.append(kept)
            used += len(kept)
            if len(kept) < len(chunk):
                truncated[0] = True
        else:
            truncated[0] = True


def _save_evidence(root: Path, test_id: str, text: str) -> str:
    evidence_dir = root / ".securetrace" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    resolved_dir = evidence_dir.resolve(strict=True)
    try:
        resolved_dir.relative_to(root)
    except ValueError as exc:
        raise OSError("Evidence directory resolves outside the project root") from exc
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", test_id)[:80]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]
    destination = resolved_dir / f"{stamp}-{safe_id}-{digest}.txt"
    fd, temporary_name = tempfile.mkstemp(prefix=".evidence-", suffix=".tmp", dir=resolved_dir)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
    finally:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
    return destination.relative_to(root).as_posix()


def run_approved_test(
    root: Path,
    requirement_id: str,
    test_file: str,
    test_id: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    verification_complete: bool = False,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> dict:
    """Run exactly one pytest function and record its genuine outcome."""
    root = root.expanduser().resolve(strict=True)
    resolved_file, test_id = validate_test_target(root, test_file, test_id)
    if not isinstance(requirement_id, str) or not _REQUIREMENT_ID.fullmatch(requirement_id):
        raise ValueError("Requirement ID must match SEC- followed by eight uppercase hexadecimal characters")
    try:
        timeout_value = float(timeout_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Timeout must be a finite number of seconds") from exc
    if isinstance(timeout_seconds, bool) or not math.isfinite(timeout_value) or not 0 < timeout_value <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS} seconds")
    if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        raise ValueError(f"Output limit must be between 1 and {MAX_OUTPUT_BYTES} bytes")
    requirement_detail = get_requirement_detail(root, requirement_id)
    if requirement_detail is None:
        raise ValueError(f"Unknown requirement: {requirement_id}")

    # Older ledgers remain runnable until the explicit mapping migration is
    # applied. Once installed, execution is limited to persisted mappings.
    from .db import connect
    with connect(root) as db:
        mapping_schema = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='requirement_tests'").fetchone()
    if mapping_schema:
        mappings = list_requirement_tests(root, requirement_id)
        validated_mappings = []
        for item in mappings:
            mapped_path, mapped_id = validate_test_target(root, item["test_file"], item["test_id"])
            validated_mappings.append((mapped_path.relative_to(root).as_posix(), mapped_id))
        if (resolved_file.relative_to(root).as_posix(), test_id) not in validated_mappings:
            raise ValueError("This test is not mapped to the requirement; add an approved mapping first")

    # Resolve/stat checks prevent ordinary path escapes. Fingerprinting before
    # and after execution detects persistent replacement or edits; a concurrent
    # swap-and-restore during pytest remains possible (see README limitation).
    resolved_again, _ = validate_test_target(root, test_file, test_id)
    if resolved_again != resolved_file:
        raise ValueError("Test path changed during validation")
    fingerprint_before = _test_fingerprint(resolved_again)
    relevant_paths = sorted(set(requirement_detail.get("file_paths", [])) | {
        resolved_again.relative_to(root).as_posix(),
    })
    source_fingerprint_before = fingerprint_source_state(root, relevant_paths)

    test_node = f"{resolved_file}::{test_id}"
    # No shell, no user-supplied command/arguments, no third-party pytest
    # plugin autoload, and no conftest discovery above the approved test dir.
    started_at = _timestamp()
    monotonic_start = time.monotonic()
    capture: list[bytes] = []
    output_truncated = [False]
    outcome = "ERROR"
    exit_code: int | None = None
    runner_error_type: str | None = None
    process: subprocess.Popen[bytes] | None = None
    reader: threading.Thread | None = None
    junit_path: Path | None = None
    config_path: Path | None = None
    process_tree_cleanup_succeeded: bool | None = None
    process_started = False
    try:
        evidence_dir = root / ".securetrace" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        adapter = get_adapter(root)
        junit_path, config_path = adapter.prepare_execution_artifacts(evidence_dir)
        argv = adapter.build_command(root, resolved_file, test_id, junit_path, config_path)
        popen_options: dict = {}
        if os.name == "nt":
            popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_options["start_new_session"] = True
        process = subprocess.Popen(
            argv, cwd=root, env=_runner_environment(), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, shell=False, **popen_options,
        )
        process_started = True
        assert process.stdout is not None
        reader = threading.Thread(
            target=_drain,
            args=(process.stdout, capture, max_output_bytes, output_truncated),
            daemon=True,
        )
        reader.start()
        try:
            exit_code = process.wait(timeout=timeout_value)
            outcome = adapter.parse_exit_outcome(exit_code, junit_path)
        except subprocess.TimeoutExpired:
            exit_code, process_tree_cleanup_succeeded = _terminate_process_tree(process)
            outcome = "TIMEOUT"
        reader.join(timeout=2)
        if reader.is_alive():
            # A test can leave descendants holding the output pipe open after
            # pytest exits. Treat that as a harness error and clean the group.
            if process.poll() is None or os.name != "nt":
                exit_code, process_tree_cleanup_succeeded = _terminate_process_tree(process)
            else:
                process_tree_cleanup_succeeded = False
            outcome = "ERROR"
            runner_error_type = "OutputDrainDidNotFinish"
            reader.join(timeout=1)
        process.stdout.close()
    except BaseException as exc:
        runner_error_type = type(exc).__name__
        if process is not None and process.poll() is None:
            exit_code, process_tree_cleanup_succeeded = _terminate_process_tree(process)
        if reader is not None:
            reader.join(timeout=1)
        if process is not None and process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        outcome = "ERROR"
    finally:
        for temporary_path in (junit_path, config_path):
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass

    ended_at = _timestamp()
    duration = round(time.monotonic() - monotonic_start, 3)
    try:
        fingerprint_after = _test_fingerprint(resolved_file)
        test_file_changed = fingerprint_after != fingerprint_before
    except OSError:
        fingerprint_after = None
        test_file_changed = True
    if test_file_changed:
        outcome = "ERROR"
        runner_error_type = "TestFileChangedDuringExecution"
    source_fingerprint_after = fingerprint_source_state(root, relevant_paths)
    source_state_stable = (
        source_fingerprint_before.get("complete") is True
        and source_fingerprint_after.get("complete") is True
        and source_fingerprint_before.get("digest") == source_fingerprint_after.get("digest")
    )
    source_state_changed = source_fingerprint_before.get("digest") != source_fingerprint_after.get("digest")
    if source_state_changed and outcome == "PASSED":
        outcome = "ERROR"
        runner_error_type = "RelevantSourceChangedDuringExecution"
    raw_output = b"".join(capture).decode("utf-8", errors="replace")
    clipped = output_truncated[0]
    safe_output = sanitize_output(raw_output)
    if runner_error_type:
        safe_output += f"\n[SecureTrace: execution error: {runner_error_type}]\n"
    if clipped:
        safe_output += "\n[SecureTrace: output truncated at configured byte limit]\n"
    evidence_ref: str | None = None
    evidence_persisted = False
    evidence_write_failed = False
    try:
        evidence_ref = _save_evidence(root, test_id, safe_output)
        evidence_persisted = True
    except OSError:
        outcome = "ERROR"
        runner_error_type = "EvidenceFileWriteFailed"
        evidence_write_failed = True
    execution = {
        "test_identifier": test_id,
        "test_file": resolved_file.relative_to(root).as_posix(),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": duration,
        "exit_code": exit_code,
        "evidence_ref": evidence_ref,
        "evidence_persisted": evidence_persisted,
        "evidence_write_failed": evidence_write_failed,
        "output_bytes_captured": min(len(b"".join(capture)), max_output_bytes),
        "output_truncated": clipped,
        "process_started": process_started,
        "process_tree_cleanup_succeeded": process_tree_cleanup_succeeded,
        "test_file_sha256_before": fingerprint_before[3],
        "test_file_sha256_after": fingerprint_after[3] if fingerprint_after else None,
        "test_file_changed": test_file_changed,
        "runner_error_type": runner_error_type,
        "source_fingerprint_before": source_fingerprint_before,
        "source_fingerprint_after": source_fingerprint_after,
        "source_state_stable": source_state_stable,
        "source_state_changed": source_state_changed,
    }
    try:
        recorded = record_test_check(
            root, requirement_id, test_id, outcome, execution,
            verification_complete=(verification_complete and outcome == "PASSED" and source_state_stable),
        )
    except Exception as exc:
        orphan = f" Orphan evidence: {root / evidence_ref}." if evidence_ref else " No evidence file was persisted."
        raise EvidencePersistenceError(
            f"Execution outcome {outcome}; ledger recording failed ({type(exc).__name__}).{orphan}"
        ) from exc
    persistence_error = "Evidence file could not be written; outcome recorded as ERROR." if evidence_write_failed else None
    return {
        **recorded,
        "outcome": outcome,
        "execution": execution,
        "output": safe_output if evidence_persisted else "",
        "persistence_error": persistence_error,
    }
