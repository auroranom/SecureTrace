"""Explicit, sequential orchestration over SecureTrace's verification plan."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from .db import connect
from .freshness import assess_mapping_freshness
from .ledger import (
    analyze_change_impact, current_verification_plan, get_requirement_detail,
    list_requirement_tests,
)
from .test_runner import EvidencePersistenceError, run_approved_test


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _plan(root: Path, changed_files: list[str] | None) -> list[dict]:
    if changed_files:
        return analyze_change_impact(root, changed_files)["verification_plan"]
    return current_verification_plan(root)


def _event_rows(
    root: Path,
    orchestration_id: str,
    mode: str,
    plan_inputs: dict,
    planned: list[dict],
    results: list[dict],
) -> list[tuple[str | None, str, str]]:
    by_requirement: dict[str, dict] = {}
    requirement_ids = sorted({item["requirement_id"] for item in planned + results})
    for requirement_id in requirement_ids:
        by_requirement[requirement_id] = {
            "orchestration_id": orchestration_id,
            "mode": mode,
            "plan_inputs": plan_inputs,
            "selected_checks": [item for item in planned if item["requirement_id"] == requirement_id],
            "results": [item for item in results if item["requirement_id"] == requirement_id],
            "unresolved_blockers": [
                {"test_file": item.get("test_file"), "test_id": item.get("test_id"),
                 "blockers": item.get("blockers", [])}
                for item in results if item["requirement_id"] == requirement_id and item.get("blockers")
            ],
        }
    if not by_requirement:
        by_requirement[""] = {
            "orchestration_id": orchestration_id, "mode": mode, "plan_inputs": plan_inputs,
            "selected_checks": planned, "results": results, "unresolved_blockers": [],
        }
    event_type = "ORCHESTRATION_PLAN" if mode == "PLAN_ONLY" else "ORCHESTRATION_RUN"
    return [
        (requirement_id or None, event_type,
         json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        for requirement_id, details in by_requirement.items()
    ]


def _persist_provenance(root: Path, rows: list[tuple[str | None, str, str]]) -> list[str]:
    try:
        with connect(root) as db:
            db.executemany(
                "INSERT INTO events(requirement_id,event_type,details,created_at) VALUES(?,?,?,?)",
                [(requirement_id, event_type, details, _now())
                 for requirement_id, event_type, details in rows],
            )
    except (OSError, sqlite3.Error) as exc:
        return [f"Orchestration provenance could not be persisted: {type(exc).__name__}."]
    return []


def _preserve_regressions(root: Path, results: list[dict]) -> list[str]:
    """Keep a failed selected test visible after later passing checks in the same run."""
    failed_requirements = sorted({item["requirement_id"] for item in results
                                  if item.get("status") == "FAILED"})
    if not failed_requirements:
        return []
    try:
        with connect(root) as db:
            db.executemany(
                "UPDATE requirements SET status='REGRESSION', updated_at=? WHERE id=?",
                [(_now(), requirement_id) for requirement_id in failed_requirements],
            )
    except (OSError, sqlite3.Error) as exc:
        return [f"Regression status could not be persisted: {type(exc).__name__}."]
    return []


def orchestrate_verification(
    root: Path,
    *,
    approve: bool = False,
    changed_files: list[str] | None = None,
    requirement_ids: list[str] | None = None,
    rerun_current: bool = False,
    allow_duplicates: bool = False,
    timeout_seconds: float = 60,
) -> dict:
    """Plan by default; execute mapped checks only after explicit approval.

    A no-evidence baseline may execute when the current fingerprint is complete.
    Unknown freshness for historical evidence, or any invalid/unreadable source,
    blocks execution pending a fresh plan or repair.
    """
    root = root.expanduser().resolve(strict=True)
    changed = sorted({str(path).replace("\\", "/").removeprefix("./")
                      for path in (changed_files or []) if str(path).strip()})
    plan = _plan(root, changed)
    if requirement_ids:
        selected_requirements = set(requirement_ids)
        plan = [entry for entry in plan if entry["requirement_id"] in selected_requirements]

    selected: list[dict] = []
    for entry in plan:
        if entry["selected"] or rerun_current:
            choice = dict(entry)
            if rerun_current and not entry["selected"]:
                choice["reason"] = "Explicitly requested rerun of current evidence."
                choice["selected"] = True
            selected.append(choice)

    # A mapped check is the (requirement, test file, test id) tuple. Duplicate
    # event inputs cannot cause duplicate executions in one orchestration run.
    unique_selected: list[dict] = []
    duplicate_results: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in selected:
        key = (entry["requirement_id"], entry["test_file"], entry["test_id"])
        if key in seen and not allow_duplicates:
            duplicate_results.append({**entry, "status": "SKIPPED_DUPLICATE", "outcome": None,
                                      "blockers": ["Duplicate mapped check suppressed for this orchestration run."]})
        else:
            unique_selected.append(entry)
            seen.add(key)

    orchestration_id = uuid.uuid4().hex
    plan_inputs = {
        "changed_files": changed,
        "requirement_ids": sorted(set(requirement_ids or [])),
        "rerun_current": rerun_current,
        "allow_duplicates": allow_duplicates,
        "approval_provided": approve,
        "timeout_seconds": timeout_seconds,
    }
    results: list[dict] = list(duplicate_results)

    if not approve:
        results.extend({**item, "status": "PLANNED", "outcome": None} for item in unique_selected)
        mode = "PLAN_ONLY"
    else:
        mode = "APPROVED_RUN"
        for entry in unique_selected:
            result = dict(entry)
            result["outcome"] = None
            result["status"] = "BLOCKED"
            result["blockers"] = []

            detail = get_requirement_detail(root, entry["requirement_id"])
            mapping = next((item for item in list_requirement_tests(root, entry["requirement_id"])
                            if item["test_file"] == entry["test_file"] and item["test_id"] == entry["test_id"]), None)
            if detail is None:
                result["blockers"].append("Requirement no longer exists.")
            elif mapping is None:
                result["blockers"].append("Approved mapping no longer exists.")
            else:
                current = assess_mapping_freshness(root, detail, mapping, detail.get("checks", []))
                if current.get("execution_blockers"):
                    result["blockers"].extend(current["execution_blockers"])
                if current.get("mapping_verification_complete") != entry.get("mapping_verification_complete"):
                    result["blockers"].append("Mapping policy changed after planning; regenerate the plan.")
                if current.get("current_fingerprint") != entry.get("current_fingerprint"):
                    result["status"] = "STALE"
                    result["blockers"].append("Source fingerprint changed after planning; regenerate the plan.")
                if current["evidence_freshness"] == "UNKNOWN":
                    baseline_allowed = not current.get("has_prior_execution") and not current.get("execution_blockers")
                    if not baseline_allowed:
                        result["blockers"].append("Freshness is UNKNOWN; execution is blocked until the source state is reliable.")
                if result["blockers"]:
                    if result["status"] != "STALE":
                        result["status"] = "BLOCKED"
                else:
                    try:
                        execution = run_approved_test(
                            root, entry["requirement_id"], entry["test_file"], entry["test_id"],
                            timeout_seconds=timeout_seconds,
                            verification_complete=bool(mapping["verification_complete"]),
                        )
                        result["outcome"] = execution["outcome"]
                        result["execution"] = execution.get("execution", {})
                        if execution["outcome"] == "TIMEOUT":
                            result["status"] = "TIMEOUT"
                        elif execution["outcome"] == "FAILED":
                            result["status"] = "FAILED"
                        elif execution["outcome"] == "ERROR":
                            result["status"] = "ERROR"
                        elif execution["outcome"] != "PASSED":
                            result["status"] = "UNKNOWN"
                            result["blockers"].append("Runner returned an unrecognized execution outcome.")
                        elif not execution.get("execution", {}).get("source_state_stable"):
                            result["status"] = "UNKNOWN"
                            result["blockers"].append("Execution passed, but a complete stable source fingerprint was unavailable.")
                        else:
                            result["status"] = "PASSED"
                    except EvidencePersistenceError as exc:
                        result["status"] = "ERROR"
                        result["outcome"] = "ERROR"
                        result["blockers"].append(f"Execution evidence persistence failed: {type(exc).__name__}.")
                    except (OSError, ValueError, sqlite3.Error) as exc:
                        result["status"] = "BLOCKED" if isinstance(exc, ValueError) else "ERROR"
                        result["outcome"] = "ERROR" if result["status"] == "ERROR" else None
                        result["blockers"].append(f"Execution could not proceed: {type(exc).__name__}.")
                    except Exception as exc:
                        result["status"] = "ERROR"
                        result["outcome"] = "ERROR"
                        result["blockers"].append(f"Unexpected orchestration error: {type(exc).__name__}.")
            results.append(result)

    rows = _event_rows(root, orchestration_id, mode, plan_inputs, unique_selected, results)
    persistence_errors = _preserve_regressions(root, results)
    persistence_errors.extend(_persist_provenance(root, rows))
    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "orchestration_id": orchestration_id,
        "mode": mode,
        "plan": plan,
        "selected_checks": unique_selected,
        "results": results,
        "counts": counts,
        "persistence_errors": persistence_errors,
        "plan_inputs": plan_inputs,
    }
