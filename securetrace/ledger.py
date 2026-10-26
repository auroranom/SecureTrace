from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from .db import connect
from .freshness import build_verification_plan


VALID_CATEGORIES = {
    "authentication",
    "authorization",
    "data-handling",
    "secrets",
    "dependencies",
    "configuration",
    "other",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


# Identical audit events inside this window are treated as one change reported
# by more than one component (e.g. watcher + hook, or editor double-saves).
DUPLICATE_EVENT_WINDOW_SECONDS = 3.0


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_path(path: str) -> str:
    return Path(path).as_posix().removeprefix("./")


def add_requirement(
    root: Path,
    title: str,
    description: str,
    category: str = "other",
    severity: str = "medium",
    file_paths: list[str] | None = None,
) -> dict:
    if not title.strip():
        raise ValueError("title cannot be empty")
    if category not in VALID_CATEGORIES:
        raise ValueError(f"category must be one of: {', '.join(sorted(VALID_CATEGORIES))}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}")

    requirement_id = f"SEC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = now_iso()
    paths = sorted({normalize_path(p) for p in (file_paths or []) if p.strip()})

    with connect(root) as db:
        db.execute(
            """INSERT INTO requirements
               (id, title, description, category, severity, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'IDENTIFIED', ?, ?)""",
            (requirement_id, title.strip(), description.strip(), category, severity, timestamp, timestamp),
        )
        db.executemany(
            "INSERT INTO requirement_files(requirement_id, file_path) VALUES (?, ?)",
            [(requirement_id, p) for p in paths],
        )
        db.execute(
            "INSERT INTO events(requirement_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
            (requirement_id, "REQUIREMENT_CREATED", f"Linked files: {', '.join(paths) or '(none)'}", timestamp),
        )

    return {
        "id": requirement_id,
        "title": title.strip(),
        "description": description.strip(),
        "category": category,
        "severity": severity,
        "status": "IDENTIFIED",
        "file_paths": paths,
    }


def list_requirements(root: Path) -> list[dict]:
    with connect(root) as db:
        rows = db.execute(
            """SELECT r.*,
                      GROUP_CONCAT(rf.file_path, '|||') AS linked_files
               FROM requirements r
               LEFT JOIN requirement_files rf ON rf.requirement_id = r.id
               GROUP BY r.id
               ORDER BY r.created_at DESC"""
        ).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        linked = item.pop("linked_files", None)
        item["file_paths"] = linked.split("|||") if linked else []
        results.append(item)
    return results


def decode_check_record(check: dict) -> dict:
    """Present the legacy details field while exposing check provenance."""
    item = dict(check)
    try:
        metadata = json.loads(item.get("details", ""))
    except (TypeError, json.JSONDecodeError):
        item["provenance"] = "manual"
        return item
    if isinstance(metadata, dict) and metadata.get("securetrace_provenance") == 1:
        item["details"] = str(metadata.get("details", ""))
        item["provenance"] = "manual"
    elif isinstance(metadata, dict) and metadata.get("securetrace_test") == 1 and metadata.get("origin") == "automated":
        item["provenance"] = "automated"
    else:
        item["provenance"] = "manual"
    return item


def record_check(
    root: Path,
    requirement_id: str,
    check_name: str,
    passed: bool,
    details: str = "",
    commit_hash: str | None = None,
    verification_complete: bool = False,
) -> dict:
    provenance = {"securetrace_provenance": 1, "origin": "manual", "details": details}
    return _record_check(
        root, requirement_id, check_name, "PASSED" if passed else "FAILED",
        details, commit_hash, verification_complete, provenance,
    )


def record_test_check(
    root: Path,
    requirement_id: str,
    test_id: str,
    outcome: str,
    execution: dict,
    *,
    verification_complete: bool = False,
) -> dict:
    """Record an actually executed test with structured provenance.

    Execution errors and timeouts are recorded as outcomes without changing the
    requirement to REGRESSION; only an assertion failure does that.
    """
    if outcome not in {"PASSED", "FAILED", "TIMEOUT", "ERROR"}:
        raise ValueError("outcome must be PASSED, FAILED, TIMEOUT, or ERROR")
    if verification_complete and outcome != "PASSED":
        raise ValueError("only a passing test can complete verification")
    provenance = {
        "securetrace_test": 1, "origin": "automated", "outcome": outcome, **execution,
    }
    return _record_check(
        root, requirement_id, test_id, outcome, "", None,
        verification_complete, provenance,
    )


def _record_check(
    root: Path,
    requirement_id: str,
    check_name: str,
    result: str,
    details: str,
    commit_hash: str | None,
    verification_complete: bool,
    provenance: dict | None = None,
) -> dict:
    timestamp = now_iso()
    stored_details = (
        json.dumps(provenance, ensure_ascii=True, separators=(",", ":"))
        if provenance is not None else details
    )

    with connect(root) as db:
        requirement = db.execute(
            "SELECT id, status FROM requirements WHERE id = ?", (requirement_id,)
        ).fetchone()
        if requirement is None:
            raise ValueError(f"Unknown requirement: {requirement_id}")

        db.execute(
            """INSERT INTO checks
               (requirement_id, check_name, result, verification_complete, details, commit_hash, ran_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (requirement_id, check_name, result, int(verification_complete), stored_details, commit_hash, timestamp),
        )

        if result in {"TIMEOUT", "ERROR"}:
            new_status = requirement["status"]
        elif result == "FAILED":
            new_status = "REGRESSION"
        elif verification_complete:
            new_status = "VERIFIED"
        elif requirement["status"] in {"IDENTIFIED", "STALE", "UNVERIFIED"}:
            new_status = "IMPLEMENTED"
        else:
            new_status = requirement["status"]

        db.execute(
            "UPDATE requirements SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, timestamp, requirement_id),
        )
        db.execute(
            "INSERT INTO events(requirement_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
            (
                requirement_id,
                "CHECK_RECORDED",
                f"{check_name}: {result}; complete_verification={verification_complete}; {details}",
                timestamp,
            ),
        )

    return {
        "requirement_id": requirement_id,
        "check_name": check_name,
        "result": result,
        "verification_complete": verification_complete,
        "status": new_status,
        "details": details,
        "commit_hash": commit_hash,
        "ran_at": timestamp,
    }


def record_event(
    root: Path,
    requirement_id: str | None,
    event_type: str,
    details: str,
    *,
    dedupe_seconds: float = 0.0,
) -> bool:
    """Append one audit event; return False if an identical recent one was suppressed.

    Several components (filesystem watcher, hooks, CLI) can report the same
    change within milliseconds. When ``dedupe_seconds`` is set, an event with
    the same requirement, type and details inside that window is not repeated.
    History is never rewritten: only the new duplicate is skipped.
    """
    with connect(root) as db:
        if dedupe_seconds > 0:
            last = db.execute(
                "SELECT created_at FROM events WHERE requirement_id IS ? AND event_type = ? AND details = ? "
                "ORDER BY id DESC LIMIT 1",
                (requirement_id, event_type, details),
            ).fetchone()
            if last is not None:
                try:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(last["created_at"])).total_seconds()
                    if age < dedupe_seconds:
                        return False
                except ValueError:
                    pass
        db.execute(
            "INSERT INTO events(requirement_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
            (requirement_id, event_type, details, now_iso()),
        )
    return True


def mark_changed_files(root: Path, changed_paths: list[str]) -> list[dict]:
    normalized = sorted({normalize_path(p) for p in changed_paths if p.strip()})
    if not normalized:
        return []

    timestamp = now_iso()
    affected: dict[str, list[str]] = {}

    with connect(root) as db:
        for path in normalized:
            rows = db.execute(
                "SELECT requirement_id FROM requirement_files WHERE file_path = ?", (path,)
            ).fetchall()
            for row in rows:
                affected.setdefault(row["requirement_id"], []).append(path)
            if _mapping_schema_available(db):
                for row in db.execute(
                    "SELECT requirement_id FROM requirement_tests WHERE test_file = ?", (path,)
                ):
                    affected.setdefault(row["requirement_id"], []).append(path)

        for requirement_id, paths in affected.items():
            paths[:] = sorted(set(paths))
    # Recorded through the shared helper so the watcher, hooks and CLI do not
    # each write the same LINKED_FILE_CHANGED event for one save.
    for requirement_id, paths in affected.items():
        record_event(root, requirement_id, "LINKED_FILE_CHANGED",
                     f"Changed files: {', '.join(paths)}", dedupe_seconds=DUPLICATE_EVENT_WINDOW_SECONDS)

    results = [analyze_requirement_impact(root, req_id, sorted(paths)) for req_id, paths in sorted(affected.items())]
    with connect(root) as db:
        for result in results:
            if result["evidence_freshness"] != "CURRENT":
                db.execute(
                    """UPDATE requirements SET status = 'STALE', updated_at = ?
                       WHERE id = ? AND status IN ('VERIFIED', 'IMPLEMENTED', 'UNVERIFIED')""",
                    (now_iso(), result["requirement_id"]),
                )
    return results


def _mapping_schema_available(db) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='requirement_tests'").fetchone() is not None


def map_requirement_test(
    root: Path, requirement_id: str, test_file: str, test_id: str,
    *, verification_complete: bool = False,
) -> dict:
    """Persist an approved requirement/test mapping after runner validation."""
    from .test_runner import validate_test_target

    # Use the validated resolved path relative to root so aliases cannot create
    # duplicate mappings to the same test.
    resolved, normalized_id = validate_test_target(root, test_file, test_id)
    normalized_file = resolved.relative_to(root.resolve()).as_posix()
    with connect(root) as db:
        if not _mapping_schema_available(db):
            raise ValueError("Test mapping schema is not installed; run `securetrace migrate` explicitly")
        if not db.execute("SELECT 1 FROM requirements WHERE id=?", (requirement_id,)).fetchone():
            raise ValueError(f"Unknown requirement: {requirement_id}")
        timestamp = now_iso()
        db.execute(
            "INSERT OR IGNORE INTO requirement_tests(requirement_id,test_file,test_id,verification_complete,created_at) VALUES(?,?,?,?,?)",
            (requirement_id, normalized_file, normalized_id, int(verification_complete), timestamp),
        )
        db.execute(
            "INSERT INTO events(requirement_id,event_type,details,created_at) VALUES(?,?,?,?)",
            (requirement_id, "TEST_MAPPED", f"Approved test mapping: {normalized_file}::{normalized_id}; complete={verification_complete}", timestamp),
        )
    return {"requirement_id": requirement_id, "test_file": normalized_file, "test_id": normalized_id,
            "verification_complete": verification_complete}


def list_requirement_tests(root: Path, requirement_id: str) -> list[dict]:
    with connect(root) as db:
        if not _mapping_schema_available(db):
            return []
        rows = db.execute(
            "SELECT requirement_id,test_file,test_id,verification_complete,created_at FROM requirement_tests WHERE requirement_id=? ORDER BY test_file,test_id",
            (requirement_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def analyze_requirement_impact(
    root: Path,
    requirement_id: str,
    changed_files: list[str],
    dependency_chains: list[list[str]] | None = None,
    dependency_graph: any = None,
    prospective_changed_files: list[str] | None = None,
) -> dict:
    requirement = get_requirement_detail(root, requirement_id) or {}
    mappings = list_requirement_tests(root, requirement_id)
    plan = build_verification_plan(
        root,
        [requirement] if requirement else [],
        {requirement_id: requirement},
        {requirement_id: mappings},
        dependency_graph=dependency_graph,
        changed_files=prospective_changed_files if prospective_changed_files is not None else changed_files,
        dependency_chains_by_req={requirement_id: dependency_chains or []} if dependency_chains else None,
    )
    eligible = [entry for entry in plan if entry["selected"]]
    freshness_states = {entry["evidence_freshness"] for entry in plan}
    evidence_freshness = (
        "UNKNOWN" if not plan or "UNKNOWN" in freshness_states
        else "STALE" if "STALE" in freshness_states else "CURRENT"
    )
    evidence_stale = "STALE" in freshness_states
    uncertainty_parts = [blocker for entry in plan for blocker in entry["blockers"]]
    uncertainty_parts.extend(
        entry["reason"] for entry in plan if entry["evidence_freshness"] == "UNKNOWN"
    )
    if not mappings:
        uncertainty_parts.append("No approved test mapping is available; rerun eligibility cannot be determined.")
    uncertainty = " ".join(uncertainty_parts)
    res = {
        "requirement_id": requirement_id,
        "changed_files": sorted(changed_files),
        "mapped_tests": mappings,
        "verification_plan": plan,
        "eligible_reruns": eligible,
        "unmapped": not mappings,
        "evidence_stale": evidence_stale,
        "evidence_freshness": evidence_freshness,
        "historical_runs_preserved": len(requirement.get("checks", [])),
        "uncertainty": uncertainty,
    }
    if dependency_chains:
        res["dependency_chains"] = [" -> ".join(chain) for chain in dependency_chains]
    return res


def analyze_change_impact(root: Path, changed_paths: list[str]) -> dict:
    """Return deterministic linked impact without executing any tests."""
    normalized = sorted({normalize_path(p) for p in changed_paths if p.strip()})

    from .dependencies import build_local_dependency_graph
    dep_graph = build_local_dependency_graph(root)

    all_dependents: set[str] = set()
    paths_to_dependents: dict[str, list[list[str]]] = {}

    for changed in normalized:
        deps, chains = dep_graph.get_transitive_dependents_with_paths(changed)
        for dep in deps:
            all_dependents.add(dep)
            paths_to_dependents.setdefault(dep, []).append(chains[dep])

    inferred_dependent_files = sorted(all_dependents - set(normalized))
    all_candidate_files = sorted(set(normalized) | set(inferred_dependent_files))

    affected: dict[str, list[str]] = {}
    req_chains: dict[str, list[list[str]]] = {}

    with connect(root) as db:
        for path in all_candidate_files:
            is_direct = path in normalized
            for row in db.execute("SELECT requirement_id FROM requirement_files WHERE file_path=?", (path,)):
                req_id = row["requirement_id"]
                affected.setdefault(req_id, []).append(path)
                if not is_direct and path in paths_to_dependents:
                    for chain in paths_to_dependents[path]:
                        req_chains.setdefault(req_id, []).append(chain)
            if _mapping_schema_available(db):
                for row in db.execute("SELECT requirement_id FROM requirement_tests WHERE test_file=?", (path,)):
                    req_id = row["requirement_id"]
                    affected.setdefault(req_id, []).append(path)
                    if not is_direct and path in paths_to_dependents:
                        for chain in paths_to_dependents[path]:
                            req_chains.setdefault(req_id, []).append(chain)

    requirements = [
        analyze_requirement_impact(
            root,
            req,
            sorted(set(paths)),
            dependency_chains=req_chains.get(req),
            dependency_graph=dep_graph,
            prospective_changed_files=normalized,
        )
        for req, paths in sorted(affected.items())
    ]

    combined_uncertainties = [item for item in requirements if item["uncertainty"]]
    for dep_unc in dep_graph.uncertainties:
        combined_uncertainties.append({"requirement_id": "", "uncertainty": dep_unc})

    coverage_status = (
        "PARTIAL_LOCAL_STATIC"
        if (dep_graph.parse_errors or dep_graph.uncertainties)
        else "LOCAL_STATIC_IMPORTS"
    )

    return {
        "changed_files": normalized,
        "inferred_dependent_files": inferred_dependent_files,
        "requirements": requirements,
        "verification_plan": [entry for item in requirements for entry in item["verification_plan"]],
        "eligible_reruns": [entry for item in requirements for entry in item["eligible_reruns"]],
        "uncertainties": combined_uncertainties,
        "dependency_coverage": coverage_status,
        "coverage_limitations": (
            "Static dependency analysis resolves local Python AST imports. "
            "External packages, C extensions, dynamic imports (importlib/exec), and non-Python assets are not inferred as complete."
        ),
    }


def current_verification_plan(root: Path) -> list[dict]:
    requirements = list_requirements(root)
    details = {item["id"]: get_requirement_detail(root, item["id"]) or {} for item in requirements}
    mappings = {item["id"]: list_requirement_tests(root, item["id"]) for item in requirements}
    from .dependencies import build_local_dependency_graph
    dep_graph = build_local_dependency_graph(root)
    return build_verification_plan(
        root,
        requirements,
        details,
        mappings,
        dependency_graph=dep_graph,
        changed_files=None,
    )


def get_requirement_detail(root: Path, requirement_id: str) -> dict | None:
    requirements = list_requirements(root)
    for requirement in requirements:
        if requirement["id"] == requirement_id:
            with connect(root) as db:
                checks = db.execute(
                    "SELECT * FROM checks WHERE requirement_id = ? ORDER BY ran_at DESC, id DESC",
                    (requirement_id,),
                ).fetchall()
                events = db.execute(
                    "SELECT * FROM events WHERE requirement_id = ? ORDER BY created_at DESC, id DESC",
                    (requirement_id,),
                ).fetchall()
            requirement["checks"] = [decode_check_record(dict(row)) for row in checks]
            requirement["events"] = [dict(row) for row in events]
            return requirement
    return None
