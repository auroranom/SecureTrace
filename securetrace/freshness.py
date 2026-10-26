"""Content based source fingerprints and deterministic verification plans."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def fingerprint_source_state(root: Path, paths: list[str]) -> dict:
    """Hash every named working-tree file; missing or unreadable paths stay explicit.

    Files are considered regardless of version-control tracking, so an untracked
    but linked file is fingerprinted just like a tracked file.
    """
    root = root.resolve(strict=True)
    records: dict[str, dict] = {}
    for raw in sorted(set(paths)):
        normalized = str(raw).replace("\\", "/")
        pure = PurePosixPath(normalized)
        if (not normalized or pure.is_absolute() or ".." in pure.parts
                or re.match(r"^[A-Za-z]:", normalized) or "\x00" in normalized):
            records[normalized] = {"state": "INVALID_PATH"}
            continue
        lexical = root.joinpath(*pure.parts)
        try:
            resolved = lexical.resolve(strict=True)
        except FileNotFoundError:
            records[pure.as_posix()] = {"state": "MISSING"}
            continue
        except OSError as exc:
            records[pure.as_posix()] = {"state": "UNREADABLE", "error": type(exc).__name__}
            continue
        try:
            resolved.relative_to(root)
        except ValueError:
            records[pure.as_posix()] = {"state": "INVALID_PATH"}
            continue
        if not resolved.is_file():
            records[pure.as_posix()] = {"state": "UNREADABLE", "error": "NotARegularFile"}
            continue
        try:
            before = resolved.stat()
            digest = hashlib.sha256()
            with resolved.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = resolved.stat()
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if identity_before != identity_after:
                records[pure.as_posix()] = {"state": "UNSTABLE"}
            else:
                records[pure.as_posix()] = {
                    "state": "PRESENT", "sha256": digest.hexdigest(), "size": after.st_size,
                }
        except OSError as exc:
            records[pure.as_posix()] = {"state": "UNREADABLE", "error": type(exc).__name__}

    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    complete = all(entry["state"] == "PRESENT" for entry in records.values())
    return {
        "algorithm": "sha256",
        "digest": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        "complete": complete,
        "files": records,
    }


def _metadata(check: dict) -> dict | None:
    try:
        value = json.loads(check.get("details", ""))
    except (TypeError, json.JSONDecodeError):
        return None
    if isinstance(value, dict) and value.get("securetrace_test") == 1 and value.get("origin") == "automated":
        return value
    return None


def assess_mapping_freshness(
    root: Path,
    requirement: dict,
    mapping: dict,
    checks: list[dict],
    *,
    dependency_graph: any = None,
    changed_files: list[str] | None = None,
    dependency_chains: list[list[str]] | None = None,
) -> dict:
    """Assess one mapped target against its latest immutable automated run."""
    test_file = mapping["test_file"]
    test_id = mapping["test_id"]
    req_file_paths = requirement.get("file_paths", [])
    relevant_paths = sorted(set(req_file_paths) | {test_file})
    current = fingerprint_source_state(root, relevant_paths)

    matching = []
    for check in checks:
        if check.get("check_name") == test_id:
            metadata = _metadata(check)
            if metadata and metadata.get("test_file") == test_file:
                matching.append((check, metadata))
    latest = matching[0] if matching else None

    blockers: list[str] = []
    execution_blockers: list[str] = []
    try:
        from .test_runner import validate_test_target
        validate_test_target(root, test_file, test_id)
    except (OSError, ValueError) as exc:
        blocker = f"Approved test target is invalid or unavailable: {type(exc).__name__}."
        blockers.append(blocker)
        execution_blockers.append(blocker)

    for path, item in current["files"].items():
        if item["state"] != "PRESENT":
            blocker = f"{path}: {item['state']}"
            blockers.append(blocker)
            execution_blockers.append(blocker)

    last_outcome = latest[1].get("outcome") if latest else None

    if latest is None:
        direct_freshness = "UNKNOWN"
        direct_reason = "No automated execution evidence exists for this mapped test."
    else:
        saved = latest[1].get("source_fingerprint_before")
        stable = latest[1].get("source_state_stable")
        if not isinstance(saved, dict):
            direct_freshness = "UNKNOWN"
            direct_reason = "Historical execution has no source fingerprint."
        elif not current["complete"]:
            direct_freshness = "UNKNOWN"
            direct_reason = "One or more relevant files cannot be fingerprinted reliably."
        elif not saved.get("complete") or stable is not True:
            direct_freshness = "UNKNOWN"
            direct_reason = "The source state was incomplete or changed during the recorded execution."
        elif saved.get("digest") == current.get("digest"):
            direct_freshness = "CURRENT"
            direct_reason = "Current relevant file contents match the recorded execution fingerprint."
        else:
            direct_freshness = "STALE"
            direct_reason = "Relevant file contents differ from the recorded execution fingerprint."

    # Discover local forward dependencies of relevant files
    if dependency_graph is None:
        from .dependencies import build_local_dependency_graph
        try:
            dependency_graph = build_local_dependency_graph(root)
        except Exception:
            dependency_graph = None

    discovered_deps: set[str] = set()
    if dependency_graph:
        for f in relevant_paths:
            discovered_deps.update(dependency_graph.get_transitive_dependencies(f))
    discovered_dependencies = sorted(discovered_deps - set(relevant_paths))

    # Check health of discovered dependencies
    for dep in discovered_dependencies:
        dep_path = root.joinpath(*PurePosixPath(dep).parts)
        if not dep_path.is_file():
            blocker = f"Dependency {dep}: MISSING"
            blockers.append(blocker)
            execution_blockers.append(blocker)

    if dependency_graph:
        for f in set(relevant_paths) | set(discovered_dependencies):
            if f in dependency_graph.parse_errors:
                blocker = f"Dependency {f} parse error: {dependency_graph.parse_errors[f]}"
                blockers.append(blocker)

    # Determine affected dependencies & active chains from prospective changes
    normalized_changed = {str(p).replace("\\", "/").removeprefix("./") for p in (changed_files or [])}

    active_chains: list[str] = []
    affected_deps: set[str] = set()

    # 1. From passed dependency chains
    if dependency_chains:
        for chain in dependency_chains:
            if chain and chain[-1] in relevant_paths:
                active_chains.append(" -> ".join(chain))
                if len(chain) > 1:
                    affected_deps.add(chain[0])

    # 2. From dependency graph lookup for changed files
    if dependency_graph and normalized_changed:
        for c in normalized_changed:
            if c in discovered_dependencies:
                affected_deps.add(c)
                # Find path from c to any relevant path
                _, paths_from_c = dependency_graph.get_transitive_dependents_with_paths(c)
                for f in relevant_paths:
                    if f in paths_from_c:
                        active_chains.append(" -> ".join(paths_from_c[f]))

    # Deduplicate chains and affected deps
    unique_chains = sorted(set(active_chains))
    unique_affected_deps = sorted(affected_deps)

    # Precedence-based selection logic:
    # 1. Direct mapping staleness on disk (or unreadable/missing direct files)
    # 2. Inferred dependency impact (dependency changed along discovered chain)
    # 3. Unverified baseline (missing evidence, failed outcome, incomplete mapping, blockers)
    # 4. Verified current baseline
    if direct_freshness == "STALE":
        selection_basis = "DIRECT_MAPPING"
        selected = True
        evidence_freshness = "STALE"
        reason = direct_reason
    elif unique_affected_deps or unique_chains:
        selection_basis = "INFERRED_DEPENDENCY"
        selected = True
        evidence_freshness = "STALE"
        dep_name = unique_affected_deps[0] if unique_affected_deps else "discovered dependency"
        chain_name = unique_chains[0] if unique_chains else dep_name
        reason = f"Local dependency '{dep_name}' changed along dependency chain '{chain_name}'."
    elif (
        latest is None
        or direct_freshness != "CURRENT"
        or last_outcome != "PASSED"
        or not mapping.get("verification_complete")
        or execution_blockers
    ):
        selection_basis = "UNVERIFIED_BASELINE"
        selected = True
        evidence_freshness = "UNKNOWN" if execution_blockers else direct_freshness
        reason = direct_reason
    else:
        selection_basis = "NONE"
        selected = False
        evidence_freshness = "CURRENT"
        reason = direct_reason

    if latest and last_outcome != "PASSED":
        if f"Latest execution outcome was {last_outcome}." not in reason:
            reason += f" Latest execution outcome was {last_outcome}."
    if not mapping.get("verification_complete"):
        blockers.append("Mapping is not designated as complete verification.")
    if last_outcome and last_outcome != "PASSED":
        blockers.append(f"Latest execution outcome is {last_outcome}.")

    coverage_status = (
        "PARTIAL_LOCAL_STATIC"
        if (dependency_graph and (dependency_graph.parse_errors or dependency_graph.uncertainties))
        else "LOCAL_STATIC_IMPORTS"
    )
    coverage_notes = [
        "Static dependency analysis resolved local Python AST imports.",
        "External packages, C extensions, dynamic imports (importlib/exec), and non-Python assets are not inferred as complete.",
    ]

    return {
        "requirement_id": requirement["id"],
        "test_file": test_file,
        "test_id": test_id,
        "reason": reason,
        "evidence_freshness": evidence_freshness,
        "direct_evidence_freshness": direct_freshness,
        "selection_basis": selection_basis,
        "affected_dependencies": unique_affected_deps,
        "dependency_chains": unique_chains,
        "discovered_dependencies": discovered_dependencies,
        "blockers": blockers,
        "execution_blockers": execution_blockers,
        "mapping_verification_complete": bool(mapping.get("verification_complete")),
        "has_prior_execution": latest is not None,
        "latest_outcome": last_outcome,
        "latest_ran_at": latest[0].get("ran_at") if latest else None,
        "current_fingerprint": current["digest"] if current["complete"] else None,
        "dependency_coverage": coverage_status,
        "coverage_notes": coverage_notes,
        "selected": selected,
    }


def build_verification_plan(
    root: Path,
    requirements: list[dict],
    details_by_id: dict[str, dict],
    mappings_by_id: dict[str, list[dict]],
    *,
    dependency_graph: any = None,
    changed_files: list[str] | None = None,
    dependency_chains_by_req: dict[str, list[list[str]]] | None = None,
) -> list[dict]:
    """Return stable requirement/test ordering and full selection rationale."""
    if dependency_graph is None:
        from .dependencies import build_local_dependency_graph
        try:
            dependency_graph = build_local_dependency_graph(root)
        except Exception:
            dependency_graph = None

    plan = []
    for requirement in sorted(requirements, key=lambda item: item["id"]):
        detail = details_by_id.get(requirement["id"], {})
        req_id = requirement["id"]
        req_chains = (dependency_chains_by_req or {}).get(req_id)
        for mapping in sorted(mappings_by_id.get(req_id, []),
                              key=lambda item: (item["test_file"], item["test_id"])):
            plan.append(
                assess_mapping_freshness(
                    root,
                    requirement,
                    mapping,
                    detail.get("checks", []),
                    dependency_graph=dependency_graph,
                    changed_files=changed_files,
                    dependency_chains=req_chains,
                )
            )
    return plan
