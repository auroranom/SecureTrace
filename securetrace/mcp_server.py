
from __future__ import annotations

import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .db import connect
from .ledger import (
    add_requirement,
    list_requirements,
    record_check,
    record_test_check,
    get_requirement_detail,
    mark_changed_files as ledger_mark_changed_files,
    analyze_change_impact,
    current_verification_plan,
)
from .reporting import render_report
from .http_probe import HttpProbeSpec, ProbeVerdict, dispatch_probe
from .monitor import start_watcher, stop_watcher


mcp = FastMCP("securetrace")


def _root() -> Path:
    """Resolve and initialize the configured target project root."""
    configured = os.environ.get("SECURETRACE_PROJECT_ROOT")

    root = (
        Path(configured).expanduser().resolve()
        if configured
        else Path.cwd().resolve()
    )

    with connect(root):
        pass

    return root


@mcp.tool()
def list_security_requirements() -> dict:
    """List security requirements tracked for the target repository."""
    root = _root()

    return {
        "repository": str(root),
        "requirements": list_requirements(root),
    }


@mcp.tool()
def add_security_requirement(
    title: str,
    description: str,
    category: str = "other",
    severity: str = "medium",
    file_paths: list[str] | None = None,
) -> dict:
    """Register a security requirement and optional repository-relative file links."""
    root = _root()

    item = add_requirement(
        root,
        title,
        description,
        category,
        severity,
        file_paths or [],
    )

    return {
        "repository": str(root),
        "requirement": item,
    }


@mcp.tool()
def record_security_check(
    requirement_id: str,
    check_name: str,
    passed: bool,
    details: str = "",
    commit_hash: str | None = None,
    verification_complete: bool = False,
) -> dict:
    """Record security-check evidence.

    Set verification_complete=True only when the check fully verifies
    the requirement.
    """
    root = _root()

    return record_check(
        root,
        requirement_id,
        check_name,
        passed,
        details,
        commit_hash,
        verification_complete,
    )


@mcp.tool()
def mark_changed_files(file_paths: list[str]) -> dict:
    """Mark linked requirements for re-verification after file changes."""
    root = _root()

    affected = ledger_mark_changed_files(root, file_paths)

    return {
        "affected_requirements": affected,
        "count": len(affected),
    }


@mcp.tool()
def get_security_report() -> dict:
    """Return the current Markdown security report."""
    root = _root()

    return {
        "repository": str(root),
        "report_markdown": render_report(root),
    }


def _validate_project_relative_paths(root: Path, file_paths: list[str]) -> list[str]:
    """Validate and resolve project-relative file paths, rejecting any escapes."""
    if not isinstance(file_paths, list):
        raise ValueError("file_paths must be a list of project-relative file paths")
    if not file_paths:
        raise ValueError("file_paths cannot be empty")

    root_resolved = root.resolve()
    normalized_paths: list[str] = []

    for raw in file_paths:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("Each file path must be a non-empty string")
        if "\x00" in raw:
            raise ValueError(f"Invalid file path: {raw!r}")

        # Windows drive-qualified and UNC paths are never project-relative. On POSIX they would
        # otherwise be read as odd-but-legal relative names and pass containment, so reject them
        # on every platform to keep ledgers portable.
        if re.match(r"^[A-Za-z]:[\\/]", raw.strip()) or raw.strip().startswith("\\\\"):
            raise ValueError(f"File path escapes the project root: {raw}")

        path_obj = Path(raw.strip())
        if path_obj.is_absolute():
            try:
                resolved = path_obj.resolve()
                rel = resolved.relative_to(root_resolved)
            except (ValueError, OSError) as exc:
                raise ValueError(f"File path escapes the project root: {raw}") from exc
        else:
            try:
                resolved = (root_resolved / path_obj).resolve()
                rel = resolved.relative_to(root_resolved)
            except (ValueError, OSError) as exc:
                raise ValueError(f"File path escapes the project root: {raw}") from exc

        rel_str = rel.as_posix()
        if not rel_str or rel_str == ".":
            raise ValueError(f"File path cannot resolve to the project root itself: {raw}")

        normalized_paths.append(rel_str)

    return sorted(set(normalized_paths))


@mcp.tool()
def get_change_impact(file_paths: list[str]) -> dict:
    """Analyze the impact of prospective file changes on security requirements and mapped tests.

    This tool is strictly read-only. It performs deterministic dry-run impact analysis
    without modifying files, mutating the ledger, running tests, or executing scanners.
    """
    root = _root()
    normalized = _validate_project_relative_paths(root, file_paths)
    impact = analyze_change_impact(root, normalized)

    affected_reqs = []
    for item in impact.get("requirements", []):
        req_copy = dict(item)
        detail = get_requirement_detail(root, item["requirement_id"])
        if detail:
            req_copy.setdefault("title", detail.get("title", ""))
            req_copy.setdefault("severity", detail.get("severity", "medium"))
            req_copy.setdefault("status", detail.get("status", "IDENTIFIED"))
        affected_reqs.append(req_copy)

    mapped_tests = [
        {
            "requirement_id": test["requirement_id"],
            "test_file": test["test_file"],
            "test_id": test["test_id"],
            "verification_complete": bool(test.get("verification_complete")),
        }
        for req in impact.get("requirements", [])
        for test in req.get("mapped_tests", [])
    ]

    return {
        "repository": str(root),
        "changed_files": normalized,
        "inferred_dependent_files": impact.get("inferred_dependent_files", []),
        "affected_requirements": affected_reqs,
        "mapped_tests": mapped_tests,
        "eligible_reruns": impact.get("eligible_reruns", []),
        "recommended_verification_actions": impact.get("eligible_reruns", []),
        "verification_plan": impact.get("verification_plan", []),
        "uncertainties": impact.get("uncertainties", []),
        "dependency_coverage": impact.get("dependency_coverage", "LOCAL_STATIC_IMPORTS"),
        "coverage_limitations": impact.get(
            "coverage_limitations",
            (
                "Static dependency analysis resolves local Python AST imports. "
                "External packages, C extensions, dynamic imports (importlib/exec), and non-Python assets are not inferred as complete."
            ),
        ),
        "notice": (
            "Dry-run change-impact analysis only. No files were modified, no tests or scanners were executed, "
            "and no ledger evidence was marked stale. Passing statuses reflect historical recorded evidence only."
        ),
    }


@mcp.tool()
def get_security_review_context(proposal_id: str | None = None) -> dict:
    """Return the latest security review (or a named one) so an agent can propose a safer alternative.

    Read-only. It does not approve, deny, apply, or re-run anything. Any new
    proposal the agent makes still goes through the pre-action hook again.
    """
    from .approval import load_proposal

    root = _root()
    p_dir = root / ".securetrace" / "proposals"
    proposal = None
    if proposal_id:
        proposal = load_proposal(root, proposal_id)
    elif p_dir.is_dir():
        for p_file in sorted(p_dir.glob("PROP-*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
            candidate = load_proposal(root, p_file.stem)
            if candidate is not None and candidate.decision == "FORCE_ASK":
                proposal = candidate
                break
    if proposal is None:
        return {"found": False, "notice": "No security review proposal was found."}

    requirements = [
        {
            "id": r.get("id"),
            "title": r.get("title"),
            "description": r.get("description", ""),
            "severity": r.get("severity"),
            "files": r.get("changed_files", []),
        }
        for r in proposal.affected_requirements
    ]
    ids = ", ".join(str(r["id"]) for r in requirements)
    return {
        "found": True,
        "proposal_id": proposal.proposal_id,
        "file": proposal.file_path,
        "review_status": proposal.status,
        "affected_requirements": requirements,
        "warning": proposal.warning_text,
        "instruction_for_agent": (
            f"The previous change to {proposal.file_path} may affect {ids}. Propose a different implementation that "
            "preserves what those requirements describe. Your new proposal will be checked again before it is written. "
            "This is a potential risk, not a confirmed vulnerability."
        ),
        "notice": "Read-only context. No change was approved, denied, or applied by this call.",
    }


@mcp.tool()
def get_verification_plan(requirement_id: str | None = None) -> dict:
    """Return the deterministic verification plan for the target project.

    This tool is strictly read-only. It inspects current evidence freshness,
    mapped verification tests, eligible reruns, and blockers without executing
    tests, running scanners, modifying files, or mutating the ledger.
    """
    root = _root()

    if requirement_id is not None:
        if not isinstance(requirement_id, str) or not requirement_id.strip():
            raise ValueError("requirement_id must be a non-empty string")
        clean_id = requirement_id.strip()
        detail = get_requirement_detail(root, clean_id)
        if detail is None:
            raise ValueError(f"Unknown requirement: {requirement_id}")
    else:
        clean_id = None

    full_plan = current_verification_plan(root)
    if clean_id is not None:
        plan = [item for item in full_plan if item.get("requirement_id") == clean_id]
    else:
        plan = full_plan

    eligible_checks = [item for item in plan if item.get("selected")]
    uncertainties = [
        {
            "requirement_id": item.get("requirement_id"),
            "test_file": item.get("test_file"),
            "test_id": item.get("test_id"),
            "reason": item.get("reason"),
            "evidence_freshness": item.get("evidence_freshness"),
            "blockers": item.get("blockers", []),
        }
        for item in plan
        if item.get("evidence_freshness") == "UNKNOWN" or item.get("blockers")
    ]

    return {
        "repository": str(root),
        "requirement_id": clean_id,
        "plan": plan,
        "eligible_checks": eligible_checks,
        "total_checks": len(plan),
        "eligible_count": len(eligible_checks),
        "uncertainties": uncertainties,
        "dependency_coverage": (
            "PARTIAL_LOCAL_STATIC"
            if any(item.get("dependency_coverage") == "PARTIAL_LOCAL_STATIC" for item in plan)
            else "LOCAL_STATIC_IMPORTS"
        ),
        "coverage_limitations": (
            "Static dependency analysis resolves local Python AST imports. "
            "External packages, C extensions, dynamic imports (importlib/exec), and non-Python assets are not inferred as complete."
        ),
        "notice": (
            "Dry-run verification planning only. No tests, scanners, or subprocesses were executed, "
            "and no ledger evidence was marked stale. Passing statuses reflect historical recorded evidence only."
        ),
    }


@mcp.tool()
def probe_endpoint_security(
    requirement_id: str,
    port: int,
    path: str = "/doner",
    approved: bool = False,
) -> dict:
    """Prepare or execute an approved local unauthenticated-access probe.

    The probe is restricted to 127.0.0.1. When approved=False,
    only a plan is returned; no network request is made.
    """
    root = _root()

    detail = get_requirement_detail(root, requirement_id)

    if detail is None:
        raise ValueError(f"Unknown requirement: {requirement_id}")

    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1024 <= port <= 65535
    ):
        raise ValueError(
            "port must be an unprivileged integer between 1024 and 65535"
        )

    clean_path = path.strip()

    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path

    if (
        ".." in clean_path
        or "\\" in clean_path
        or "\r" in clean_path
        or "\n" in clean_path
        or "?" in clean_path
        or "#" in clean_path
    ):
        raise ValueError(
            "path must be a clean project route without traversal, "
            "backslashes, query strings, or fragments"
        )

    target_url = f"http://127.0.0.1:{port}{clean_path}"

    spec = HttpProbeSpec(
        requirement_id=requirement_id,
        target_url=target_url,
        method="GET",
        timeout_seconds=5.0,
        expected_unauthenticated_indicators=(
            "eshwar_admin",
            "Donor",
            "table",
            "doner",
        ),
    )

    if not approved:
        return {
            "status": "APPROVAL_REQUIRED",
            "message": (
                "Probe plan prepared. Explicit user approval is required "
                "before the HTTP request is dispatched."
            ),
            "plan": {
                "requirement_id": requirement_id,
                "requirement_title": detail.get("title", ""),
                "target_url": target_url,
                "method": "GET",
                "scope": "Read-only unauthenticated route check",
                "invariants": [
                    "Restricted to 127.0.0.1 loopback",
                    "External redirects must not be followed",
                    "Sensitive response content must not be persisted",
                    "A single endpoint probe cannot mark a requirement VERIFIED",
                ],
            },
        }

    eval_result = dispatch_probe(spec)
    provenance = eval_result.to_provenance(spec)
    check_name = f"http_probe:GET {clean_path}"

    record_result = record_test_check(
        root=root,
        requirement_id=requirement_id,
        test_id=check_name,
        outcome=eval_result.ledger_outcome,
        execution=provenance,
        verification_complete=False,
    )

    verdict_labels = {
        ProbeVerdict.VULNERABLE: "VULNERABLE",
        ProbeVerdict.SECURE_FOR_THIS_CHECK: "SECURE_FOR_THIS_CHECK",
        ProbeVerdict.INCONCLUSIVE: "INCONCLUSIVE",
    }

    verdict_label = verdict_labels.get(
        eval_result.verdict,
        str(eval_result.verdict),
    )

    return {
        "status": "COMPLETED",
        "verdict": eval_result.verdict.value,
        "summary": f"{verdict_label}: {eval_result.explanation}",
        "requirement_id": requirement_id,
        "requirement_status": record_result.get("status"),
        "http_status": eval_result.status_code,
        "evidence_recorded": {
            "check_name": check_name,
            "ledger_outcome": eval_result.ledger_outcome,
            "verification_complete": False,
            "body_byte_count": eval_result.body_byte_count,
            "body_sha256": eval_result.body_sha256,
        },
    }


def main() -> None:
    """Run MCP with automatic filesystem monitoring."""
    root = _root()
    observer = start_watcher(root)

    try:
        mcp.run(transport="stdio")
    finally:
        stop_watcher(observer)


if __name__ == "__main__":
    main()
