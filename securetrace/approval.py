"""Pre-action security approval and plain-language warning engine.

This module provides prospective analysis of proposed code changes before they
are written to disk, formats deterministic plain-language security warnings,
generates cryptographically bound approval tokens, and enforces atomic
application with Compare-And-Swap (CAS) concurrency guards.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Any
import uuid

from .config import project_root
from .db import connect
from .ledger import (
    analyze_change_impact,
    get_requirement_detail,
    mark_changed_files,
    now_iso,
    record_event,
)

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300  # 5 minutes
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Proposal:
    """A captured in-memory file change proposal awaiting user review or application."""
    proposal_id: str
    file_path: str  # Project-relative POSIX path
    canonical_path: str  # Resolved absolute path string
    operation: str  # "edit" or "write"
    original_hash: str  # SHA-256 of disk file before change (or empty if creating new file)
    proposed_hash: str  # SHA-256 of content after applying proposed change
    proposed_content: str  # Full prospective text content
    created_at: float
    expires_at: float
    decision: str  # "ALLOW", "FORCE_ASK", "DENY"
    status: str  # "PENDING", "APPROVED", "DENIED", "APPLIED", "EXPIRED"
    token: str
    warning_text: str
    affected_requirements: list[dict[str, Any]] = field(default_factory=list)
    inferred_dependent_files: list[str] = field(default_factory=list)
    dependency_coverage: str = "LOCAL_STATIC_IMPORTS"
    uncertainties: list[str] = field(default_factory=list)
    failure_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Proposal:
        return cls(**data)


def _get_approval_secret(root: Path) -> bytes:
    """Load or generate the persistent secret key used to sign approval tokens."""
    securetrace_dir = root / ".securetrace"
    securetrace_dir.mkdir(parents=True, exist_ok=True)
    key_file = securetrace_dir / "approval.key"
    if key_file.exists():
        try:
            return bytes.fromhex(key_file.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pass
    secret = secrets.token_bytes(32)
    try:
        key_file.write_text(secret.hex(), encoding="utf-8")
    except OSError:
        pass
    return secret


def compute_approval_token(
    root: Path,
    proposal_id: str,
    canonical_path: str,
    original_hash: str,
    proposed_hash: str,
    expires_at: float,
) -> str:
    """Compute an HMAC-SHA256 token binding proposal identity, target, and contents."""
    secret = _get_approval_secret(root)
    message = f"{proposal_id}:{canonical_path}:{original_hash}:{proposed_hash}:{expires_at:.3f}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_approval_token(
    root: Path,
    proposal: Proposal,
    token: str,
) -> bool:
    """Verify that an approval token is authentic and matches the proposal."""
    expected = compute_approval_token(
        root=root,
        proposal_id=proposal.proposal_id,
        canonical_path=proposal.canonical_path,
        original_hash=proposal.original_hash,
        proposed_hash=proposal.proposed_hash,
        expires_at=proposal.expires_at,
    )
    return hmac.compare_digest(expected, token)


def resolve_project_relative_path(root: Path, file_path: str | Path) -> tuple[str, Path]:
    """Resolve and validate a file path strictly within the project root.

    Rejects directory traversal (..) and symlinks resolving outside the root.
    Returns a tuple of (project_relative_posix_path, resolved_absolute_path).
    """
    root_resolved = root.resolve()
    target_candidate = (root / file_path).resolve()

    try:
        rel = target_candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(
            f"Path traversal or symlink escape rejected: '{file_path}' resolves outside project root"
        ) from exc

    return rel.as_posix(), target_candidate


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_disk_file_bytes(path: Path) -> tuple[bytes, str]:
    """Read binary bytes and compute SHA-256 to ensure exact newline/encoding consistency."""
    if not path.is_file():
        return b"", ""
    raw = path.read_bytes()
    return raw, _sha256_bytes(raw)


def simulate_proposed_content(
    target_path: Path,
    operation: str,
    content: str | None = None,
    target_pattern: str | None = None,
    replacement_pattern: str | None = None,
    append: bool = False,
    replace_all: bool = True,
    multi_edits: list[tuple[str, str, bool]] | None = None,
) -> tuple[str, str, str]:
    """Compute (original_content, proposed_content, original_hash) in memory without touching disk."""
    raw_bytes, original_hash = _read_disk_file_bytes(target_path)
    if raw_bytes:
        try:
            original_content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            original_content = raw_bytes.decode("latin-1")
    else:
        original_content = ""

    if operation == "write":
        if content is None:
            raise ValueError("write operation requires 'content'")
        if append:
            proposed_content = original_content + content
        else:
            proposed_content = content
    elif operation == "edit":
        if target_pattern is None or replacement_pattern is None:
            raise ValueError("edit operation requires 'target_pattern' and 'replacement_pattern'")
        if target_pattern not in original_content:
            raise ValueError(
                f"Target text not found in '{target_path.name}'. Edit cannot be applied."
            )
        proposed_content = original_content.replace(
            target_pattern, replacement_pattern, -1 if replace_all else 1
        )
    elif operation == "multi_edit":
        if not multi_edits:
            raise ValueError("multi_edit operation requires at least one replacement chunk")
        proposed_content = original_content
        for chunk_target, chunk_replacement, chunk_all in multi_edits:
            if chunk_target not in proposed_content:
                raise ValueError(
                    f"Target text not found in '{target_path.name}'. Edit cannot be applied."
                )
            proposed_content = proposed_content.replace(
                chunk_target, chunk_replacement, -1 if chunk_all else 1
            )
    else:
        raise ValueError(f"Unknown proposal operation: '{operation}'")

    return original_content, proposed_content, original_hash


def _proposals_dir(root: Path) -> Path:
    p_dir = root / ".securetrace" / "proposals"
    p_dir.mkdir(parents=True, exist_ok=True)
    return p_dir


def save_proposal(root: Path, proposal: Proposal) -> None:
    p_file = _proposals_dir(root) / f"{proposal.proposal_id}.json"
    p_file.write_text(json.dumps(proposal.to_dict(), indent=2), encoding="utf-8")


def load_proposal(root: Path, proposal_id: str) -> Proposal | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", proposal_id):
        return None
    p_file = _proposals_dir(root) / f"{proposal_id}.json"
    if not p_file.is_file():
        return None
    try:
        data = json.loads(p_file.read_text(encoding="utf-8"))
        return Proposal.from_dict(data)
    except (json.JSONDecodeError, OSError, TypeError):
        return None


def format_plain_language_warning(
    file_path: str,
    operation: str,
    affected_requirements: list[dict[str, Any]],
    inferred_dependent_files: list[str],
    dependency_coverage: str,
    uncertainties: list[str],
) -> str:
    """Format a deterministic 6-part plain-language security warning for nontechnical users.

    Uses accessible everyday English and clearly avoids unexplained technical terms
    such as 'AST', 'transitive dependency', 'fingerprint', or 'stale evidence'.
    """
    lines: list[str] = []
    lines.append("### SecureTrace Pre-Action Security Warning\n")

    # Part 1: What is proposed to change
    op_desc = {
        "edit": "replacing text",
        "multi_edit": "replacing several pieces of text",
    }.get(operation, "updating file content")
    lines.append(f"**1. What is proposed to change:**")
    lines.append(f"The AI coding agent proposes to modify `{file_path}` ({op_desc}).\n")

    # Part 2: What could go wrong in everyday language
    lines.append(f"**2. What could go wrong:**")
    categories = {req.get("category", "other").lower() for req in affected_requirements}
    risk_descriptions: list[str] = []
    if "authorization" in categories or "authentication" in categories:
        risk_descriptions.append(
            "If this change contains a mistake, it could allow unauthorized users to perform restricted actions, access private accounts, or bypass permission checks."
        )
    if "data_protection" in categories or "cryptography" in categories:
        risk_descriptions.append(
            "If this change contains a mistake, it could expose sensitive private data or weaken how confidential information is protected."
        )
    if "input_validation" in categories or "injection" in categories:
        risk_descriptions.append(
            "If this change contains a mistake, it could allow unsafe or unvalidated user input to reach sensitive parts of the application."
        )
    if not risk_descriptions:
        risk_descriptions.append(
            "If this change contains a mistake, it could weaken or bypass the security safeguards registered for this feature."
        )

    for desc in risk_descriptions:
        lines.append(desc)
    lines.append(
        "*(Note: This warning indicates a potential security risk requiring review. It does not mean a vulnerability has been found, "
        "and it does not mean the requirement has already been violated. The file is linked to the requirement, "
        "so a mistake here could affect it.)*\n"
    )

    # Part 3: Which registered security requirement triggered the warning and why
    lines.append(f"**3. Why this warning appeared:**")
    lines.append("This modification touches code protected by registered project security requirements:")
    for req in affected_requirements:
        req_id = req.get("id") or req.get("requirement_id", "UNKNOWN")
        title = req.get("title", "Security Requirement")
        severity = req.get("severity", "medium").upper()
        req_changed_files = req.get("changed_files", [])
        if file_path in req_changed_files:
            lines.append(f"- **{req_id}** (Severity: {severity}): \"{title}\" — `{file_path}` is directly linked to this requirement.")
        else:
            lines.append(f"- **{req_id}** (Severity: {severity}): \"{title}\" — This requirement relies on code that imports `{file_path}`. Changes here could indirectly affect that protected feature.")
        description = (req.get("description") or "").strip()
        if description:
            lines.append(f"  - What the requirement says: {description}")
        if req_changed_files:
            lines.append("  - Linked files this change reaches (directly or through imports): " + ", ".join(f"`{f}`" for f in req_changed_files))
        status = req.get("status")
        if status:
            lines.append(f"  - Its current recorded status: {status}")
    lines.append("")

    # Part 4: How serious the potential impact is
    lines.append(f"**4. How serious this potential impact is:**")
    max_severity_val = 0
    max_severity_name = "MEDIUM"
    for req in affected_requirements:
        sev = req.get("severity", "medium").lower()
        val = SEVERITY_ORDER.get(sev, 2)
        if val > max_severity_val:
            max_severity_val = val
            max_severity_name = sev.upper()

    lines.append(f"- **Highest Registered Severity:** {max_severity_name}")
    lines.append(f"- **Scope of Impact:** {len(affected_requirements)} registered security requirement(s) potentially affected.")
    if inferred_dependent_files:
        lines.append(f"- **Dependent Application Files:** {len(inferred_dependent_files)} other local file(s) rely on this code.")
    lines.append("*(Severity is derived directly from the registered requirements in your project ledger; it has not been invented.)*\n")

    # Part 5: What you can choose to do
    lines.append(f"**5. What you can choose to do:**")
    lines.append("- **Allow / Approve:** Permit the change if you have inspected the proposed modification and confirmed it is safe and intentional.")
    lines.append("- **Deny / Abort:** Stop the change if you did not expect this file to be modified or want to review the code with your team first.")
    ids = ", ".join(str(r.get("id") or r.get("requirement_id", "")) for r in affected_requirements)
    lines.append(
        f"- **Try another approach:** Choose Deny, then tell the agent to propose a different change that keeps {ids} intact. "
        "SecureTrace can only ask the agent's tool for an approve-or-deny prompt, so this step is a message you send. "
        "The new proposal is checked again automatically before anything is written.\n"
    )

    # Part 6: What happens after your decision
    lines.append(f"**6. What happens after your decision:**")
    lines.append(f"- **If you approve:** The change will be applied to `{file_path}`. SecureTrace will immediately mark the verification records for the affected requirements as outdated, and you should run your verification tests to confirm the application remains safe.")
    lines.append(f"- **If you deny:** The change is discarded. `{file_path}` will not be modified, and your repository remains completely untouched.\n")

    # Incomplete dependency analysis disclosure if applicable
    if dependency_coverage == "PARTIAL_LOCAL_STATIC" or uncertainties:
        lines.append(
            "> [!NOTE]\n"
            "> **Notice on Analysis Scope:** SecureTrace could not check every possible dependency in this project "
            "(for example, dynamic imports or non-standard file structures were encountered). "
            "Additional parts of the application might depend on this code beyond those listed above."
        )

    return "\n".join(lines).strip()


def evaluate_proposal(
    root: Path,
    file_path: str,
    operation: str = "write",
    content: str | None = None,
    target_pattern: str | None = None,
    replacement_pattern: str | None = None,
    append: bool = False,
    timeout_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    replace_all: bool = True,
    multi_edits: list[tuple[str, str, bool]] | None = None,
) -> Proposal:
    """Evaluate a proposed file modification prospectively without modifying files.

    Performs containment checks, computes in-memory prospective content, runs
    impact analysis against registered requirements, and determines whether
    explicit user approval is required.
    """
    rel_path, target_resolved = resolve_project_relative_path(root, file_path)
    proposal_id = f"PROP-{uuid.uuid4().hex[:12].upper()}"
    now = time.time()
    expires_at = now + timeout_seconds

    # Read original content and simulate proposed content with exact binary hash
    original_content, proposed_content, original_hash = simulate_proposed_content(
        target_path=target_resolved,
        operation=operation,
        content=content,
        target_pattern=target_pattern,
        replacement_pattern=replacement_pattern,
        append=append,
        replace_all=replace_all,
        multi_edits=multi_edits,
    )

    proposed_hash = _sha256_bytes(proposed_content.encode("utf-8"))

    # If content does not change at all, allow without friction
    if original_hash and original_hash == proposed_hash:
        token = compute_approval_token(root, proposal_id, target_resolved.as_posix(), original_hash, proposed_hash, expires_at)
        proposal = Proposal(
            proposal_id=proposal_id,
            file_path=rel_path,
            canonical_path=target_resolved.as_posix(),
            operation=operation,
            original_hash=original_hash,
            proposed_hash=proposed_hash,
            proposed_content=proposed_content,
            created_at=now,
            expires_at=expires_at,
            decision="ALLOW",
            status="APPROVED",
            token=token,
            warning_text="No substantive changes proposed.",
            affected_requirements=[],
            inferred_dependent_files=[],
            dependency_coverage="LOCAL_STATIC_IMPORTS",
            uncertainties=[],
        )
        save_proposal(root, proposal)
        return proposal

    # Run change-impact analysis for this file path
    impact = analyze_change_impact(root, [rel_path])
    raw_reqs = impact.get("requirements", [])
    inferred_deps = impact.get("inferred_dependent_files", [])
    coverage = impact.get("dependency_coverage", "LOCAL_STATIC_IMPORTS")
    uncertainties = [u.get("uncertainty", "") for u in impact.get("uncertainties", []) if isinstance(u, dict) and u.get("uncertainty")]

    # Enrich affected requirements with full metadata from ledger
    affected_reqs: list[dict[str, Any]] = []
    for item in raw_reqs:
        req_id = item.get("requirement_id")
        detail = get_requirement_detail(root, req_id) or {}
        enriched = {
            "id": req_id,
            "requirement_id": req_id,
            "title": detail.get("title", "Security Requirement"),
            "description": detail.get("description", ""),
            "linked_files": detail.get("file_paths", []),
            "category": detail.get("category", "other"),
            "severity": detail.get("severity", "medium"),
            "status": detail.get("status", "IDENTIFIED"),
            "changed_files": item.get("changed_files", []),
            "dependency_chains": item.get("dependency_chains", []),
        }
        affected_reqs.append(enriched)

    # If any registered security requirement is affected (directly or via dependencies)
    if affected_reqs:
        warning = format_plain_language_warning(
            file_path=rel_path,
            operation=operation,
            affected_requirements=affected_reqs,
            inferred_dependent_files=inferred_deps,
            dependency_coverage=coverage,
            uncertainties=uncertainties,
        )
        token = compute_approval_token(root, proposal_id, target_resolved.as_posix(), original_hash, proposed_hash, expires_at)
        proposal = Proposal(
            proposal_id=proposal_id,
            file_path=rel_path,
            canonical_path=target_resolved.as_posix(),
            operation=operation,
            original_hash=original_hash,
            proposed_hash=proposed_hash,
            proposed_content=proposed_content,
            created_at=now,
            expires_at=expires_at,
            decision="FORCE_ASK",
            status="PENDING",
            token=token,
            warning_text=warning,
            affected_requirements=affected_reqs,
            inferred_dependent_files=inferred_deps,
            dependency_coverage=coverage,
            uncertainties=uncertainties,
        )
    else:
        # No security requirements affected: safe documented policy
        token = compute_approval_token(root, proposal_id, target_resolved.as_posix(), original_hash, proposed_hash, expires_at)
        proposal = Proposal(
            proposal_id=proposal_id,
            file_path=rel_path,
            canonical_path=target_resolved.as_posix(),
            operation=operation,
            original_hash=original_hash,
            proposed_hash=proposed_hash,
            proposed_content=proposed_content,
            created_at=now,
            expires_at=expires_at,
            decision="ALLOW",
            status="APPROVED",
            token=token,
            warning_text="No registered security requirements affected.",
            affected_requirements=[],
            inferred_dependent_files=inferred_deps,
            dependency_coverage=coverage,
            uncertainties=uncertainties,
        )

    save_proposal(root, proposal)
    return proposal


def deny_proposal(root: Path, proposal_id: str) -> Proposal:
    """Explicitly deny/abort a proposal. Leaves the target file untouched."""
    proposal = load_proposal(root, proposal_id)
    if not proposal:
        raise ValueError(f"Proposal '{proposal_id}' not found")
    if proposal.status == "APPLIED":
        raise ValueError(f"Proposal '{proposal_id}' has already been applied and cannot be denied")

    proposal.status = "DENIED"
    save_proposal(root, proposal)

    # Record event in ledger
    timestamp = now_iso()
    try:
        with connect(root) as db:
            db.execute(
                "INSERT INTO events(requirement_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
                (
                    proposal.affected_requirements[0].get("id") if proposal.affected_requirements else None,
                    "APPROVAL_DENIED",
                    f"Proposal {proposal_id} for {proposal.file_path} was denied by user.",
                    timestamp,
                ),
            )
    except Exception:
        pass

    return proposal


def apply_proposal(
    root: Path,
    proposal_id: str,
    token: str,
) -> Proposal:
    """Apply an approved proposal to disk with atomic swap and CAS validation.

    Enforces:
    1. Valid HMAC token binding proposal, target, and prospective content.
    2. Expiry check (fails closed if expired).
    3. Single-use replay protection (cannot re-apply an already applied proposal).
    4. Status check (must not be DENIED).
    5. Compare-And-Swap (CAS) guard: target file on disk must match original_hash.
    6. Atomic file write via temporary sibling file and os.replace.
    7. Updates ledger to mark affected requirements as STALE.
    """
    proposal = load_proposal(root, proposal_id)
    if not proposal:
        raise ValueError(f"Proposal '{proposal_id}' not found")

    # 1. Verify token
    if not verify_approval_token(root, proposal, token):
        raise ValueError("Invalid approval token: signature mismatch or tampered proposal")

    # 2. Check replay
    if proposal.status == "APPLIED":
        raise ValueError(f"Replay rejected: proposal '{proposal_id}' has already been applied")

    # 3. Check denial
    if proposal.status == "DENIED":
        raise ValueError(f"Cannot apply proposal '{proposal_id}': proposal was denied")

    # 4. Check expiry
    if time.time() > proposal.expires_at:
        proposal.status = "EXPIRED"
        save_proposal(root, proposal)
        raise ValueError(f"Proposal '{proposal_id}' has expired. Re-review required.")

    # 5. Validate path containment
    _, target_resolved = resolve_project_relative_path(root, proposal.file_path)

    # 6. Compare-And-Swap (CAS) concurrency guard
    _, current_disk_hash = _read_disk_file_bytes(target_resolved)
    if current_disk_hash != proposal.original_hash:
        raise ValueError(
            f"Concurrent modification detected: '{proposal.file_path}' changed on disk since review "
            f"(expected SHA-256 {proposal.original_hash or 'EMPTY'}, found {current_disk_hash or 'EMPTY'}). "
            f"Overwriting is blocked."
        )

    # 7. Atomic file application
    target_dir = target_resolved.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    fd, temp_path_str = tempfile.mkstemp(prefix=".sec_tmp_", suffix=".tmp", dir=target_dir)
    temp_path = Path(temp_path_str)

    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(proposal.proposed_content.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, target_resolved)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass

    # 8. Mark proposal status as APPLIED
    proposal.status = "APPLIED"
    save_proposal(root, proposal)

    # 9. Reassess freshness / mark affected requirements as STALE in ledger
    timestamp = now_iso()
    try:
        mark_changed_files(root, [proposal.file_path])
        with connect(root) as db:
            db.execute(
                "INSERT INTO events(requirement_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
                (
                    proposal.affected_requirements[0].get("id") if proposal.affected_requirements else None,
                    "APPROVAL_APPLIED",
                    f"Proposal {proposal_id} applied to {proposal.file_path} (SHA-256: {proposal.proposed_hash[:10]}).",
                    timestamp,
                ),
            )
    except Exception:
        pass

    return proposal


def sweep_unresolved_reviews(root: Path, *, now: float | None = None) -> list[str]:
    """Close out review requests that expired with no observed write.

    The host does not report the user's decision to SecureTrace, so an expired
    PENDING proposal is recorded as "no write observed", never as "denied".
    """
    now = time.time() if now is None else now
    closed: list[str] = []
    p_dir = root / ".securetrace" / "proposals"
    if not p_dir.is_dir():
        return closed
    for p_file in sorted(p_dir.glob("PROP-*.json")):
        proposal = load_proposal(root, p_file.stem)
        if proposal is None or proposal.status != "PENDING" or proposal.decision != "FORCE_ASK":
            continue
        if now <= proposal.expires_at:
            continue
        proposal.status = "EXPIRED"
        save_proposal(root, proposal)
        for req in proposal.affected_requirements or [{}]:
            record_event(
                root, req.get("id"), "REVIEW_NO_WRITE_OBSERVED",
                f"Review {proposal.proposal_id} for {proposal.file_path} expired and no completed write matching it "
                "was observed. The host does not report the user's decision, so this may be a denial, a cancellation, "
                "or a failed write.",
            )
        closed.append(proposal.proposal_id)
    return closed


def find_reviewed_proposal_for_write(root: Path, rel_path: str, *, now: float | None = None) -> Proposal | None:
    """Return the pending reviewed proposal whose proposed content now matches the file on disk."""
    now = time.time() if now is None else now
    try:
        _, target = resolve_project_relative_path(root, rel_path)
    except ValueError:
        return None
    _, disk_hash = _read_disk_file_bytes(target)
    if not disk_hash:
        return None
    p_dir = root / ".securetrace" / "proposals"
    if not p_dir.is_dir():
        return None
    for p_file in sorted(p_dir.glob("PROP-*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        proposal = load_proposal(root, p_file.stem)
        if (
            proposal is not None
            and proposal.status == "PENDING"
            and proposal.decision == "FORCE_ASK"
            and proposal.file_path == rel_path
            and proposal.proposed_hash == disk_hash
        ):
            return proposal
    return None
