"""Pre-action security approval and plain-language warning engine.

This module provides prospective analysis of proposed code changes before they
are written to disk, formats deterministic plain-language security warnings,
generates cryptographically bound approval tokens, and enforces atomic
application with Compare-And-Swap (CAS) concurrency guards.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time
from collections.abc import Iterator
from typing import Any
import uuid

from .config import project_root
from .db import connect
from .diff_analysis import DiffAssessment, assess_proposed_diff
from .ledger import (
    analyze_change_impact,
    get_requirement_detail,
    mark_changed_files,
    now_iso,
    record_event,
)

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300  # 5 minutes
LOCK_WAIT_SECONDS = 5.0
LOCK_STALE_SECONDS = 60.0
# Statuses from which the standalone path may still apply a proposal.
APPLICABLE_STATUSES = frozenset({"PENDING", "APPROVED"})
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
    diff_classification: str = ""
    assessed_risk: str = ""
    diff_evidence: list[str] = field(default_factory=list)
    recommended_tests: list[str] = field(default_factory=list)
    # --- Phase 3 additions (all defaulted: records written by older versions still load) ---
    # CONFIRMED_AFFECTED | INCOMPLETE_UNKNOWN_IMPACT | COMPLETE_NO_IMPACT | NOT_ANALYZED_NO_CHANGE | "" (legacy)
    analysis_status: str = ""
    # Requirements that incomplete analysis could not rule out. Never merged into affected_requirements.
    possibly_affected_requirements: list[dict[str, Any]] = field(default_factory=list)
    unknown_impact: list[str] = field(default_factory=list)
    # Text encoding of the on-disk original ("utf-8" or "latin-1" for non-UTF-8 files; preserved on apply).
    encoding: str = "utf-8"
    # Persistence failures observed while recording this proposal's lifecycle (never silently dropped).
    audit_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Proposal:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


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

    Limits: this is a check at one instant. A symlink or parent directory can be
    swapped after it returns (TOCTOU); ``apply_proposal`` therefore re-resolves and
    re-checks immediately before replacing, but a portable implementation cannot
    close that window completely (see README "Filesystem threat model").
    """
    if not str(file_path).strip() or "\x00" in str(file_path):
        raise ValueError("Invalid file path: empty or contains a NUL byte")
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


def detect_text_encoding(raw: bytes) -> str:
    """UTF-8 when valid, otherwise latin-1 (a lossless byte<->str mapping, so untouched bytes survive)."""
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "latin-1"


def encode_proposed(text: str, encoding: str) -> bytes:
    try:
        return text.encode(encoding)
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"Proposed content cannot be represented in the file's existing {encoding} encoding "
            "without altering other bytes; refusing rather than silently transcoding the file."
        ) from exc


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
            if "\r\n" in original_content and "\r\n" not in content:
                content = content.replace("\n", "\r\n")
            elif "\r\n" not in original_content and "\r\n" in content:
                content = content.replace("\r\n", "\n")
            proposed_content = original_content + content
        else:
            if "\r\n" in original_content and "\r\n" not in content:
                crlf_content = content.replace("\n", "\r\n")
                if crlf_content == original_content:
                    content = crlf_content
            proposed_content = content
    elif operation == "edit":
        if target_pattern is None or replacement_pattern is None:
            raise ValueError("edit operation requires 'target_pattern' and 'replacement_pattern'")
        if target_pattern not in original_content:
            if "\r\n" in original_content and "\r\n" not in target_pattern:
                crlf_target = target_pattern.replace("\n", "\r\n")
                if crlf_target in original_content:
                    target_pattern = crlf_target
                    replacement_pattern = replacement_pattern.replace("\r\n", "\n").replace("\n", "\r\n")
            elif "\r\n" not in original_content and "\r\n" in target_pattern:
                lf_target = target_pattern.replace("\r\n", "\n")
                if lf_target in original_content:
                    target_pattern = lf_target
                    replacement_pattern = replacement_pattern.replace("\r\n", "\n")
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
                if "\r\n" in proposed_content and "\r\n" not in chunk_target:
                    crlf_target = chunk_target.replace("\n", "\r\n")
                    if crlf_target in proposed_content:
                        chunk_target = crlf_target
                        chunk_replacement = chunk_replacement.replace("\r\n", "\n").replace("\n", "\r\n")
                elif "\r\n" not in proposed_content and "\r\n" in chunk_target:
                    lf_target = chunk_target.replace("\r\n", "\n")
                    if lf_target in proposed_content:
                        chunk_target = lf_target
                        chunk_replacement = chunk_replacement.replace("\r\n", "\n")
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
    """Persist atomically (temp file + replace) so a concurrent reader never sees a torn record."""
    p_file = _proposals_dir(root) / f"{proposal.proposal_id}.json"
    fd, tmp = tempfile.mkstemp(prefix=".prop_", suffix=".tmp", dir=p_file.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(proposal.to_dict(), indent=2))
        os.replace(tmp, p_file)
    finally:
        try:
            Path(tmp).unlink(missing_ok=True)
        except OSError:
            pass


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


_IMPACT_SENTENCES = (
    ({"authorization", "authentication"},
     "A mistake here could let unauthorized users perform restricted actions or bypass permission checks."),
    ({"data_protection", "cryptography"},
     "A mistake here could expose sensitive data or weaken how it is protected."),
    ({"input_validation", "injection"},
     "A mistake here could let unsafe user input reach sensitive parts of the app."),
)
_DEFAULT_IMPACT = "A mistake here could weaken or bypass the security safeguards registered for this feature."
_DECISION_NOTE = (
    "> **Decide in Antigravity's approval prompt.** This message does not approve or deny anything."
)


def _impact_sentence(affected_requirements: list[dict[str, Any]]) -> str:
    categories = {str(r.get("category", "other")).lower() for r in affected_requirements}
    for wanted, sentence in _IMPACT_SENTENCES:
        if categories & wanted:
            return sentence
    return _DEFAULT_IMPACT


def _all_uncertainties(uncertainties: list[str], diff_assessment: DiffAssessment | None) -> list[str]:
    merged = list(uncertainties)
    if diff_assessment:
        merged.extend(u for u in diff_assessment.uncertainties if u not in merged)
    return merged


def format_plain_language_warning(
    file_path: str,
    operation: str,
    affected_requirements: list[dict[str, Any]],
    inferred_dependent_files: list[str],
    dependency_coverage: str,
    uncertainties: list[str],
    diff_assessment: DiffAssessment | None = None,
    proposal_id: str = "",
) -> str:
    """Compact, scannable pre-action warning (about 8-12 short lines).

    The full analysis (evidence, dependencies, uncertainties) is not repeated here; it is
    produced by :func:`format_warning_details` and stored on the recorded proposal.
    """
    risk = (diff_assessment.assessed_risk if diff_assessment and diff_assessment.assessed_risk else "UNCERTAIN").upper()
    top = max(
        (str(r.get("severity", "medium")).lower() for r in affected_requirements),
        key=lambda sev: SEVERITY_ORDER.get(sev, 2), default="medium",
    )
    prominent = risk in {"HIGH", "CRITICAL"} or top in {"high", "critical"}
    heading = "### \u26a0\ufe0f SecureTrace: review required"
    if risk in {"HIGH", "CRITICAL"}:
        heading = f"### \U0001f6a8 SecureTrace: {risk} RISK change \u2014 review required"

    lines = [heading, f"**File:** `{file_path}`"]
    classification = diff_assessment.classification if diff_assessment and diff_assessment.classification else "UNCERTAIN"
    risk_text = f"**{risk}**" if prominent and risk in {"HIGH", "CRITICAL"} else risk
    lines.append(f"**Change:** {classification} \u00b7 **Assessed risk:** {risk_text}")
    for req in affected_requirements:
        req_id = req.get("id") or req.get("requirement_id", "UNKNOWN")
        sev = str(req.get("severity", "medium")).upper()
        lines.append(f"**Requirement:** {req_id} \u2014 \"{req.get('title', 'Security Requirement')}\" ({sev} severity)")
    lines.append(f"**Impact:** {_impact_sentence(affected_requirements)}")
    if diff_assessment and diff_assessment.recommended_tests:
        lines.append("**Verify with:** " + ", ".join(f"`{t}`" for t in diff_assessment.recommended_tests))
    statuses = sorted({str(r["status"]) for r in affected_requirements if r.get("status")})
    if statuses:
        lines.append(f"**Evidence status:** {', '.join(statuses)}")
    lines.append(_DECISION_NOTE)
    note = "> Details" + (f" for `{proposal_id}`" if proposal_id else "") + " are in SecureTrace's recorded proposal/report"
    if proposal_id:
        note += f" (`securetrace review {proposal_id}`)"
    if dependency_coverage == "PARTIAL_LOCAL_STATIC" or _all_uncertainties(uncertainties, diff_assessment):
        note += "; analysis was partial, so treat this as a minimum, not a guarantee"
    lines.append(note + ".")
    return "\n".join(lines)


def format_warning_details(proposal: "Proposal") -> str:
    """Expanded details for a recorded proposal: evidence, dependencies, uncertainties, recommendations."""
    lines = [f"### SecureTrace details for {proposal.proposal_id}", f"**File:** `{proposal.file_path}` ({proposal.operation})"]
    if proposal.diff_classification or proposal.assessed_risk:
        lines.append(f"**Change:** {proposal.diff_classification or 'UNCERTAIN'} \u00b7 **Assessed risk:** {proposal.assessed_risk or 'UNCERTAIN'}")
    for req in proposal.affected_requirements:
        rid = req.get("id") or req.get("requirement_id", "UNKNOWN")
        lines.append(f"\n**{rid}** \u2014 \"{req.get('title', '')}\" ({str(req.get('severity', 'medium')).upper()}, status {req.get('status', 'unknown')})")
        if req.get("description"):
            lines.append(f"- Requirement: {req['description'].strip()}")
        if req.get("changed_files"):
            lines.append("- Linked files reached: " + ", ".join(f"`{f}`" for f in req["changed_files"]))
        direct = proposal.file_path in req.get("changed_files", [])
        lines.append("- Link: " + ("this file is directly linked." if direct else f"relies on code that imports `{proposal.file_path}` (indirect)."))
    for req in proposal.possibly_affected_requirements:
        lines.append(f"\n**{req.get('id')}** \u2014 \"{req.get('title', '')}\" could not be ruled out.")
    if proposal.diff_evidence:
        lines.append("\n**Evidence:**")
        lines.extend(f"- {e}" for e in proposal.diff_evidence)
    if proposal.recommended_tests:
        lines.append("\n**Recommended verification tests:**")
        lines.extend(f"- `{t}`" for t in proposal.recommended_tests)
    if proposal.inferred_dependent_files:
        lines.append(f"\n**Dependent local files ({len(proposal.inferred_dependent_files)}):** " + ", ".join(f"`{f}`" for f in proposal.inferred_dependent_files))
    if proposal.unknown_impact:
        lines.append("\n**Could not analyze:**")
        lines.extend(f"- {u}" for u in proposal.unknown_impact)
    lines.append(f"\n**Dependency coverage:** {proposal.dependency_coverage}")
    if proposal.uncertainties:
        lines.extend(f"- {u}" for u in proposal.uncertainties)
    lines.append(
        "\n> [!NOTE]\n> This is a potential-risk review, not a finding of a vulnerability. Static analysis is limited: "
        "it cannot see every way code reaches other code, and passing tests do not prove the app is secure."
    )
    lines.append("> If approved, SecureTrace marks the affected requirements' verification evidence as outdated; "
                 "if denied, the file is not modified.")
    return "\n".join(lines)


def format_uncertain_impact_warning(
    file_path: str,
    operation: str,
    possibly_affected: list[dict[str, Any]],
    unknown_impact: list[str],
    diff_assessment: DiffAssessment | None = None,
    proposal_id: str = "",
) -> str:
    """Compact warning for INCOMPLETE_UNKNOWN_IMPACT.

    Deliberately says "could not rule out", never "affects": no requirement has been
    shown to be affected, but SecureTrace also cannot show that none is.
    """
    lines = ["### \u26a0\ufe0f SecureTrace: review required (impact could not be determined)", f"**File:** `{file_path}`"]
    if diff_assessment and diff_assessment.classification:
        lines.append(f"**Change:** {diff_assessment.classification} \u00b7 **Assessed risk:** {diff_assessment.assessed_risk or 'UNCERTAIN'}")
    for req in possibly_affected:
        lines.append(
            f"**Could not rule out:** {req.get('id')} \u2014 \"{req.get('title', 'Security Requirement')}\" "
            f"({str(req.get('severity', 'medium')).upper()} severity)"
        )
    lines.append("**Why:** SecureTrace could not finish checking what depends on this file. This is not a finding that anything is wrong.")
    if diff_assessment and diff_assessment.recommended_tests:
        lines.append("**Verify with:** " + ", ".join(f"`{t}`" for t in diff_assessment.recommended_tests))
    lines.append(_DECISION_NOTE)
    note = "> Not analyzed: " + (unknown_impact[0] if unknown_impact else "see details")
    if len(unknown_impact) > 1:
        note += f" (+{len(unknown_impact) - 1} more)"
    if proposal_id:
        note += f". Details: `securetrace review {proposal_id}`"
    lines.append(note)
    return "\n".join(lines)


def _enrich_requirement(root: Path, req_id: str, item: dict[str, Any] | None = None) -> dict[str, Any]:
    item = item or {}
    detail = get_requirement_detail(root, req_id) or {}
    return {
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

    Decision policy (one place, used by both the hook and the standalone path):

    * CONFIRMED_AFFECTED   - a registered requirement is linked directly or via known
      imports -> ``FORCE_ASK`` with the full warning.
    * INCOMPLETE_UNKNOWN_IMPACT - nothing confirmed, but dependency analysis was
      incomplete in a way that could hide a requirement (see ledger._unknown_impact)
      -> ``FORCE_ASK``; ``possibly_affected_requirements`` names what could not be ruled out.
    * COMPLETE_NO_IMPACT   - analysis was sufficient and nothing is affected -> ``ALLOW``.

    Evaluation errors (unreadable ledger, analysis exception, unparseable request)
    propagate as exceptions; callers must treat them as fail-closed.
    """
    rel_path, target_resolved = resolve_project_relative_path(root, file_path)
    proposal_id = f"PROP-{uuid.uuid4().hex[:12].upper()}"
    now = time.time()
    expires_at = now + timeout_seconds

    raw_bytes, _ = _read_disk_file_bytes(target_resolved)
    encoding = detect_text_encoding(raw_bytes)
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
    proposed_hash = _sha256_bytes(encode_proposed(proposed_content, encoding))
    token = compute_approval_token(root, proposal_id, target_resolved.as_posix(), original_hash, proposed_hash, expires_at)

    def build(**overrides: Any) -> Proposal:
        base: dict[str, Any] = dict(
            proposal_id=proposal_id, file_path=rel_path, canonical_path=target_resolved.as_posix(),
            operation=operation, original_hash=original_hash, proposed_hash=proposed_hash,
            proposed_content=proposed_content, created_at=now, expires_at=expires_at, token=token,
            encoding=encoding,
        )
        base.update(overrides)
        return Proposal(**base)

    if original_hash and original_hash == proposed_hash:
        proposal = build(
            decision="ALLOW", status="APPROVED", warning_text="No substantive changes proposed.",
            analysis_status="NOT_ANALYZED_NO_CHANGE",
        )
        save_proposal(root, proposal)
        return proposal

    impact = analyze_change_impact(root, [rel_path])
    inferred_deps = impact.get("inferred_dependent_files", [])
    coverage = impact.get("dependency_coverage", "LOCAL_STATIC_IMPORTS")
    uncertainties = [u.get("uncertainty", "") for u in impact.get("uncertainties", []) if isinstance(u, dict) and u.get("uncertainty")]
    determination = impact.get("impact_determination")
    if determination is None:  # defensive: an analyzer that does not report completeness is not "complete"
        determination = "CONFIRMED_AFFECTED" if impact.get("requirements") else "INCOMPLETE_UNKNOWN_IMPACT"

    affected_reqs = [_enrich_requirement(root, item.get("requirement_id"), item) for item in impact.get("requirements", [])]
    unknown_items = impact.get("unknown_impact", [])
    possible_ids = sorted({rid for u in unknown_items for rid in u.get("requirement_ids", [])} - {r["id"] for r in affected_reqs})
    possible_reqs = [_enrich_requirement(root, rid) for rid in possible_ids]
    unknown_text = [u.get("detail", "") for u in unknown_items if u.get("detail")]

    diff_assessment = assess_proposed_diff(
        original_content=original_content, proposed_content=proposed_content, file_path=rel_path,
        affected_requirements=affected_reqs or possible_reqs, root=root,
    )
    common = dict(
        inferred_dependent_files=inferred_deps, dependency_coverage=coverage, uncertainties=uncertainties,
        diff_classification=diff_assessment.classification, assessed_risk=diff_assessment.assessed_risk,
        diff_evidence=diff_assessment.evidence, recommended_tests=diff_assessment.recommended_tests,
        possibly_affected_requirements=possible_reqs, unknown_impact=unknown_text,
    )

    if affected_reqs:
        warning = format_plain_language_warning(
            file_path=rel_path, operation=operation, affected_requirements=affected_reqs,
            inferred_dependent_files=inferred_deps, dependency_coverage=coverage,
            uncertainties=uncertainties, diff_assessment=diff_assessment, proposal_id=proposal_id,
        )
        proposal = build(
            decision="FORCE_ASK", status="PENDING", warning_text=warning,
            affected_requirements=affected_reqs, analysis_status="CONFIRMED_AFFECTED", **common,
        )
    elif determination == "INCOMPLETE_UNKNOWN_IMPACT":
        warning = format_uncertain_impact_warning(rel_path, operation, possible_reqs, unknown_text, diff_assessment, proposal_id)
        proposal = build(
            decision="FORCE_ASK", status="PENDING", warning_text=warning,
            affected_requirements=[], analysis_status="INCOMPLETE_UNKNOWN_IMPACT", **common,
        )
    else:
        proposal = build(
            decision="ALLOW", status="APPROVED", warning_text="No registered security requirements affected.",
            affected_requirements=[], analysis_status="COMPLETE_NO_IMPACT", **common,
        )

    save_proposal(root, proposal)
    return proposal


# ---------------------------------------------------------------------------
# Lifecycle helpers: locking, audit recording, diagnostics
# ---------------------------------------------------------------------------

def log_diagnostic(root: Path, component: str, message: str) -> None:
    """Best-effort append to .securetrace/diagnostics.log (never raises, never records file contents)."""
    try:
        d = root / ".securetrace"
        d.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": now_iso(), "component": component, "message": str(message)[:500]})
        with open(d / "diagnostics.log", "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
    except OSError:
        pass


@contextmanager
def _exclusive_lock(root: Path, name: str) -> Iterator[None]:
    """Cross-process advisory lock via O_EXCL lock file (portable: POSIX and Windows).

    Serializes the check-then-replace window for one target between SecureTrace
    processes only. It does NOT stop other programs (editors, shells, the host)
    from writing the file; the compare-and-swap hash check covers those.
    A lock older than LOCK_STALE_SECONDS is treated as left by a crashed process.
    """
    lock_dir = root / ".securetrace" / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{hashlib.sha256(name.encode()).hexdigest()[:24]}.lock"
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, f"{os.getpid()} {time.time()}".encode())
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > LOCK_STALE_SECONDS:
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise ValueError("Another SecureTrace operation holds the lock for this file; try again.")
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass


def _record_lifecycle_event(root: Path, proposal: Proposal, event_type: str, details: str) -> None:
    """Record one event per affected/possibly-affected requirement (or one unattached event).

    Failures are appended to ``proposal.audit_errors`` and the diagnostics log; the
    caller decides how to surface them. Nothing here may change a completed file operation.
    """
    reqs = proposal.affected_requirements or proposal.possibly_affected_requirements
    targets = [r.get("id") for r in reqs] or [None]
    for req_id in targets:
        try:
            record_event(root, req_id, event_type, details)
        except Exception as exc:  # noqa: BLE001 - recorded and surfaced, not hidden
            msg = f"{event_type} not recorded for {req_id or 'no requirement'}: {type(exc).__name__}: {exc}"
            proposal.audit_errors.append(msg)
            log_diagnostic(root, "approval", msg)


def _persist_proposal(root: Path, proposal: Proposal) -> None:
    try:
        save_proposal(root, proposal)
    except OSError as exc:
        msg = f"proposal state for {proposal.proposal_id} not persisted: {type(exc).__name__}: {exc}"
        proposal.audit_errors.append(msg)
        log_diagnostic(root, "approval", msg)


def deny_proposal(root: Path, proposal_id: str) -> Proposal:
    """Record an explicit denial made through SecureTrace (CLI/MCP). Leaves the target untouched.

    This is the only place ``DENIED`` is produced. It is NOT inferred from expiry or from
    a missing write, and it is not a statement about what the host/user did in the IDE.
    Idempotent: denying an already-denied proposal records nothing new.
    """
    proposal = load_proposal(root, proposal_id)
    if not proposal:
        raise ValueError(f"Proposal '{proposal_id}' not found")
    if proposal.status in {"APPLIED", "APPLIED_BY_HOST"}:
        raise ValueError(f"Proposal '{proposal_id}' has already been applied and cannot be denied")
    if proposal.status == "DENIED":
        return proposal
    proposal.status = "DENIED"
    save_proposal(root, proposal)
    _record_lifecycle_event(
        root, proposal, "APPROVAL_DENIED",
        f"Proposal {proposal_id} for {proposal.file_path} was denied by user.",
    )
    if proposal.audit_errors:
        _persist_proposal(root, proposal)
    return proposal


def _reject(root: Path, proposal: Proposal, reason: str) -> ValueError:
    """Record a refused application attempt for a known proposal and return the error to raise."""
    _record_lifecycle_event(root, proposal, "APPROVAL_APPLY_REJECTED", f"Proposal {proposal.proposal_id}: {reason}")
    return ValueError(reason)


def apply_proposal(root: Path, proposal_id: str, token: str) -> Proposal:
    """Apply an approved proposal to disk with atomic swap and CAS validation.

    Enforces, in order, under a per-target lock and against a fresh read of the record:
    HMAC token; proposal content bound to ``proposed_hash``; target identity bound to
    ``canonical_path``; single-use (replay) and status; expiry; compare-and-swap on the
    original hash (re-checked immediately before the replace); atomic temp-file replace
    preserving permissions and the file's original encoding.

    Post-write bookkeeping (state save, freshness, audit events) cannot undo a write that
    already happened, so failures there do not raise; they are returned in
    ``proposal.audit_errors`` and logged to diagnostics.log. Callers must display them.
    """
    proposal = load_proposal(root, proposal_id)
    if not proposal:
        raise ValueError(f"Proposal '{proposal_id}' not found")
    if not verify_approval_token(root, proposal, token):
        raise ValueError("Invalid approval token: signature mismatch or tampered proposal")

    _, target_resolved = resolve_project_relative_path(root, proposal.file_path)
    with _exclusive_lock(root, proposal.canonical_path):
        proposal = load_proposal(root, proposal_id) or proposal   # fresh state inside the lock
        if proposal.status == "APPLIED":
            raise _reject(root, proposal, f"Replay rejected: proposal '{proposal_id}' has already been applied")
        if proposal.status == "APPLIED_BY_HOST":
            raise _reject(root, proposal, f"Proposal '{proposal_id}' was already observed as written by the host")
        if proposal.status == "DENIED":
            raise _reject(root, proposal, f"Cannot apply proposal '{proposal_id}': proposal was denied")
        if time.time() > proposal.expires_at:
            if proposal.status != "EXPIRED":
                proposal.status = "EXPIRED"
                save_proposal(root, proposal)
                _record_lifecycle_event(
                    root, proposal, "APPROVAL_EXPIRED",
                    f"Proposal {proposal_id} for {proposal.file_path} expired before it was applied through SecureTrace. "
                    "Expiry is not a denial.",
                )
            raise ValueError(f"Proposal '{proposal_id}' has expired. Re-review required.")
        if proposal.status not in APPLICABLE_STATUSES:
            raise _reject(root, proposal, f"Proposal '{proposal_id}' has status {proposal.status} and cannot be applied")

        # Proposal integrity: content and target identity must still be what was reviewed.
        try:
            payload = encode_proposed(proposal.proposed_content, proposal.encoding or "utf-8")
        except ValueError as exc:
            raise _reject(root, proposal, str(exc)) from exc
        if _sha256_bytes(payload) != proposal.proposed_hash:
            raise _reject(root, proposal, "Proposal integrity failure: stored content does not match its reviewed hash")
        if target_resolved.as_posix() != proposal.canonical_path:
            raise _reject(
                root, proposal,
                f"Target identity changed since review: '{proposal.file_path}' now resolves elsewhere "
                "(symlink or directory replaced). Re-review required.",
            )

        def current_hash() -> str:
            return _read_disk_file_bytes(target_resolved)[1]

        found = current_hash()
        if found != proposal.original_hash:
            raise _reject(
                root, proposal,
                f"Concurrent modification detected: '{proposal.file_path}' changed on disk since review "
                f"(expected SHA-256 {proposal.original_hash or 'EMPTY'}, found {found or 'EMPTY'}). Overwriting is blocked.",
            )

        target_dir = target_resolved.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        fd, temp_path_str = tempfile.mkstemp(prefix=".sec_tmp_", suffix=".tmp", dir=target_dir)
        temp_path = Path(temp_path_str)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # mkstemp creates 0600; keep the original file's mode (or a normal 0644 for new files).
            try:
                if target_resolved.exists():
                    shutil.copymode(target_resolved, temp_path)
                else:
                    os.chmod(temp_path, 0o644)
            except OSError as exc:
                raise ValueError(f"Could not preserve file permissions; write aborted: {exc}") from exc
            # Narrow the TOCTOU window: re-check path identity and content immediately before the swap.
            _, again = resolve_project_relative_path(root, proposal.file_path)
            if again != target_resolved or current_hash() != proposal.original_hash:
                raise _reject(root, proposal, "Target changed between validation and write; write aborted. Re-review required.")
            os.replace(temp_path, target_resolved)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

        proposal.status = "APPLIED"
        _persist_proposal(root, proposal)

    # The file is written. Everything below is bookkeeping whose failure must be visible, not fatal.
    try:
        mark_changed_files(root, [proposal.file_path])
    except Exception as exc:  # noqa: BLE001
        msg = f"Evidence freshness not updated for {proposal.file_path}: {type(exc).__name__}: {exc}"
        proposal.audit_errors.append(msg)
        log_diagnostic(root, "approval", msg)
    _record_lifecycle_event(
        root, proposal, "APPROVAL_APPLIED",
        f"Proposal {proposal_id} applied to {proposal.file_path} (SHA-256: {proposal.proposed_hash[:10]}).",
    )
    if proposal.audit_errors:
        _persist_proposal(root, proposal)
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
        _record_lifecycle_event(
            root, proposal, "REVIEW_NO_WRITE_OBSERVED",
            f"Review {proposal.proposal_id} for {proposal.file_path} expired and no completed write matching it "
            "was observed. The host does not report the user's decision, so this may be a denial, a cancellation, "
            "or a failed write.",
        )
        closed.append(proposal.proposal_id)
    return closed


def classify_host_write(root: Path, rel_path: str, *, now: float | None = None) -> dict[str, Any]:
    """Relate the file now on disk to reviewed proposals for this path.

    Returns ``{"state": ..., "match": Proposal|None, "candidates": [ids], "disk_hash": str}`` where state is
      * ``MATCHED``    exactly one open proposal's proposed content equals the file on disk;
      * ``AMBIGUOUS``  several open proposals share that proposed content (cannot tell which was reviewed);
      * ``MISMATCH``   open proposals exist for the path but none equals what is on disk
                       (intervening modification, or the host wrote different content than was reviewed);
      * ``UNCHANGED``  the file still equals the original of every open proposal (nothing was written);
      * ``ALREADY_RECORDED`` no open proposal, but this exact content was already recorded as host-applied
                       (a duplicate post-action callback);
      * ``NO_REVIEW``  no open proposal exists for this path.
    "Open" means PENDING, or EXPIRED-without-write (a late approval after the review window still matches).
    The match is by project-relative path AND the SHA-256 of the proposed bytes; the host gives no proposal ID.
    """
    try:
        _, target = resolve_project_relative_path(root, rel_path)
    except ValueError:
        return {"state": "NO_REVIEW", "match": None, "candidates": [], "disk_hash": ""}
    _, disk_hash = _read_disk_file_bytes(target)
    p_dir = root / ".securetrace" / "proposals"
    open_props: list[Proposal] = []
    recorded = False
    if p_dir.is_dir():
        for p_file in sorted(p_dir.glob("PROP-*.json")):
            proposal = load_proposal(root, p_file.stem)
            if proposal is None or proposal.decision != "FORCE_ASK" or proposal.file_path != rel_path:
                continue
            if proposal.status in {"PENDING", "EXPIRED"}:
                open_props.append(proposal)
            elif proposal.status == "APPLIED_BY_HOST" and disk_hash and proposal.proposed_hash == disk_hash:
                recorded = True
    if not open_props and recorded:
        return {"state": "ALREADY_RECORDED", "match": None, "candidates": [], "disk_hash": disk_hash}
    if not open_props:
        return {"state": "NO_REVIEW", "match": None, "candidates": [], "disk_hash": disk_hash}
    matches = [p for p in open_props if disk_hash and p.proposed_hash == disk_hash]
    if len(matches) == 1:
        return {"state": "MATCHED", "match": matches[0], "candidates": [matches[0].proposal_id], "disk_hash": disk_hash}
    if len(matches) > 1:
        return {"state": "AMBIGUOUS", "match": None, "candidates": [p.proposal_id for p in matches], "disk_hash": disk_hash}
    if all(p.original_hash == disk_hash for p in open_props):
        return {"state": "UNCHANGED", "match": None, "candidates": [p.proposal_id for p in open_props], "disk_hash": disk_hash}
    return {"state": "MISMATCH", "match": None, "candidates": [p.proposal_id for p in open_props], "disk_hash": disk_hash}


def find_reviewed_proposal_for_write(root: Path, rel_path: str, *, now: float | None = None) -> Proposal | None:
    """Return the single reviewed proposal whose proposed content is now on disk, else None.

    Ambiguity (several identical open proposals) returns None rather than guessing.
    """
    return classify_host_write(root, rel_path, now=now)["match"]
