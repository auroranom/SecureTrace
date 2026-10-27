"""Antigravity lifecycle hook handlers for SecureTrace pre-action approval.

This module is invoked by Antigravity's PreToolUse and PostToolUse lifecycle
hooks to evaluate proposed file writes before execution, present plain-language
warnings, and mark affected requirements stale after approved changes.

Decision policy (see README "Fail-closed policy"):

* tool is not one of FILE_WRITE_TOOLS -> allow (the hook matcher only registers file tools;
  SecureTrace does NOT see shell commands or external-editor writes);
* payload missing/unintelligible for a file tool -> deny;
* evaluation raised (ledger unavailable, analysis error, ...) -> deny;
* assessment says FORCE_ASK (confirmed OR incomplete-analysis) -> force_ask;
* assessment says ALLOW (complete analysis, no impact) -> allow;
* any other decision value -> deny.

The host exposes no approval/denial callback to hooks. Post-action records state only what
was observed: the host reported completion, and what is on disk now.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from .approval import (
    _record_lifecycle_event,
    classify_host_write,
    evaluate_proposal,
    find_reviewed_proposal_for_write,  # noqa: F401 - re-exported for existing callers/tests
    log_diagnostic,
    resolve_project_relative_path,
    save_proposal,
    sweep_unresolved_reviews,
)
from .config import project_root
from .ledger import mark_changed_files, record_event


# Antigravity's native file tools (write_to_file, replace_file_content,
# multi_replace_file_content) use PascalCase arguments. The legacy names below
# were this project's original, unverified assumption and are kept so existing
# callers keep working.
WRITE_TOOLS = frozenset({"write_to_file", "write_file"})
EDIT_TOOLS = frozenset({"replace_file_content", "edit_file"})
MULTI_EDIT_TOOLS = frozenset({"multi_replace_file_content"})
FILE_WRITE_TOOLS = WRITE_TOOLS | EDIT_TOOLS | MULTI_EDIT_TOOLS

_PATH_KEYS = ("TargetFile", "AbsolutePath", "Path", "path", "file_path", "filePath")


def _arg(args: dict[str, Any], *names: str, default: Any = None) -> Any:
    """Return the first present argument, matching names case-insensitively."""
    lowered = {str(k).lower(): v for k, v in args.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return default


def _target_path(args: dict[str, Any]) -> str | None:
    value = _arg(args, *_PATH_KEYS)
    return value if isinstance(value, str) and value.strip() else None


def _extract_workspace_root(payload: dict[str, Any]) -> Path:
    """Determine the workspace root from hook payload or local configuration."""
    ws_paths = payload.get("workspacePaths")
    if ws_paths and isinstance(ws_paths, list) and ws_paths[0]:
        try:
            candidate = Path(ws_paths[0]).resolve()
            if candidate.is_dir():
                return candidate
        except (ValueError, OSError):
            pass
    try:
        return project_root()
    except Exception:
        return Path.cwd().resolve()


def _find_project_root_for_file(workspace_root: Path, file_path_str: str) -> Path:
    """Find the most specific project root containing .securetrace for this file."""
    try:
        resolved_file = Path(file_path_str)
        if not resolved_file.is_absolute():
            resolved_file = (workspace_root / resolved_file).resolve()
        curr = resolved_file.parent
        ws_resolved = workspace_root.resolve()
        while True:
            if (curr / ".securetrace" / "securetrace.db").is_file():
                return curr
            if curr == ws_resolved or curr.parent == curr:
                break
            curr = curr.parent
    except Exception:
        pass
    return workspace_root


def _require_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{what} must be text, got {type(value).__name__}")
    return value


def _evaluate_tool_call(root: Path, tool_name: str, file_path: str, args: dict[str, Any]):
    """Translate one host tool call into an in-memory proposal evaluation (never writes the target)."""
    if tool_name in EDIT_TOOLS:
        target = _arg(args, "TargetContent", "Target")
        if target is None:
            raise ValueError(f"cannot evaluate {tool_name} without its target text")
        target = _require_str(target, "TargetContent")
        replacement = _require_str(_arg(args, "ReplacementContent", "Replacement", default=""), "ReplacementContent")
        # Legacy edit_file replaced every occurrence; Antigravity edits are one match unless AllowMultiple.
        allow_multiple = True if tool_name == "edit_file" else bool(_arg(args, "AllowMultiple", default=False))
        return evaluate_proposal(
            root=root, file_path=file_path, operation="edit",
            target_pattern=target, replacement_pattern=replacement, replace_all=allow_multiple,
        )
    if tool_name in MULTI_EDIT_TOOLS:
        chunks = _arg(args, "ReplacementChunks")
        if not isinstance(chunks, list) or not chunks:
            raise ValueError("cannot evaluate multi_replace_file_content without ReplacementChunks")
        edits: list[tuple[str, str, bool]] = []
        for chunk in chunks:
            if not isinstance(chunk, dict) or _arg(chunk, "TargetContent", "Target") is None:
                raise ValueError("a replacement chunk is missing its target text")
            edits.append((
                _require_str(_arg(chunk, "TargetContent", "Target"), "TargetContent"),
                _require_str(_arg(chunk, "ReplacementContent", "Replacement", default=""), "ReplacementContent"),
                bool(_arg(chunk, "AllowMultiple", default=False)),
            ))
        return evaluate_proposal(root=root, file_path=file_path, operation="multi_edit", multi_edits=edits)
    # Write tools. Content must be present: defaulting to "" would let a payload whose content
    # field we failed to recognise look like a no-op on an empty protected file.
    content = _arg(args, "CodeContent", "Content")
    if content is None:
        raise ValueError(f"cannot evaluate {tool_name} without its content (expected CodeContent)")
    content = _require_str(content, "CodeContent")
    return evaluate_proposal(
        root=root, file_path=file_path, operation="write",
        content=content, append=bool(_arg(args, "Append", default=False)),
    )


def _deny(reason: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason}


def handle_pre_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle PreToolUse event: evaluate proposed tool call before execution.

    Returns:
        A dict with 'decision' ("allow", "force_ask", "deny") and optional 'reason'.
    """
    root: Path | None = None
    try:
        if not isinstance(payload, dict):
            return _deny("SecureTrace received a malformed hook payload (not an object). Denying to prevent an unreviewed change.")
        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            return _deny("SecureTrace received a hook payload without a readable toolCall. Denying to prevent an unreviewed change.")
        tool_name = tool_call.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return _deny("SecureTrace could not determine which tool was called. Denying to prevent an unreviewed change.")
        args = tool_call.get("args", {})

        # Only intercept file modification tools
        if tool_name not in FILE_WRITE_TOOLS:
            return {"decision": "allow"}

        ws_root = _extract_workspace_root(payload)
        file_path = _target_path(args) if isinstance(args, dict) else None
        if not file_path:
            # Missing path cannot be evaluated safely: fail closed
            return _deny("SecureTrace could not determine target file path for proposed edit. Denying to protect repository.")

        root = _find_project_root_for_file(ws_root, file_path)
        try:
            sweep_unresolved_reviews(root)
        except Exception as exc:  # noqa: BLE001 - housekeeping must never decide this review, but must be visible
            log_diagnostic(root, "pre_tool_use", f"review sweep failed: {type(exc).__name__}: {exc}")

        try:
            proposal = _evaluate_tool_call(root, tool_name, file_path, args)
        except ValueError as exc:
            return _deny(f"SecureTrace cannot evaluate this {tool_name} request: {exc}")

        if proposal.decision == "ALLOW":
            return {"decision": "allow"}
        if proposal.decision != "FORCE_ASK":
            return _deny(f"SecureTrace produced an unrecognised decision {proposal.decision!r}. Denying to prevent an unreviewed change.")

        if proposal.analysis_status == "INCOMPLETE_UNKNOWN_IMPACT":
            detail = (
                "Impact could not be determined (incomplete dependency analysis); this requirement could not be ruled out."
            )
        else:
            detail = "Potential impact only; no violation or vulnerability is established by this event."
        _record_lifecycle_event(
            root, proposal, "SECURITY_REVIEW_REQUESTED",
            f"Review {proposal.proposal_id} requested for {tool_name} on {proposal.file_path}. {detail}",
        )
        reason = proposal.warning_text
        if proposal.audit_errors:
            # The review itself still happens; only its audit trail is degraded, and the user is told.
            reason += (
                "\n\n> [!WARNING]\n> SecureTrace could not record this review request in its ledger "
                f"({proposal.audit_errors[0]}). The review is still required; the audit trail is incomplete."
            )
        return {"decision": "force_ask", "reason": reason}

    except Exception as exc:  # noqa: BLE001
        # Strict fail-closed policy: never silently allow when evaluation fails
        if root is not None:
            log_diagnostic(root, "pre_tool_use", f"evaluation failed: {type(exc).__name__}: {exc}")
        return _deny(
            f"SecureTrace pre-action security evaluation failed: {type(exc).__name__}: {exc}. "
            "Denying operation to prevent unreviewed changes. "
            "Run `python -m securetrace.cli doctor` to diagnose."
        )


def _post_diag(root: Path | None, message: str) -> None:
    """Make a post-action problem observable without disrupting the host (which already ran the tool)."""
    if root is not None:
        log_diagnostic(root, "post_tool_use", message)
    try:
        sys.stderr.write(f"SecureTrace post-action warning: {message}\n")
    except OSError:
        pass


def handle_post_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle PostToolUse event: observe what happened and keep evidence honest.

    The tool has already run, so this can never block it and always returns ``{}``. Every
    failure is written to .securetrace/diagnostics.log and stderr instead of being swallowed.

    Association of the write with a reviewed proposal is by project-relative path AND the
    SHA-256 of the proposed bytes versus the file now on disk. The host supplies no proposal
    ID, so several identical open reviews are reported as ambiguous and none is marked applied.
    """
    root: Path | None = None
    try:
        if not isinstance(payload, dict):
            _post_diag(None, "payload was not an object; nothing recorded")
            return {}
        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            _post_diag(None, "payload had no readable toolCall; nothing recorded")
            return {}
        tool_name = tool_call.get("name", "")
        args = tool_call.get("args", {})
        if tool_name not in FILE_WRITE_TOOLS:
            return {}
        if not isinstance(args, dict):
            _post_diag(None, f"{tool_name} args were not an object; nothing recorded")
            return {}
        file_path = _target_path(args)
        if not file_path:
            _post_diag(None, f"{tool_name} completed but no target path was readable; evidence not re-evaluated")
            return {}

        ws_root = _extract_workspace_root(payload)
        root = _find_project_root_for_file(ws_root, file_path)
        try:
            rel_path, _ = resolve_project_relative_path(root, file_path)
        except ValueError as exc:
            _post_diag(root, f"{tool_name} target rejected by path containment: {exc}")
            return {}

        if payload.get("error"):
            # Observed: the host reported failure. Leave any open review alone (it expires as 'no write observed').
            record_event(
                root, None, "TOOL_WRITE_FAILED",
                f"Host reported {tool_name} on {rel_path} failed; no write was recorded. Open reviews for this file, "
                "if any, remain open until they expire.",
                dedupe_seconds=3.0,
            )
            return {}

        outcome = classify_host_write(root, rel_path)
        state = outcome["state"]

        # Re-evaluate evidence for every observed completion; a failure here must be visible.
        affected_ids: list[str] = []
        try:
            affected_ids = [r["requirement_id"] for r in mark_changed_files(root, [rel_path])]
        except Exception as exc:  # noqa: BLE001
            _post_diag(root, f"evidence freshness update failed for {rel_path}: {type(exc).__name__}: {exc}")
            try:
                record_event(root, None, "FRESHNESS_UPDATE_FAILED",
                             f"Evidence freshness could not be updated after {tool_name} on {rel_path}. "
                             "Treat verification evidence for requirements linked to this file as unverified.",
                             dedupe_seconds=3.0)
            except Exception:  # noqa: BLE001 - diagnostics log already holds the failure
                pass

        detail = f"Antigravity {tool_name} completed for '{rel_path}'."
        reviewed = outcome["match"]
        ids = ", ".join(outcome["candidates"])
        if state == "MATCHED" and reviewed is not None:
            late = reviewed.status == "EXPIRED"
            reviewed.status = "APPLIED_BY_HOST"
            save_proposal(root, reviewed)
            _record_lifecycle_event(
                root, reviewed, "CHANGE_APPLIED_AFTER_REVIEW",
                f"The host completed {tool_name} on {rel_path} and the file content matches reviewed proposal "
                f"{reviewed.proposal_id}"
                + (" (observed after its review window had expired)" if late else "")
                + ". The host does not report the user's decision directly; a completed "
                "write after a review request implies it was allowed.",
            )
            if reviewed.audit_errors:
                save_proposal(root, reviewed)
                _post_diag(root, "; ".join(reviewed.audit_errors))
            detail += f" Content matches reviewed proposal {reviewed.proposal_id}."
        elif state == "AMBIGUOUS":
            record_event(
                root, None, "WRITE_REVIEW_AMBIGUOUS",
                f"{rel_path} now matches the proposed content of several open reviews ({ids}); "
                "which one was reviewed cannot be determined, so none was marked applied.",
                dedupe_seconds=3.0,
            )
            detail += f" No matching security review was recorded for this exact content: it matches several open reviews ({ids}), none marked applied."
        elif state == "MISMATCH":
            record_event(
                root, None, "WRITE_DID_NOT_MATCH_REVIEW",
                f"{rel_path} was written but its content matches none of the open reviews ({ids}). "
                "It may have been modified after review or written differently than reviewed; "
                "the reviews were NOT marked applied.",
                dedupe_seconds=3.0,
            )
            detail += f" No matching security review was recorded for this exact content: it differs from open reviews ({ids})."
        elif state == "UNCHANGED":
            record_event(
                root, None, "TOOL_COMPLETED_NO_FILE_CHANGE",
                f"Host reported {tool_name} completed on {rel_path} but the file is unchanged from the reviewed original; "
                f"no write matching reviews ({ids}) was observed.",
                dedupe_seconds=3.0,
            )
            return {}
        elif state == "ALREADY_RECORDED":
            detail += " Duplicate callback: this content was already recorded against a reviewed proposal."
        else:  # NO_REVIEW
            if affected_ids:
                detail += " No matching security review was recorded for this exact content."

        if affected_ids:
            detail += f" Evidence for {', '.join(affected_ids)} re-evaluated (STALE where it no longer matches)."
        elif state == "NO_REVIEW":
            detail += " No registered requirement is linked to this file."
        record_event(root, None, "TOOL_WRITE_COMPLETED", detail, dedupe_seconds=3.0)

    except Exception as exc:  # noqa: BLE001
        _post_diag(root, f"post-action handling failed: {type(exc).__name__}: {exc}")

    return {}


def main() -> None:
    """CLI entry point reading hook JSON from stdin and writing decision to stdout."""
    action = sys.argv[1] if len(sys.argv) > 1 else "pre_tool_use"
    try:
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input) if raw_input.strip() else {}
    except Exception as exc:
        # Fail closed on input parse failure
        if action == "pre_tool_use":
            output = {
                "decision": "deny",
                "reason": f"SecureTrace failed to parse hook payload: {exc}. Denying to prevent unverified write.",
            }
        else:
            output = {}
        sys.stdout.write(json.dumps(output))
        sys.stdout.flush()
        return

    if action == "pre_tool_use":
        result = handle_pre_tool_use(payload)
    elif action == "post_tool_use":
        result = handle_post_tool_use(payload)
    else:
        result = {"decision": "allow"}

    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
