"""Antigravity lifecycle hook handlers for SecureTrace pre-action approval.

This module is invoked by Antigravity's PreToolUse and PostToolUse lifecycle
hooks to evaluate proposed file writes before execution, present plain-language
warnings, and mark affected requirements stale after approved changes.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from .approval import (
    evaluate_proposal,
    find_reviewed_proposal_for_write,
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


def _evaluate_tool_call(root: Path, tool_name: str, file_path: str, args: dict[str, Any]):
    """Translate one host tool call into an in-memory proposal evaluation (never writes the target)."""
    if tool_name in EDIT_TOOLS:
        target = _arg(args, "TargetContent", "Target")
        replacement = _arg(args, "ReplacementContent", "Replacement", default="")
        if target is None:
            raise ValueError(f"cannot evaluate {tool_name} without its target text")
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
                _arg(chunk, "TargetContent", "Target"),
                _arg(chunk, "ReplacementContent", "Replacement", default=""),
                bool(_arg(chunk, "AllowMultiple", default=False)),
            ))
        return evaluate_proposal(root=root, file_path=file_path, operation="multi_edit", multi_edits=edits)
    content = _arg(args, "CodeContent", "Content", default="")
    return evaluate_proposal(
        root=root, file_path=file_path, operation="write",
        content=content, append=bool(_arg(args, "Append", default=False)),
    )


def handle_pre_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle PreToolUse event: evaluate proposed tool call before execution.

    Returns:
        A dict with 'decision' ("allow", "force_ask", "deny") and optional 'reason'.
    """
    try:
        tool_call = payload.get("toolCall", {})
        tool_name = tool_call.get("name", "")
        args = tool_call.get("args", {})

        # Only intercept file modification tools
        if tool_name not in FILE_WRITE_TOOLS:
            return {"decision": "allow"}

        ws_root = _extract_workspace_root(payload)
        file_path = _target_path(args) if isinstance(args, dict) else None
        if not file_path:
            # Missing path cannot be evaluated safely: fail closed
            return {
                "decision": "deny",
                "reason": "SecureTrace could not determine target file path for proposed edit. Denying to protect repository.",
            }

        root = _find_project_root_for_file(ws_root, file_path)
        try:
            sweep_unresolved_reviews(root)
        except Exception:
            pass  # housekeeping must never decide the outcome of this review

        try:
            proposal = _evaluate_tool_call(root, tool_name, file_path, args)
        except ValueError as exc:
            if "Path traversal" in str(exc) or "outside project root" in str(exc):
                raise
            return {
                "decision": "deny",
                "reason": f"SecureTrace cannot evaluate this {tool_name} request: {exc}",
            }

        if proposal.decision == "FORCE_ASK":
            for req in proposal.affected_requirements:
                record_event(
                    root, req.get("id"), "SECURITY_REVIEW_REQUESTED",
                    f"Review {proposal.proposal_id} requested for {tool_name} on {proposal.file_path} "
                    f"(registered severity {str(req.get('severity', '')).upper()}). Potential impact only; "
                    "no violation or vulnerability is established by this event.",
                    dedupe_seconds=3.0,
                )
            return {
                "decision": "force_ask",
                "reason": proposal.warning_text,
            }
        return {"decision": "allow"}

    except Exception as exc:
        # Strict fail-closed policy: never silently allow when evaluation fails
        return {
            "decision": "deny",
            "reason": f"SecureTrace pre-action security evaluation failed: {exc}. Denying operation to prevent unreviewed changes.",
        }


def handle_post_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle PostToolUse event: update evidence and freshness after successful writes."""
    try:
        # If tool failed or was aborted by user, do not mark files changed
        if payload.get("error"):
            return {}

        tool_call = payload.get("toolCall", {})
        tool_name = tool_call.get("name", "")
        args = tool_call.get("args", {})

        if tool_name not in FILE_WRITE_TOOLS or not isinstance(args, dict):
            return {}

        file_path = _target_path(args)
        if not file_path:
            return {}

        ws_root = _extract_workspace_root(payload)
        root = _find_project_root_for_file(ws_root, file_path)

        try:
            rel_path, _ = resolve_project_relative_path(root, file_path)
        except ValueError:
            return {}

        # Did the file now on disk match a change we asked the user to review?
        reviewed = find_reviewed_proposal_for_write(root, rel_path)

        # Mark changed files in ledger so affected requirements become STALE
        results = mark_changed_files(root, [rel_path])
        affected_ids = [r["requirement_id"] for r in results]

        if reviewed is not None:
            reviewed.status = "APPLIED_BY_HOST"
            save_proposal(root, reviewed)
            for req in reviewed.affected_requirements:
                record_event(
                    root, req.get("id"), "CHANGE_APPLIED_AFTER_REVIEW",
                    f"The host completed {tool_name} on {rel_path} and the file content matches reviewed proposal "
                    f"{reviewed.proposal_id}. The host does not report the user's decision directly; a completed "
                    "write after a review request implies it was allowed.",
                    dedupe_seconds=3.0,
                )

        detail = f"Antigravity {tool_name} completed for '{rel_path}'."
        if affected_ids:
            detail += f" Evidence for {', '.join(affected_ids)} re-evaluated (STALE where it no longer matches)."
        else:
            detail += " No registered requirement is linked to this file."
        if reviewed is None and affected_ids:
            detail += " No matching security review was recorded for this exact content."
        record_event(root, None, "TOOL_WRITE_COMPLETED", detail, dedupe_seconds=3.0)

    except Exception:
        pass

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
