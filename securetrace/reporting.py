from __future__ import annotations

from pathlib import Path
from collections.abc import Mapping
import json
from .db import connect
from .ledger import list_requirements, get_requirement_detail, list_requirement_tests
from .freshness import assess_mapping_freshness


def _automated_metadata(check: dict) -> dict | None:
    try:
        metadata = json.loads(check.get("details", ""))
    except (TypeError, json.JSONDecodeError):
        return None
    if isinstance(metadata, dict) and metadata.get("securetrace_test") == 1 and metadata.get("origin") == "automated":
        return metadata
    return None


def _recorded_details(check: dict) -> str:
    try:
        metadata = json.loads(check.get("details", ""))
    except (TypeError, json.JSONDecodeError):
        return check.get("details", "")
    if isinstance(metadata, dict) and metadata.get("securetrace_provenance") == 1:
        return str(metadata.get("details", ""))
    return check.get("details", "")


def render_report(
    root: Path,
    *,
    requirements: list[dict] | None = None,
    details_by_id: Mapping[str, dict] | None = None,
    mappings_by_id: Mapping[str, list[dict]] | None = None,
    scanner_events: list[dict] | None = None,
) -> str:
    """Render the security report from the ledger or a supplied read-only snapshot.

    Supplying requirements, details, mappings, and scanner events avoids opening
    or initializing the database, which lets read-only consumers use the same
    canonical report renderer. Scanner events may be omitted from a read-only
    snapshot, in which case that snapshot renders without scanner history.
    """
    snapshot_supplied = requirements is not None and details_by_id is not None and mappings_by_id is not None
    requirements = list_requirements(root) if requirements is None else requirements
    if scanner_events is None and snapshot_supplied:
        scanner_events = []
    if scanner_events is None:
        with connect(root) as db:
            scanner_events = [dict(row) for row in db.execute(
                "SELECT event_type,details,created_at FROM events WHERE event_type='SEMGREP_SCAN' "
                "ORDER BY created_at DESC,id DESC LIMIT 20"
            )]
    lines = [
        "# SecureTrace Security Report",
        "",
        f"- **Repository:** `{root.resolve()}`",
        "- **Scope:** Requirements and verification evidence registered in SecureTrace.",
        "- **Important:** This report is not proof that the entire application is secure.",
        "",
        "## Summary",
        "",
        f"- Requirements tracked: **{len(requirements)}**",
    ]

    counts: dict[str, int] = {}
    for item in requirements:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    for status in sorted(counts):
        lines.append(f"- {status}: **{counts[status]}**")

    lines.extend(["", "## Requirements", ""])
    verification_plan: list[dict] = []
    if not requirements:
        lines.append("No security requirements have been registered yet.")
    for item in requirements:
        lines.extend([
            f"### {item['id']} — {item['title']}",
            "",
            f"- **Status:** {item['status']}",
            f"- **Severity:** {item['severity']}",
            f"- **Category:** {item['category']}",
            f"- **Description:** {item['description']}",
            f"- **Linked files:** {', '.join(f'`{p}`' for p in item['file_paths']) or 'None'}",
        ])
        mappings = (mappings_by_id.get(item["id"], []) if mappings_by_id is not None
                    else list_requirement_tests(root, item["id"]))
        lines.append("- **Approved tests:**")
        if mappings:
            for mapping in mappings:
                lines.append(f"  - `{mapping['test_file']}::{mapping['test_id']}` "
                             f"(complete verification: {'yes' if mapping['verification_complete'] else 'no'})")
        else:
            lines.append("  - None mapped; rerun eligibility is unknown.")
        if details_by_id is not None:
            detail = details_by_id.get(item["id"], {})
        else:
            detail = get_requirement_detail(root, item["id"]) or {}
        checks = detail.get("checks", [])
        requirement_plan = [assess_mapping_freshness(root, item, mapping, checks) for mapping in mappings]
        verification_plan.extend(requirement_plan)
        if requirement_plan:
            states = ", ".join(
                f"`{entry['test_file']}::{entry['test_id']}`: **{entry['evidence_freshness']}**"
                for entry in requirement_plan
            )
            lines.append(f"- **Evidence freshness:** {states}")
        elif item["file_paths"] and not mappings:
            lines.append("- **Evidence freshness:** **UNKNOWN** (no mapped test fingerprint is available).")
        lines.append("- **Latest check:**")
        if checks:
            latest = checks[0]
            metadata = _automated_metadata(latest)
            source = "automatically executed test" if metadata else "manually recorded check"
            lines.append(
                f"  - `{latest['check_name']}`: **{latest['result']}** "
                f"(complete verification: {'yes' if latest['verification_complete'] else 'no'}; "
                f"source: {source})"
            )
            if metadata:
                lines.append(f"  - Test identifier: `{metadata.get('test_identifier', latest['check_name'])}`")
                lines.append(f"  - Test outcome: **{metadata.get('outcome', latest['result'])}**")
                lines.append(f"  - Exit code: `{metadata.get('exit_code')}`")
                lines.append(f"  - Duration: `{metadata.get('duration_seconds')}s`")
                if metadata.get("evidence_ref"):
                    lines.append(f"  - Evidence: `{metadata['evidence_ref']}`")
            elif _recorded_details(latest):
                lines.append(f"  - Details: {_recorded_details(latest)}")
            if latest["commit_hash"]:
                lines.append(f"  - Revision: `{latest['commit_hash']}`")
        else:
            lines.append("  - No checks recorded.")
        if item["status"] == "STALE":
            lines.append("  - **Evidence freshness:** stale after a linked file change; historical runs are retained.")
        change_events = [event for event in detail.get("events", []) if event.get("event_type") == "LINKED_FILE_CHANGED"]
        if change_events:
            latest_change = change_events[0]
            lines.append("- **Change impact:**")
            lines.append(f"  - Latest linked change: {latest_change.get('details', '')}")
            selected_plan = [entry for entry in requirement_plan if entry["selected"]]
            if selected_plan:
                lines.append("  - Proposed reruns (not executed automatically): " + ", ".join(
                    f"`{entry['test_file']}::{entry['test_id']}` ({entry['evidence_freshness']})"
                    for entry in selected_plan
                ))
            elif not mappings:
                lines.append("  - Rerun eligibility is uncertain because no approved test is mapped.")
            else:
                lines.append("  - Content fingerprints match current mapped evidence; no rerun is proposed.")
        orchestration_events = [event for event in detail.get("events", [])
                                if event.get("event_type") in {"ORCHESTRATION_PLAN", "ORCHESTRATION_RUN"}]
        if orchestration_events:
            latest_orchestration = orchestration_events[0]
            try:
                orchestration_data = json.loads(latest_orchestration.get("details", ""))
            except (TypeError, json.JSONDecodeError):
                orchestration_data = {}
            lines.append("- **Latest orchestration:**")
            lines.append(f"  - Mode: {orchestration_data.get('mode', latest_orchestration['event_type'])}")
            lines.append(f"  - ID: `{orchestration_data.get('orchestration_id', 'unknown')}`")
            for result in orchestration_data.get("results", []):
                target = f"{result.get('test_file', '?')}::{result.get('test_id', '?')}"
                outcome = f"; outcome {result['outcome']}" if result.get("outcome") else ""
                lines.append(f"  - {result.get('status', 'UNKNOWN')}: `{target}`{outcome}")
                for blocker in result.get("blockers", []):
                    lines.append(f"    - Blocker: {blocker}")
        if len(checks) > 1:
            lines.append("- **Earlier recorded checks (history retained):**")
            for previous in checks[1:]:
                origin = "automated test" if _automated_metadata(previous) else "manual check"
                lines.append(f"  - `{previous['check_name']}`: **{previous['result']}** ({origin}, {previous['ran_at']})")
        lines.append("")

    lines.extend(["## Semgrep Scanner Evidence", "",
                  "Scanner findings are separate from test outcomes. A clean scan does not verify a requirement.", ""])
    if not scanner_events:
        lines.append("No Semgrep scans have been recorded.")
    for event in scanner_events:
        try:
            scan = json.loads(event.get("details", ""))
        except (TypeError, json.JSONDecodeError):
            scan = {}
        lines.append(f"- **{scan.get('status', 'UNKNOWN')}** ({scan.get('ended_at', event.get('created_at', 'unknown'))})")
        lines.append(f"  - Version: `{scan.get('scanner_version') or 'unavailable'}`")
        lines.append(f"  - Ruleset: `{scan.get('ruleset', 'unknown')}` (SHA-256: `{scan.get('ruleset_sha256', 'unknown')}`)")
        lines.append(f"  - Exit status: `{scan.get('exit_code')}`; duration: `{scan.get('duration_seconds', 'unknown')}s`")
        lines.append(f"  - Findings: {scan.get('finding_count', len(scan.get('findings', [])))}; unmapped: {scan.get('unmapped_count', 0)}")
        if scan.get("error"):
            lines.append(f"  - Scanner note: {scan['error']}")
        for finding in scan.get("findings", []):
            refs = finding.get("requirement_ids") or []
            mapped = ", ".join(f"`{item}`" for item in refs) if refs else "unmapped"
            location = f"{finding.get('path', '?')}:{finding.get('start_line') or '?'}"
            lines.append(f"  - {finding.get('severity', 'UNKNOWN')}: `{location}` `{finding.get('check_id', 'unknown')}` — {finding.get('message', '')} (requirements: {mapped})")
    lines.append("")

    lines.extend(["## Verification Plan", "", "Planning does not execute tests.", ""])
    if not verification_plan:
        lines.append("No mapped checks are available to plan.")
    for planned in verification_plan:
        state = "PROPOSED" if planned["selected"] else "CURRENT"
        lines.append(f"- **{state}** `{planned['requirement_id']}` — "
                     f"`{planned['test_file']}::{planned['test_id']}`")
        lines.append(f"  - Reason: {planned['reason']}")
        lines.append(f"  - Evidence freshness: **{planned['evidence_freshness']}**")
        lines.append(f"  - Dependency coverage: **{planned['dependency_coverage']}**")
        for note in planned.get("coverage_notes", []):
            lines.append(f"  - Coverage limitation: {note}")
        lines.append(f"  - Blockers: {'; '.join(planned['blockers']) if planned['blockers'] else 'None'}")
        if planned.get("current_fingerprint"):
            lines.append(f"  - Current source fingerprint: `{planned['current_fingerprint']}`")
    lines.append("")

    lines.extend([
        "## Interpretation",
        "",
        "- `VERIFIED` means a check explicitly marked as complete verification passed.",
        "- `REGRESSION` means a recorded check failed.",
        "- `STALE` means linked code changed after prior evidence and the requirement needs re-verification.",
        "- These statuses are evidence summaries, not guarantees of application-wide security.",
        "",
    ])
    return "\n".join(lines)


def write_report(root: Path, output_path: Path | None = None) -> Path:
    destination = output_path or (root / ".securetrace" / "SECURITY_REPORT.md")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report(root), encoding="utf-8")
    return destination
