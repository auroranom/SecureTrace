from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from .config import project_root
from .db import connect
from .ledger import (add_requirement, list_requirements, record_check, mark_changed_files,
                     map_requirement_test, analyze_change_impact, current_verification_plan)
from .monitor import watch
from .reporting import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securetrace", description="Continuous security assurance ledger")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize the local SecureTrace database")
    sub.add_parser("doctor", help="Read-only diagnostics for installation, ledger and hook configuration")
    sub.add_parser("migrate", help="Explicitly add the requirement-to-test mapping tables")

    mapping = sub.add_parser("map-test", help="Map one approved pytest function to a requirement")
    mapping.add_argument("--requirement", required=True)
    mapping.add_argument("--test-file", required=True)
    mapping.add_argument("--test-id", required=True)
    mapping.add_argument("--complete", action="store_true", help="This test fully verifies the requirement")

    impact = sub.add_parser("impact", help="Analyze linked file changes and propose eligible test reruns")
    impact.add_argument("files", nargs="+")
    sub.add_parser("plan", help="Show the deterministic verification plan without executing tests")

    orchestration = sub.add_parser(
        "orchestrate", help="Plan mapped checks; execute only with explicit --approve",
    )
    orchestration.add_argument("--approve", action="store_true",
                               help="Explicitly authorize execution of selected mapped checks")
    orchestration.add_argument("--changed-file", action="append", default=[], dest="changed_files",
                               help="Limit the plan to linked changes; repeatable")
    orchestration.add_argument("--requirement", action="append", default=[], dest="requirements",
                               help="Limit checks to this requirement; repeatable")
    orchestration.add_argument("--rerun-current", action="store_true",
                               help="Explicitly select checks whose evidence is currently fresh")
    orchestration.add_argument("--allow-duplicates", action="store_true",
                               help="Permit duplicate mapped checks in this run")
    orchestration.add_argument("--timeout", type=float, default=60)

    semgrep = sub.add_parser("semgrep", help="Plan or explicitly approve a local Semgrep scan")
    semgrep.add_argument("--config", required=True,
                         help="Project-relative YAML ruleset file; remote rulesets are not accepted")
    semgrep.add_argument("--approve", action="store_true",
                         help="Explicitly authorize Semgrep execution against this local project root")
    semgrep.add_argument("--timeout", type=float, default=120,
                         help="Scanner timeout in seconds (maximum 600; default 120)")

    add = sub.add_parser("add-requirement", help="Add a security requirement")
    add.add_argument("--title", required=True)
    add.add_argument("--description", required=True)
    add.add_argument("--category", default="other")
    add.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="medium")
    add.add_argument("--file", action="append", default=[], dest="files", help="Relevant repository-relative file; repeatable")

    sub.add_parser("list", help="List registered security requirements")

    check = sub.add_parser("record-check", help="Record a verification result")
    check.add_argument("--requirement", required=True)
    check.add_argument("--name", required=True)
    check.add_argument("--passed", action="store_true")
    check.add_argument("--complete", action="store_true", help="Mark this as a complete verification for the requirement")
    check.add_argument("--details", default="")
    check.add_argument("--commit", default=None)

    run_test = sub.add_parser(
        "run-test", help="Execute one explicitly approved pytest function and record its evidence",
    )
    run_test.add_argument("--approve", action="store_true", required=True,
                          help="Confirm that this local test code is approved to execute")
    run_test.add_argument("--requirement", required=True,
                          help="Requirement this specific test is intended to verify")
    run_test.add_argument("--test-file", required=True,
                          help="Project-relative Python file under tests/ or examples/<sample>/tests/")
    run_test.add_argument("--test-id", required=True, help="One pytest function name, such as test_owner_only")
    run_test.add_argument("--timeout", type=float, default=60,
                          help="Execution timeout in seconds (maximum 600; default 60)")
    run_test.add_argument("--complete", action="store_true",
                          help="This approved test fully verifies the mapped requirement")

    changed = sub.add_parser("mark-changed", help="Mark requirements linked to files as needing re-verification")
    changed.add_argument("files", nargs="+")

    report = sub.add_parser("report", help="Generate the Markdown security report")
    report.add_argument("--output", default=None)

    sub.add_parser("watch", help="Watch the repository and mark linked requirements stale")
    dashboard = sub.add_parser("dashboard", help="Serve the local SecureTrace dashboard")
    dashboard.add_argument("--port", type=int, default=8765)

    review = sub.add_parser("review", help="Review a pre-action security approval proposal")
    review.add_argument("proposal_id", help="Proposal ID (e.g. PROP-...)")

    approve_cmd = sub.add_parser("approve", help="Approve and apply a proposed modification")
    approve_cmd.add_argument("proposal_id", help="Proposal ID (e.g. PROP-...)")
    approve_cmd.add_argument("--token", default=None, help="Approval token (optional if proposal is loaded from disk)")

    abort_cmd = sub.add_parser("abort", help="Deny and discard a proposed modification without changing files")
    abort_cmd.add_argument("proposal_id", help="Proposal ID (e.g. PROP-...)")

    install = sub.add_parser("install-hooks", help="Write the Antigravity hook config (.agents/hooks.json) for this project")
    install.add_argument("--dir", default=None, help="Project directory (default: the SecureTrace project root)")
    install.add_argument("--python", default=None, help="Interpreter the hook should use (default: the one running this command)")

    sub.add_parser("pre-tool-use", help="Antigravity PreToolUse hook entry point")
    sub.add_parser("post-tool-use", help="Antigravity PostToolUse hook entry point")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    root = project_root()

    if args.command == "doctor":
        from .doctor import main as doctor_main
        raise SystemExit(doctor_main(root))

    if args.command == "init":
        db_file = root / ".securetrace" / "securetrace.db"
        existed = db_file.exists()
        with connect(root):
            pass
        print(f"{'Opened existing' if existed else 'Initialized'} SecureTrace ledger at {db_file}"
              + (" (existing history preserved)" if existed else ""))
    elif args.command == "migrate":
        from .db import migrate_mappings
        migrate_mappings(root)
        print("Applied additive requirement-to-test mapping migration.")
    elif args.command == "map-test":
        try:
            item = map_requirement_test(root, args.requirement, args.test_file, args.test_id,
                                        verification_complete=args.complete)
        except (OSError, ValueError, sqlite3.Error) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(f"Mapped {item['requirement_id']} -> {item['test_file']}::{item['test_id']}")
    elif args.command == "impact":
        from .ledger import analyze_change_impact
        result = analyze_change_impact(root, args.files)
        print(f"Affected requirements: {len(result['requirements'])}")
        for item in result["requirements"]:
            print(f"{item['requirement_id']} (changed: {', '.join(item['changed_files'])})")
            if item["uncertainty"]:
                print(f"  Uncertainty: {item['uncertainty']}")
        print("Eligible reruns:")
        for item in result["eligible_reruns"]:
            print(f"  {item['requirement_id']}: {item['test_file']}::{item['test_id']} "
                  f"[freshness={item['evidence_freshness']}] {item['reason']}")
            print(f"    Dependency coverage: {item['dependency_coverage']}")
            for blocker in item["blockers"]:
                print(f"    Blocker: {blocker}")
        if not result["eligible_reruns"]:
            print("  None")
    elif args.command == "plan":
        plan = current_verification_plan(root)
        print(f"Verification plan: {len(plan)} mapped check(s); no tests executed.")
        for item in plan:
            state = "PROPOSED" if item["selected"] else "CURRENT"
            print(f"{state} {item['requirement_id']}: {item['test_file']}::{item['test_id']} "
                  f"[freshness={item['evidence_freshness']}] {item['reason']}")
            print(f"  Dependency coverage: {item['dependency_coverage']}")
            for note in item.get("coverage_notes", []):
                print(f"  Coverage limitation: {note}")
            for blocker in item["blockers"]:
                print(f"  Blocker: {blocker}")
    elif args.command == "orchestrate":
        from .orchestration import orchestrate_verification
        try:
            result = orchestrate_verification(
                root, approve=args.approve, changed_files=args.changed_files,
                requirement_ids=args.requirements, rerun_current=args.rerun_current,
                allow_duplicates=args.allow_duplicates, timeout_seconds=args.timeout,
            )
        except (OSError, ValueError, sqlite3.Error) as exc:
            print(f"Orchestration error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(f"Orchestration {result['orchestration_id']} ({result['mode']})")
        print(f"Selected checks: {len(result['selected_checks'])}; executed checks: "
              f"{sum(item.get('outcome') is not None for item in result['results'])}")
        for item in result["results"]:
            print(f"{item['status']}: {item['requirement_id']} "
                  f"{item['test_file']}::{item['test_id']}"
                  + (f" outcome={item['outcome']}" if item.get("outcome") else ""))
            print(f"  Reason: {item.get('reason', '')}")
            print(f"  Freshness: {item.get('evidence_freshness', 'UNKNOWN')}")
            print(f"  Dependency coverage: {item.get('dependency_coverage', 'INCOMPLETE')}")
            for note in item.get("coverage_notes", []):
                print(f"  Coverage limitation: {note}")
            for blocker in item.get("blockers", []):
                print(f"  Blocker: {blocker}")
        print(f"Summary: {json.dumps(result['counts'], sort_keys=True)}")
        for error in result["persistence_errors"]:
            print(error, file=sys.stderr)
        if result["persistence_errors"] or any(item["status"] in {"TIMEOUT", "ERROR", "BLOCKED", "STALE", "UNKNOWN"}
                                                for item in result["results"]):
            raise SystemExit(2)
        if any(item["status"] == "FAILED" for item in result["results"]):
            raise SystemExit(1)
    elif args.command == "semgrep":
        from .semgrep import run_semgrep_scan
        try:
            result = run_semgrep_scan(root, args.config, timeout_seconds=args.timeout, approve=args.approve)
        except (OSError, ValueError, sqlite3.Error) as exc:
            print(f"Semgrep error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if result["status"] == "PLANNED":
            print("Semgrep plan only; no scanner was executed and no evidence was recorded.")
            print(f"Target: {root} (local project root)")
            print(f"Ruleset: {result['ruleset']} (SHA-256: {result['ruleset_sha256']})")
            print("Execute with --approve after reviewing the target and ruleset.")
        else:
            print(f"Semgrep {result['status']}: version={result.get('scanner_version') or 'unavailable'} "
                  f"exit={result.get('exit_code')} duration={result.get('duration_seconds', 0)}s")
            print(f"Ruleset: {result['ruleset']} (SHA-256: {result['ruleset_sha256']})")
            print(f"Findings: {result.get('finding_count', 0)}; unmapped: {result.get('unmapped_count', 0)}")
            for finding in result.get("findings", []):
                references = ", ".join(finding["requirement_ids"]) if finding["requirement_ids"] else "unmapped"
                print(f"  {finding['severity']} {finding['path']}:{finding['start_line']} "
                      f"{finding['check_id']} (requirements: {references}) — {finding['message']}")
            if result.get("error"):
                print(f"Scanner note: {result['error']}")
            print("Scanner evidence is not a pytest result and cannot mark a requirement VERIFIED.")
            if result["status"] in {"ERROR", "TIMEOUT", "INCOMPLETE"}:
                raise SystemExit(2)
            if result["status"] == "FINDINGS":
                raise SystemExit(1)
    elif args.command == "add-requirement":
        with connect(root):
            pass
        item = add_requirement(root, args.title, args.description, args.category, args.severity, args.files)
        print(f"Created {item['id']}: {item['title']}")
    elif args.command == "list":
        items = list_requirements(root)
        if not items:
            print("No requirements yet. Use `securetrace add-requirement`.")
        for item in items:
            print(f"{item['id']} [{item['status']}] ({item['severity']}) {item['title']}")
            if item["file_paths"]:
                print(f"  Files: {', '.join(item['file_paths'])}")
    elif args.command == "record-check":
        try:
            result = record_check(
                root,
                args.requirement,
                args.name,
                args.passed,
                args.details,
                args.commit,
                args.complete,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(f"{result['requirement_id']}: {result['result']} -> {result['status']}")
    elif args.command == "run-test":
        from .test_runner import EvidencePersistenceError, run_approved_test

        try:
            result = run_approved_test(
                root, args.requirement, args.test_file, args.test_id,
                timeout_seconds=args.timeout,
                verification_complete=args.complete,
            )
        except EvidencePersistenceError as exc:
            print(f"Evidence persistence error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        except (OSError, ValueError, sqlite3.Error) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(
            f"{result['requirement_id']}: {result['outcome']} -> {result['status']} "
            f"(exit={result['execution']['exit_code']}, "
            f"duration={result['execution']['duration_seconds']}s)"
        )
        if result["execution"]["evidence_ref"]:
            print(f"Evidence: {result['execution']['evidence_ref']}")
        if result["persistence_error"]:
            print(f"Evidence persistence error: {result['persistence_error']}", file=sys.stderr)
        if result["output"]:
            print(result["output"], end="" if result["output"].endswith("\n") else "\n")
        if result["outcome"] == "FAILED":
            raise SystemExit(1)
        if result["outcome"] in {"TIMEOUT", "ERROR"}:
            raise SystemExit(2)
    elif args.command == "mark-changed":
        affected = mark_changed_files(root, args.files)
        print(f"Matched {len(affected)} requirement(s).")
        for item in affected:
            print(f"{item['requirement_id']}: {', '.join(item['changed_files'])}")
            for test in item["eligible_reruns"]:
                print(f"  Eligible rerun: {test['test_file']}::{test['test_id']}")
            if item["uncertainty"]:
                print(f"  Uncertainty: {item['uncertainty']}")
    elif args.command == "report":
        output = Path(args.output).resolve() if args.output else None
        destination = write_report(root, output)
        print(f"Wrote report: {destination}")
    elif args.command == "watch":
        with connect(root):
            pass
        watch(root)
    elif args.command == "dashboard":
        from .dashboard import serve

        try:
            serve(root, args.port)
        except OSError as exc:
            print(f"Error starting dashboard: {exc}", file=sys.stderr)
            raise SystemExit(2)
    elif args.command == "review":
        from .approval import format_warning_details, load_proposal
        proposal = load_proposal(root, args.proposal_id)
        if not proposal:
            print(f"Error: Proposal '{args.proposal_id}' not found.", file=sys.stderr)
            raise SystemExit(1)
        print(f"Proposal: {proposal.proposal_id}")
        print(f"Target:   {proposal.file_path}")
        print(f"Status:   {proposal.status}")
        print(f"Decision: {proposal.decision}")
        print("---")
        print(proposal.warning_text)
        print("---")
        print(format_warning_details(proposal))
    elif args.command == "approve":
        from .approval import apply_proposal, load_proposal
        proposal = load_proposal(root, args.proposal_id)
        if not proposal:
            print(f"Error: Proposal '{args.proposal_id}' not found.", file=sys.stderr)
            raise SystemExit(1)
        token = args.token or proposal.token
        try:
            applied = apply_proposal(root, args.proposal_id, token)
            print(f"Approved and applied proposal {applied.proposal_id} to {applied.file_path}")
            for problem in applied.audit_errors:
                print(f"WARNING (file was written, bookkeeping incomplete): {problem}", file=sys.stderr)
            if applied.audit_errors:
                raise SystemExit(3)
        except ValueError as exc:
            print(f"Approval error: {exc}", file=sys.stderr)
            raise SystemExit(2)
    elif args.command == "abort":
        from .approval import deny_proposal
        try:
            denied = deny_proposal(root, args.proposal_id)
            print(f"Aborted proposal {denied.proposal_id}. '{denied.file_path}' was not modified.")
        except ValueError as exc:
            print(f"Abort error: {exc}", file=sys.stderr)
            raise SystemExit(2)
    elif args.command == "install-hooks":
        from .hook_install import install_hooks
        try:
            written = install_hooks(Path(args.dir) if args.dir else project_root(), args.python)
        except ValueError as exc:
            print(f"install-hooks error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        print(f"Wrote {written}. Restart the Antigravity session so it reloads hooks.json.")
    elif args.command == "pre-tool-use":
        from .hooks import main as hooks_main
        sys.argv = [sys.argv[0], "pre_tool_use"]
        hooks_main()
    elif args.command == "post-tool-use":
        from .hooks import main as hooks_main
        sys.argv = [sys.argv[0], "post_tool_use"]
        hooks_main()


if __name__ == "__main__":
    main()
