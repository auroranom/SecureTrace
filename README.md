# SecureTrace

**Continuous Security Assurance for AI-Built Applications**

SecureTrace is a local-first prototype that maintains a persistent, feature-aware security ledger. It records security requirements, links them to relevant source files, stores verification evidence, marks evidence stale when linked files change, and generates a living Markdown report. An MCP server exposes the ledger to Gemini CLI.

> Prototype boundary: SecureTrace does not prove an entire application is secure. A `VERIFIED` status means the explicitly recorded verification completed successfully for the recorded revision. It is not a general security guarantee.

## Initial scope

- Local SQLite ledger
- Security requirements linked to files
- Verification result history
- Change-triggered stale evidence for linked files
- Markdown report
- MCP tools for Gemini CLI
- Local file watcher
- Tests for the ledger's core behavior

## Requirements

- Python 3.11+
- `uv` recommended for environment/dependency management
- Gemini CLI for agent integration (optional for standalone CLI use)

## Installation from a fresh clone

A fresh clone contains no ledger (`.securetrace/` is gitignored) and its checked-in `.agents/hooks.json` / `securetrace_hook.cmd` files may reference the original developer's interpreter path. Always regenerate them for your machine:

```bash
git clone <repo> && cd <repo>
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                                # or: uv sync --extra dev
securetrace init                                       # creates .securetrace/securetrace.db; never overwrites an existing one
securetrace install-hooks                              # writes .agents/hooks.json for THIS interpreter
securetrace doctor                                     # read-only check of Python, dependencies, ledger, hook config
```

`securetrace doctor` actually opens the ledger and runs the configured hook interpreter (`import securetrace`) from the project directory, so it catches the common failure: a hook command pointing at an interpreter that does not exist or lacks the package. It cannot verify that Antigravity discovers or runs the hook; that needs a live session.

**Windows.** `winotify` (desktop toasts) is installed only on Windows and imported lazily, so every other module works on Linux/macOS. If the interpreter path contains spaces, `install-hooks` writes `.agents\securetrace_hook.cmd` and points the hook at it (working around cmd.exe quoting). The wrapper is ASCII-only: an interpreter path that has both spaces and non-ASCII characters is refused with an explanation rather than written incorrectly. Place the virtual environment at a plain ASCII path in that case. The wrapper output is verified by string-level tests on every platform but has not been executed under cmd.exe by the automated suite.

**Hooks that cannot start.** If the hook process fails to launch (missing interpreter, missing package), whether Antigravity then blocks or permits the edit is decided by the host, not SecureTrace. Treat a failing `securetrace doctor` as a real gap in protection.

## Quick start

From this directory:

```bash
uv sync --extra dev
uv run securetrace init
uv run securetrace add-requirement \
  --title "Customers can cancel only their own appointments" \
  --description "The server must verify that the authenticated user owns the appointment." \
  --category authorization \
  --severity high \
  --file src/routes/appointments.py
uv run securetrace list
uv run securetrace report
uv run pytest
```

The database is created at `.securetrace/securetrace.db` under the project root. By default the root is the current working directory. You can override it with `SECURETRACE_PROJECT_ROOT`.

## Record a verification result

```bash
uv run securetrace record-check \
  --requirement SEC-XXXXXXXX \
  --name "appointment-owner-authorization" \
  --passed \
  --complete
```

Use `--complete` only when the check represents the full verification required for that requirement. Without it, a passing check is recorded as evidence but does not mark the requirement `VERIFIED`.

## Execute one approved local test

`run-test` executes exactly one named pytest function from `tests/` or
`examples/<sample>/tests/`. The command is fixed to the current Python
interpreter running pytest; it does not accept arbitrary shell commands, Python
snippets, or pytest arguments. The requirement ID and test function supplied on
each invocation form the explicit test-to-requirement mapping. `--complete`
must be supplied separately when that test fully verifies the requirement.

Run the included authorization demo in its own project root (PowerShell):

```powershell
Set-Location examples/authorization_demo
$env:SECURETRACE_PROJECT_ROOT = (Get-Location).Path
$env:PYTHONPATH = (Resolve-Path ../..).Path
$python = Resolve-Path ..\..\.venv\Scripts\python.exe
& $python -m securetrace.cli init
$created = & $python -m securetrace.cli add-requirement `
  --title "Only appointment owners can cancel" `
  --description "A different user must not cancel an appointment." `
  --category authorization --severity high --file app.py
$requirementId = [regex]::Match(($created -join "`n"), 'Created (SEC-[A-F0-9]+)').Groups[1].Value
& $python -m securetrace.cli run-test --approve `
  --requirement $requirementId --test-file tests/test_authorization.py `
  --test-id test_other_user_cannot_cancel_appointment --complete
& $python -m securetrace.cli run-test --approve `
  --requirement $requirementId --test-file tests/test_vulnerable_authorization.py `
  --test-id test_other_user_cannot_cancel_appointment_on_vulnerable_control
& $python -m securetrace.cli report
```

The first test executes the owner-only control and should pass. The second
executes the same denial assertion against an intentionally vulnerable legacy
implementation and should produce a real assertion failure and `REGRESSION`.
The demo database is under `examples/authorization_demo/.securetrace/`.

Test output is captured, redacted for common credential formats, limited to
16 KiB, and saved as a referenced evidence text file. The runner records the
test ID, file, timestamps, duration, exit code, outcome, and evidence path in
the existing check history. Timeouts, collection/runtime errors, and output
storage errors cannot mark a requirement verified; only an assertion failure
marks a regression. Manual `record-check` and dashboard evidence remains
available and is labeled separately from an automatically executed test.

Before launch, SecureTrace validates the requirement against the ledger and
rejects unknown IDs. The child process receives a small OS/runtime environment
allowlist; inherited `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`, `PYTHONPATH`, and
other pytest/Python override variables are removed. Pytest uses a temporary
empty config and an explicit root directory. A `conftest.py` directly in the
approved test file's directory is intentionally allowed and executes as part
of that approved test scope; parent conftests and project pytest addopts are
excluded. On timeout, POSIX process groups are terminated and Windows child
processes are enumerated and terminated with bounded waits. The runner checks
the test file's identity and hash before and after execution and invalidates a
result if it changed.

If the evidence file cannot be written, SecureTrace records an `ERROR` outcome
without claiming evidence was persisted. If the ledger write fails after an
evidence file is saved, the CLI exits with an error and identifies the orphan
evidence path for manual cleanup; it does not claim the result was recorded.

These path and process checks reduce common mistakes and races, but do not
make test code safe. A same-user process can still change and restore a test
file between the runner's hash checks, and approved code runs with the current
user's full permissions. Process-tree termination also depends on OS process
controls; metadata reports when cleanup could not be verified.

This is not a security sandbox. Approved test code executes as the current
user and has that user's filesystem, network, and process permissions. Use a
controlled local test target, never production. Test execution is not exposed
through MCP or the dashboard chat interface.

For a failure:

```bash
uv run securetrace record-check \
  --requirement SEC-XXXXXXXX \
  --name "appointment-owner-authorization" \
  --details "A user could cancel an appointment owned by another user."
```

A failing check marks the requirement `REGRESSION`.

## Watch linked files

Run in a separate terminal from the target repository:

```bash
uv run securetrace watch
```

When a linked file changes, SecureTrace marks the linked requirement `STALE` and records an event. This first version watches file events; it does not yet run scanners automatically. That is a later milestone.

## Gemini CLI MCP integration

Gemini CLI supports local MCP servers configured in `settings.json`. See the official guide:
https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md

1. Install SecureTrace in its own directory:

   ```bash
   cd /absolute/path/to/securetrace
   uv sync
   ```

2. In the application repository you want Gemini to work on, create `.gemini/settings.json` (merge with any existing settings; do not overwrite existing configuration).

3. Add an MCP server entry, replacing `/ABSOLUTE/PATH/TO/SECURETRACE` with the absolute path to this SecureTrace checkout:

   ```json
   {
     "mcpServers": {
       "securetrace": {
         "command": "uv",
         "args": [
           "run",
           "--project",
           "/ABSOLUTE/PATH/TO/SECURETRACE",
           "securetrace-mcp"
         ],
         "cwd": ".",
         "trust": false
       }
     }
   }
   ```

4. Launch or restart Gemini CLI from the application repository and inspect `/mcp` to confirm the server and tools are available.

5. Try asking Gemini to use SecureTrace to list security requirements or record a requirement for a feature.

The MCP server uses the working directory as the target repository root unless `SECURETRACE_PROJECT_ROOT` is set. Keep `trust` false initially so Gemini CLI does not bypass tool confirmations.

## Current MCP tools

- `list_security_requirements`
- `add_security_requirement`
- `record_security_check`
- `mark_changed_files`
- `get_security_report`

These tools update local project metadata. The current starter does not execute arbitrary shell commands through MCP.

## Project structure

```text
securetrace/
├── pyproject.toml
├── README.md
├── GEMINI.md
├── .gitignore
├── securetrace/
│   ├── __init__.py
│   ├── config.py
│   ├── db.py
│   ├── ledger.py
│   ├── reporting.py
│   ├── monitor.py
│   ├── cli.py
│   └── mcp_server.py
└── tests/
    ├── test_ledger.py
    └── test_reporting.py
```

## Planned milestones

1. Foundation and ledger (this starter)
2. Gemini CLI MCP integration
3. Change-impact analysis and event monitoring
4. Semgrep local scanner evidence provider (first scanner integration)
5. Secret scanning and dependency scanner adapters (future work)
6. Security regression test orchestration
7. Evidence freshness and security-fix integrity
8. Evaluation against conventional scanning workflows

## Safety and correctness notes

- Run checks against a local, controlled development repository first.
- Never send secrets or full source files to a remote model unnecessarily.
- Do not mark a requirement verified just because an agent claims a fix is complete.
- A source file change only marks linked evidence stale; it does not prove a vulnerability exists.
- Human approval should be required before accepting a risk or applying automated fixes.

## Requirement-to-test mapping and change impact

Existing requirement-to-file links are the source of truth for code impact. Approved pytest targets are stored separately per requirement. To upgrade an existing ledger, run `securetrace migrate` explicitly; this additive migration creates `requirement_tests` and keeps existing requirements, checks, and events intact. No normal read or run command silently applies this migration. Until it is applied, reports explain that mapped rerun eligibility is unknown.

Map a target with `securetrace map-test --requirement SEC-XXXXXXXX --test-file tests/test_access.py --test-id test_owner_access [--complete]`. Mapping validates the path with the same allowlist as the runner. Once the mapping schema exists, `run-test --approve` accepts only a target mapped to that requirement and revalidates every mapping before launch.

Use `securetrace impact src/changed.py` to get an impact proposal without changing evidence or executing tests. `securetrace plan` shows the current deterministic verification plan. `securetrace mark-changed src/changed.py` records linked changes and marks evidence stale only when content fingerprints differ; if a source is missing or unreadable, freshness is UNKNOWN and the requirement remains scheduled conservatively. The report retains prior check history and shows each mapped check's reason, freshness, and blockers. A user must explicitly approve each `run-test`; file changes never launch tests automatically. If there is no approved mapping, rerun eligibility is reported as uncertain.

Every newly executed mapped test stores SHA-256 fingerprints for its linked requirement files and the approved test file, before and after execution. All mapped working-tree files are included whether or not Git tracks them. Identical content remains current even if timestamps change. Added or modified linked content makes the prior fingerprint STALE; deleted, unreadable, invalid, or unstable files yield UNKNOWN. Historical and manual records are not rewritten. Legacy automated evidence has no source fingerprint and is therefore UNKNOWN until a new approved run records one. This is stored in the existing checks metadata JSON; no additional database migration is required.

`securetrace orchestrate` consumes the deterministic plan. Without `--approve`, it records a plan event and does not execute tests or append check history. With `--approve`, it revalidates the requirement mapping, target path, and source fingerprint before each selected run, then uses the hardened pytest runner. A complete first run is allowed to establish a baseline when no prior automated result exists and the current source fingerprint is reliable. Legacy evidence with unknown freshness and any missing/unreadable source is blocked. Duplicate requirement/test pairs are suppressed within a run unless `--allow-duplicates` is passed. Watcher and MCP paths remain non-executing.

Dependency coverage is reported as `INCOMPLETE`: SecureTrace fingerprints only explicitly linked requirement files and the approved test file; it does not infer transitive imports or runtime dependencies. A `CURRENT` result therefore describes those recorded files, not the whole dependency graph.

## Semgrep local scanner evidence

SecureTrace supports Semgrep Community Edition through the `semgrep` CLI. Semgrep is an optional external executable and is not installed by SecureTrace. The integration uses one fixed command shape with a local YAML ruleset:

```text
semgrep scan --json --metrics=off --config <validated-project-rules.yml> --exclude .securetrace --exclude .git <validated-project-root>
```

The ruleset must be a YAML file inside the configured project root, at most 1 MiB, and cannot use Semgrep `extends` or remote/inherited rulesets. SecureTrace resolves and hashes it before execution, passes an argv list with `shell=False`, and always supplies the configured root as the only scan target. It excludes SecureTrace evidence and Git metadata. An out-of-root symlink blocks the scan. Captured output is bounded and sanitized; structured finding messages are retained without source snippets. Semgrep execution is a subprocess, not a security sandbox, and runs with the current user's permissions.

Install Semgrep separately if desired. Semgrep documents `pipx install semgrep` or `uv tool install semgrep`; on Windows its Community Edition page also documents `python3 -m pip install semgrep`. SecureTrace does not install or update it. See [Semgrep local CLI scans](https://semgrep.dev/docs/category/local-and-cli-scans) and [Semgrep Community Edition installation](https://semgrep.dev/products/community-edition/).

Run `securetrace semgrep --config rules/semgrep.yml` to inspect a plan. This does not execute Semgrep or write scanner evidence. After reviewing the local target and ruleset, run `securetrace semgrep --config rules/semgrep.yml --approve` to execute. The command records scanner version, ruleset SHA-256, start/end times, duration, exit code, status, and sanitized findings in the existing `events` table. No database migration is needed. Findings map only to requirements with an exact existing requirement-to-file link; other findings are shown as unmapped.

Semgrep outcomes (`CLEAN`, `FINDINGS`, `ERROR`, `TIMEOUT`, and `INCOMPLETE`) remain separate from manual evidence and pytest outcomes. `CLEAN` never marks a requirement `VERIFIED`. The Markdown report and dashboard report view show recent scanner records and unmapped findings. MCP tools and dashboard chat do not expose scanner execution, and file watchers do not run scans.

The Semgrep executable was unavailable in this development environment, so a real scan has not been verified here. Mocked integration tests cover structured results and failure states. To run the later local authorization-demo scan in PowerShell after installing Semgrep yourself:

```powershell
$repo = (Get-Location).Path
$env:SECURETRACE_PROJECT_ROOT = Join-Path $repo 'examples\authorization_demo'
$python = Join-Path $repo '.venv\Scripts\python.exe'
& $python -m securetrace.cli semgrep --config semgrep.yml
& $python -m securetrace.cli semgrep --config semgrep.yml --approve
& $python -m securetrace.cli report
```

This sample ruleset is deliberately narrow and only demonstrates a local custom rule; it is not a comprehensive authorization ruleset. Scanner coverage, ignored target behavior, dependencies, and transitive runtime inputs are not inferred as complete.

## Pre-Action Security Approval & Plain-Language Warnings (Phase 4.0)

SecureTrace provides pre-action security approval to protect critical codebase features before AI coding agents apply proposed modifications.

When an AI agent in the Antigravity IDE/CLI environment attempts to edit or overwrite a project file through one of the file tools below, the PreToolUse hook evaluates the proposed operation in memory, runs AST-based dependency and requirement impact analysis, formats an accessible 6-part plain-language warning, and requests an explicit user decision.

### How the Workflow Operates

```
[AI Proposes Edit] ──> [PreToolUse Hook] ──> [SecureTrace In-Memory Impact Check]
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼                                                             ▼
         [No Security Requirements Affected]                      [Security Requirement Linked/Imported]
                       │                                                             │
                       ▼                                                             ▼
           decision: "allow" (Automatic)                           decision: "force_ask" (Prompt User)
                       │                                                             │
                       │                                           ┌─────────────────┴─────────────────┐
                       │                                           ▼                                   ▼
                       │                                    [User Denies]                       [User Approves]
                       │                                           │                                   │
                       ▼                                           ▼                                   ▼
          [Native Tool Modifies File]                     [Operation Aborted]               [Native Tool Modifies File]
                       │                              [File 100% Untouched on Disk]                    │
                       ▼                                                                               ▼
              [PostToolUse Hook]                                                               [PostToolUse Hook]
      (Logs audit; marks evidence STALE)                                               (Logs audit; marks evidence STALE)
```

1. **In-Memory Prospective Evaluation**: The proposed file change (`Path`, `Target`/`Replacement`, or `Content`) is simulated strictly in memory. The target file on disk is not touched.
2. **Impact & Dependency Analysis**: SecureTrace traces both directly mapped security requirements and transitive Python dependencies (e.g., if `app.py` imports `auth.py`, changing `auth.py` impacts the requirements protecting `app.py`).
3. **Plain-Language Warning**: If any registered security requirement is affected, SecureTrace generates a structured, nontechnical warning explaining the exact risk, registered severity, and decision options.
4. **User Gating (`force_ask`)**: SecureTrace returns `force_ask`, which Antigravity documents-by-behavior (per third-party reports; not verified against first-party docs here) as forcing a human approve/deny prompt. SecureTrace does not draw its own popup; how the warning is rendered is up to Antigravity.
5. **Enforcement**:
   - **Denial**: The native tool execution is canceled immediately. The target file on disk retains its original bytes and timestamp.
   - **Approval**: The change is applied to the file.
6. **Evidence Invalidation (`PostToolUse`)**: Once applied, SecureTrace marks all affected requirements as `STALE` in the ledger and records an audit event (`CHANGE_APPLIED_AFTER_REVIEW` / `TOOL_WRITE_COMPLETED` / `LINKED_FILE_CHANGED`).

### Sample Plain-Language Warning

The warning shown in Antigravity's approval prompt is a short summary (about 9 lines). HIGH/CRITICAL assessed risk gets a prominent heading. The warning never approves or denies anything; the decision is made in Antigravity's own approval prompt.

```markdown
### 🚨 SecureTrace: CRITICAL RISK change — review required
**File:** `app.py`
**Change:** REMOVES_OR_WEAKENS_CHECK · **Assessed risk:** **CRITICAL**
**Requirement:** SEC-A36DA686 — "Only appointment owners can cancel" (HIGH severity)
**Impact:** A mistake here could let unauthorized users perform restricted actions or bypass permission checks.
**Verify with:** `examples/authorization_demo/tests/test_authorization.py::test_other_user_cannot_cancel_appointment`
**Evidence status:** VERIFIED
> **Decide in Antigravity's approval prompt.** This message does not approve or deny anything.
> Details for `PROP-82DF8D5574C7` are in SecureTrace's recorded proposal/report (`securetrace review PROP-82DF8D5574C7`).
```

Evidence, dependency information, uncertainties and the static-analysis limitations are kept in the recorded proposal; `securetrace review <proposal-id>` prints them in full.

### Setup and Configuration

Generate the config with `python -m securetrace.cli install-hooks` (writes `.agents/hooks.json` using the interpreter that runs the command, merges with existing hooks, no BOM). Antigravity's file tools are `write_to_file`, `replace_file_content` and `multi_replace_file_content`; earlier versions of this README named `edit_file`/`write_file`, which are kept only as legacy aliases. The resulting file looks like (shape only; the command path will be yours):

```json
{
  "securetrace-approval": {
    "PreToolUse": [
      {
        "matcher": "write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "python -m securetrace.hooks pre_tool_use"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "python -m securetrace.hooks post_tool_use"
          }
        ]
      }
    ]
  }
}
```

### Architecture in one page

| Piece | Role |
|---|---|
| Ledger (`.securetrace/securetrace.db`) | Requirements, linked files, mapped tests, evidence, append-only audit events. |
| Dependency graph (`dependencies.py`) | Static local Python import graph; reports what it could *not* analyze. |
| Approval engine (`approval.py`) | `evaluate_proposal` decides ALLOW / FORCE_ASK; also the standalone `apply_proposal`. |
| Diff analyzer (`diff_analysis.py`) | Advisory classification of one edit for the human reviewer. |
| Native hooks (`hooks.py`) | Translate Antigravity payloads into the same evaluation and record observations. |

**Registering and tracing a requirement:**

```bash
securetrace add-requirement --title "Only owners cancel" --description "..." \
  --category authorization --severity high --file app.py          # severity = how much the requirement matters
securetrace map-test --requirement <SEC-ID> --test-file tests/test_auth.py --test-id test_owner_only --complete
securetrace list ; securetrace plan ; securetrace report            # inspect requirements and evidence
securetrace review <PROP-ID>                                        # inspect one assessment
```

Paths must be project-relative (absolute paths and `..` are rejected; `\`, `./` and `//` are normalized). Audit history is in the `events` table (`sqlite3 .securetrace/securetrace.db "select * from events order by id desc limit 20"`), proposals are JSON under `.securetrace/proposals/`, and hook problems go to `.securetrace/diagnostics.log`.

### Four different things (never conflated)

1. **Requirement severity**: registered by a person (`low`..`critical`).
2. **Change risk**: the analyzer's assessment of *one* edit (`LOW`..`CRITICAL`, or `UNCERTAIN`).
3. **Analysis confidence**: `dependency_coverage` (`LOCAL_STATIC_IMPORTS` or `PARTIAL_LOCAL_STATIC`) plus `analysis_status` below.
4. **Enforcement**: `ALLOW` or `FORCE_ASK`. Decided by requirement linkage and analysis completeness, **not** by the diff classification: a comment-only edit to a protected file is still reviewed.

### Fail-closed and uncertainty policy

Every proposal has an `analysis_status`:

| `analysis_status` | Meaning | Decision |
|---|---|---|
| `CONFIRMED_AFFECTED` | A registered requirement is linked directly or via known imports. | `FORCE_ASK`, full warning |
| `INCOMPLETE_UNKNOWN_IMPACT` | None confirmed, but incomplete analysis could hide one (see below). | `FORCE_ASK`; warning says "could not rule out" and names the requirements |
| `COMPLETE_NO_IMPACT` | Analysis was sufficient and nothing is affected (or no requirement is registered at all). | `ALLOW` |
| `NOT_ANALYZED_NO_CHANGE` | The edit produces identical content. | `ALLOW` |

Incomplete analysis counts only when it is **relevant**: an unparseable file, a dynamic import, or an unresolved import matters when that file (or something that imports it) is linked to a requirement, and for unresolved imports only for changed files whose name could satisfy the import. A traversal cut off by depth/node limits is always relevant once requirements exist. A broken scratch file elsewhere does *not* force review of unrelated edits. `dependency_coverage` still reports `PARTIAL_LOCAL_STATIC` honestly.

| Situation | Hook result |
|---|---|
| File tool, unprotected, analysis sufficient | `allow` |
| Known protected change | `force_ask` |
| Impact cannot be determined (relevant incompleteness) | `force_ask` |
| Malformed payload / missing path / missing or non-text content / unreadable target | `deny` |
| Ledger corrupt or unavailable, analysis raised an exception | `deny` |
| Unrecognised decision value from the engine | `deny` |
| Audit event could not be written *after* a successful assessment | still `force_ask`; the warning states the audit trail is incomplete |
| Tool not in the matcher (e.g. `run_command`) | `allow`: not seen, not assessed |

### Diff classifications and their limits

`COMMENT_ONLY`, `UNRELATED_LOGIC`, `MODIFIES_AUTH_LOGIC`, `REMOVES_OR_WEAKENS_CHECK`, `UNCERTAIN`. The analyzer is a targeted AST heuristic keyed on authorization-style function names, not a proof. It notices e.g. a new `return True`, `==` negated, `and` turned into `or`, removed identity validation, changed signature/decorators, edited same-module helpers (transitively), a guard call dropped from a caller, a new function that is not guarded, a rebinding of the check function, and new dynamic constructs. It does **not** follow calls across files, analyze class-method bodies (a changed class is `UNCERTAIN`), model control-flow order, or see code reached by `getattr`/`importlib`. In a file with no recognisable authorization function, changed code is `UNCERTAIN`, never `UNRELATED_LOGIC`. `UNRELATED_LOGIC/LOW` is claimed only when a protected function was identified and left untouched.

### Native integration vs standalone path

| | Native Antigravity hook | Standalone (`approve`) |
|---|---|---|
| Who writes the file | The host, after its own prompt | SecureTrace |
| Prevents the write | Only by returning `deny`/`force_ask` to the host | Yes: token, content hash, target identity, single-use, expiry, CAS re-check, per-target lock, atomic replace |
| Link between review and write | Path + SHA-256 of proposed content compared with the file after the write | Proposal ID |
| Host decision known | **No.** The hook API reports tool calls, not the user's choice. | Yes: `approve`/`abort` are SecureTrace commands |

Do not assume the standalone protections apply to host-managed writes. They do not.

### Audit events: observed vs inferred

| Event | Written when | Basis |
|---|---|---|
| `SECURITY_REVIEW_REQUESTED` | Pre-hook returned `force_ask` (one per affected, or possibly affected, requirement) | observed |
| `CHANGE_APPLIED_AFTER_REVIEW` | Host reported completion **and** exactly one open review's proposed content equals the file now on disk | observed write; "allowed" is inferred |
| `WRITE_REVIEW_AMBIGUOUS` | Several open reviews match the same content; none marked applied | observed |
| `WRITE_DID_NOT_MATCH_REVIEW` | A write occurred but matches no open review (later edit, or host wrote something else) | observed |
| `TOOL_COMPLETED_NO_FILE_CHANGE` / `TOOL_WRITE_FAILED` | Host said completed but file unchanged / host reported an error | observed |
| `TOOL_WRITE_COMPLETED`, `LINKED_FILE_CHANGED` | Completed write; evidence re-evaluated | observed |
| `REVIEW_NO_WRITE_OBSERVED` | Review expired with no matching write. **Never "denied"**: could be a denial, cancellation or failure | absence of evidence |
| `FRESHNESS_UPDATE_FAILED` | Post-write evidence invalidation raised; treat evidence as unverified | observed failure |
| `APPROVAL_APPLIED` / `APPROVAL_APPLY_REJECTED` / `APPROVAL_EXPIRED` | Standalone path | observed |
| `APPROVAL_DENIED` | Only by `securetrace abort` | explicit |

Proposal statuses: `PENDING`, `APPROVED` (no review needed), `APPLIED` (standalone), `APPLIED_BY_HOST` (observed after a native write), `EXPIRED`, `DENIED`. New fields on proposal files are optional, so older records and events remain readable; existing history is never rewritten. `apply` reports, but does not undo, a failure to record bookkeeping after the file is written: such failures appear in `audit_errors`, the CLI exit code (3) and `diagnostics.log`.

### Evidence freshness

A change to a requirement's linked file, a mapped test, **or any file they import (transitively)** marks the requirement's evidence stale. Unrelated files do not. If the transitive part cannot be computed, direct invalidation is still applied and the failure is raised/recorded, never reported as success.

### Prevention vs post-action detection

Prevention exists only where a hook runs *before* the write and the host honours its answer (the five file tools), or where SecureTrace itself writes (`approve`). Everything else (shell commands, editors, git checkouts, other processes) is detected afterwards at best (`securetrace watch`, or the post-hook for host tools) and cannot be blocked.

### Diagnosing hook failures

1. `securetrace doctor`
2. `.securetrace/diagnostics.log` (JSON lines: time, component, message; never file contents)
3. `securetrace review <PROP-ID>` and the `events` table
4. Replay a payload: `echo '{...}' | python -m securetrace.hooks pre_tool_use`

### Trying another approach

Antigravity's `force_ask` prompt is approve-or-deny. "Try another approach" is therefore a follow-up: choose Deny, then ask the agent for a different change. The MCP tool `get_security_review_context` (read-only) gives the agent the affected requirements and warning. The agent's next write goes through the hook again.

### Standalone CLI Commands

You can also evaluate, review, and apply proposals directly via the CLI:

```bash
# Review a pending proposal with the plain-language warning
python -m securetrace.cli review PROP-XXXXXXXXXXXX

# Approve and apply an exact proposal (enforcing HMAC token & CAS checks)
python -m securetrace.cli approve PROP-XXXXXXXXXXXX

# Abort a proposal without modifying files
python -m securetrace.cli abort PROP-XXXXXXXXXXXX
```

### Security Boundaries & Platform Limitations

- **Intercepted before execution (when the host runs the hook and honours the result):** Antigravity's `write_to_file`, `replace_file_content`, `multi_replace_file_content`, plus legacy aliases `write_file`, `edit_file`. The matcher in `.agents/hooks.json` and the implementation are tested to agree.
- **Not intercepted:** shell commands (`run_command`), external editors, git operations, other processes. `securetrace watch` can mark evidence stale afterwards; it cannot prevent anything.
- **No host approval/denial callback exists** in the hook contract SecureTrace uses. SecureTrace does not invent one; see the event table for what is observed.
- **Filesystem threat model (standalone `approve`).** Defended: `..` traversal, symlinks leaving the project, retargeting a symlink after review (proposals bind to the resolved file), swapping the reviewed path for a symlink, content changed after review (compare-and-swap, checked again just before the swap), tampered proposal content (re-hashed), replay, expiry, two SecureTrace processes racing (per-target lock; stale after 60 s). Preserved: file mode, original text encoding for non-UTF-8 files (edits that cannot be represented are refused), CRLF/BOM. **Not defended:** a different program that changes the file in the instant between the final check and `os.replace` (not closable portably; the newer content would be replaced); atomic replace gives the target a new inode, so hard links to it keep the old bytes and ACL/xattr/ownership are not copied; Windows semantics are not exercised by the automated suite.
- **The ledger is not tamper-proof.** It is a local SQLite file writable by anyone who can write the project. It records what happened for honest use and diagnosis; it is not evidence against a hostile local user. It is never deleted or recreated automatically (a corrupt ledger raises an error telling you so).
- **Static analysis** parses local Python imports only; dynamic imports and non-Python assets are reported as incomplete (see the uncertainty policy). Pre-action approval does not prove that an approved change is secure.

### Demonstration with Authorization Demo

The demo needs a registered requirement; `.securetrace/` is gitignored, so a fresh clone has none and the hook correctly answers `allow` (nothing is protected).

```bash
pip install -e .
export SECURETRACE_PROJECT_ROOT="$PWD/examples/authorization_demo"      # PowerShell: $env:SECURETRACE_PROJECT_ROOT = "$PWD\examples\authorization_demo"
securetrace init
securetrace add-requirement --title "Only appointment owners can cancel" \
  --description "Server must verify the actor owns the appointment." --category authorization --severity high --file app.py
python examples/hook_demo.py
```

Expected: (1) weakening the ownership check -> `force_ask` with the warning; (2) a no-op edit to the unlinked `pyproject.toml` -> `allow`. `hook_demo.py` only simulates the host by piping JSON to the hook; it never writes `app.py` and is not a live Antigravity test.

### Running the Test Suite

```bash
pip install -e ".[dev]"
python -m pytest -q
```

All tests use temporary directories and do not touch `.securetrace/` or `examples/authorization_demo/app.py`. Expected skips and platform notes:

- Symlink, hard-link, file-mode and POSIX shell-quoting tests skip (or are marked) on Windows or where symlinks are not permitted; the skip reason is printed with `-rs`.
- `tests/test_test_runner.py::test_timeout_kills_child_process_tree` can fail in containers whose PID 1 reaps orphaned children slowly (the killed process group lingers longer than the 0.5 s verification window). It is an environment limitation, not a SecureTrace result; run it on a normal host.
- Hook tests simulate the host by sending JSON. They prove SecureTrace's policy and recording, not that Antigravity invokes the hook.
