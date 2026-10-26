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

When an AI agent in the Antigravity IDE/CLI environment attempts to edit or overwrite a project file via `edit_file` or `write_file`, SecureTrace intercepts the operation in memory, runs AST-based dependency and requirement impact analysis, formats an accessible 6-part plain-language warning, and requests an explicit user decision.

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

```markdown
### SecureTrace Pre-Action Security Warning

**1. What is proposed to change:**
The AI coding agent proposes to modify `examples/authorization_demo/app.py` (replacing text).

**2. What could go wrong:**
If this change contains a mistake, it could allow unauthorized users to perform restricted actions, access private accounts, or bypass permission checks.
*(Note: This warning indicates a potential security risk requiring review; it does not mean a confirmed defect or vulnerability has already been found.)*

**3. Why this warning appeared:**
This modification touches code protected by registered project security requirements:
- **SEC-D91558F9** (Severity: HIGH): "Only appointment owners can cancel" — `app.py` is directly linked to this requirement.

**4. How serious this potential impact is:**
- **Highest Registered Severity:** HIGH
- **Scope of Impact:** 1 registered security requirement(s) potentially affected.
- **Dependent Application Files:** 1 other local file(s) rely on this code.
*(Severity is derived directly from the registered requirements in your project ledger; it has not been invented.)*

**5. What you can choose to do:**
- **Allow / Approve:** Permit the change if you have inspected the proposed modification and confirmed it is safe and intentional.
- **Deny / Abort:** Stop the change if you did not expect this file to be modified or want to review the code with your team first.

**6. What happens after your decision:**
- **If you approve:** The change will be applied to `app.py`. SecureTrace will immediately mark the verification records for the affected requirements as outdated, and you should run your verification tests to confirm the application remains safe.
- **If you deny:** The change is discarded. `app.py` will not be modified, and your repository remains completely untouched.
```

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

### Audit events and what the host can tell us

Antigravity's hook API reports tool calls, not the user's decision. SecureTrace therefore records only what it observes: `SECURITY_REVIEW_REQUESTED` (per requirement), `CHANGE_APPLIED_AFTER_REVIEW` (the file on disk matches the reviewed proposal after a completed write), `LINKED_FILE_CHANGED`, `TOOL_WRITE_COMPLETED`, and `REVIEW_NO_WRITE_OBSERVED` (a review expired with no matching write; this may be a denial, cancellation or failure and is never recorded as "denied"). `APPROVAL_DENIED` is written only by the `abort` CLI command. Identical `LINKED_FILE_CHANGED` events within 3 seconds are recorded once.

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

- **What IS Intercepted**:
  - All native agent modifications made through Antigravity's `edit_file` and `write_file` tools.
  - Directory traversal (`..`) and symlinks attempting to escape the project root are rejected.
  - Proposals enforce cryptographic HMAC token binding, 5-minute expiry, single-use replay prevention, and Compare-And-Swap (CAS) pre-image checks to block concurrent overwrites.
  - Integration errors, timeouts, and unparseable inputs fail closed (`decision: "deny"`).
- **What is NOT Intercepted**:
  - External shell commands running out-of-band writes (e.g. `run_command("echo ... > app.py")`).
  - File changes made by external text editors, IDE git checkouts, or external processes outside Antigravity.
  - *Post-Write Detection*: The existing `securetrace watch` filesystem monitor detects these unmonitored changes post-facto and marks evidence `STALE`, but cannot prevent them in advance.
- **Known Static-Analysis Limitations**:
  - Static AST analysis parses local Python imports. Dynamic runtime imports (`importlib`, `sys.modules` injection) cannot be fully resolved statically; SecureTrace flags these as `PARTIAL_LOCAL_STATIC` and appends an explicit scope notice.
- **Assurance Boundary**:
  - **Pre-action approval does not prove that an approved change is secure or bug-free.** It ensures that users are informed of potential security impacts before files are altered and prompts them to re-verify their security test suite.

### Demonstration with Authorization Demo

1. Test the hook with a security-sensitive edit to `examples/authorization_demo/app.py`:

```powershell
python -c "import json, subprocess, os; ws = os.path.abspath('examples/authorization_demo'); p = {'toolCall': {'name': 'edit_file', 'args': {'Path': os.path.join(ws, 'app.py'), 'Target': 'return bool(actor_id) and actor_id == appointment_owner_id', 'Replacement': 'return True'}}, 'workspacePaths': [ws]}; res = subprocess.run(['python', '-m', 'securetrace.hooks', 'pre_tool_use'], input=json.dumps(p), capture_output=True, text=True); print(res.stdout)"
```

Expected result: outputs `{"decision": "force_ask", "reason": "### SecureTrace Pre-Action Security Warning..."}` citing `SEC-D91558F9` and authorization bypass risk.

2. Test the hook with a non-security change to `pyproject.toml`:

```powershell
python -c "import json, subprocess, os; ws = os.path.abspath('examples/authorization_demo'); p = {'toolCall': {'name': 'edit_file', 'args': {'Path': os.path.join(ws, 'pyproject.toml'), 'Target': 'name', 'Replacement': 'package_name'}}, 'workspacePaths': [ws]}; res = subprocess.run(['python', '-m', 'securetrace.hooks', 'pre_tool_use'], input=json.dumps(p), capture_output=True, text=True); print(res.stdout)"
```

Expected result: outputs `{"decision": "allow"}` without prompting the user.

### Running the Test Suite

Run the full Phase 4.0 approval test suite:

```bash
.venv\Scripts\python.exe -m pytest tests/test_approval.py -v
```

Run all non-network tests across the entire repository:

```bash
.venv\Scripts\python.exe -m pytest --ignore=tests/test_dashboard.py -v
```

