# SecureTrace implementation roadmap

## Phase 1: Local ledger (starter)
- [x] SQLite database and requirement model
- [x] CLI to register/list requirements
- [x] Record verification results and statuses
- [x] Link requirements to repository-relative files
- [x] Mark linked requirements stale on file changes
- [x] Generate Markdown report
- [x] MCP tools for Gemini CLI
- [x] Unit tests for core state transitions

## Phase 2: Integration hardening
- [ ] Validate MCP server with the installed Gemini CLI version
- [ ] Add project-root safeguards and path normalization tests
- [ ] Add structured logging with secret redaction
- [ ] Add status-history queries and schema migrations

## Phase 3: Security checks
- [ ] Semgrep adapter
- [ ] Secret scanning adapter
- [ ] OSV-Scanner adapter
- [ ] Store tool version, exit code, commit, and sanitized output reference
- [ ] Never interpret "no findings" as proof that all requirements are verified

## Phase 4: Change-aware verification
- [ ] Map requirements to tests, symbols, routes, and config keys
- [ ] Re-run only relevant tests after change events
- [ ] Mark evidence stale when linked code or environment changes
- [ ] Avoid duplicate events from atomic-save editor behavior

## Phase 5: Evaluation
- [ ] Create safe sample application with seeded security regressions
- [ ] Compare ordinary scanning vs SecureTrace workflow
- [ ] Measure regression detection, false positives, staleness detection, latency, and overhead
