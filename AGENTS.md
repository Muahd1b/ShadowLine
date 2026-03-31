# Shadowline — Agent Orchestration Guide

## Purpose

This file is the project-level control plane for agent orchestration on the Shadowline codebase. It defines lanes, roles, validation checks, and workflow rules for all agent-driven development.

## Precedence

1. Global policy from `~/.config/opencode/AGENTS.md`.
2. Workspace overlay from `~/.codex/agent-fabric/workspaces/` (if registered).
3. **This file** (`~/Dev/Shadowline/AGENTS.md`) — project-level orchestration.
4. `PRD.md` — product requirements and feature specifications.

## Project Overview

**Shadowline** is a single-binary, Rust-based TUI application for:
- Attack velocity forecasting (ExfilClock)
- Vendor breach kill-switching (ChainKill)
- Supply chain scanning (package + agent skill auditing)
- Agentic security reasoning (Codex-powered AI brain)
- Plugin/skill system (extensible architecture)

**Tech Stack:**
- Language: Rust 2024 edition
- TUI: ratatui + crossterm
- Database: SQLite (rusqlite)
- HTTP: reqwest + rustls
- Crypto: ring, zeroize
- CLI: clap
- Keychain: keyring-rs
- AI: OpenAI Codex API (primary), local model (fallback)
- Serialization: serde + serde_json

---

## Lane-Based Sub-Agent System

All development work is dispatched to lane subagents based on the component being modified.

### Lanes

#### `lane-core`
- **Scope:** Core engine logic — velocity clock, kill switch, integration graph, blast radius calculator, action validator
- **Dir:** `src/core/`
- **Checks:** `cargo test`, `cargo clippy`, `cargo check`

#### `lane-tui`
- **Scope:** Terminal UI — dashboard, panels, command prompt, live updates, keyboard handling
- **Dir:** `src/tui/`
- **Checks:** `cargo test`, `cargo clippy`, `cargo check`, visual review via screenshot testing

#### `lane-connectors`
- **Scope:** SaaS platform connectors — OAuth flows, API clients, token management, webhook discovery
- **Dir:** `src/connectors/`
- **Checks:** `cargo test`, `cargo clippy`, integration tests against sandbox APIs

#### `lane-scanner`
- **Scope:** Supply chain scanner — package analysis, dependency tree parsing, malicious pattern detection, agent skill scanning
- **Dir:** `src/scanner/`, `skills/supply-chain-scanner/`
- **Checks:** `cargo test`, `cargo clippy`, detection accuracy tests

#### `lane-security`
- **Scope:** Security hardening — prompt firewall, seccomp profiles, credential vault, audit log, memory safety, sandbox
- **Dir:** `src/security/`, `src/sandbox/`
- **Checks:** `cargo test`, `cargo clippy`, `cargo audit`, `cargo vet`, `cargo deny`

#### `lane-plugins`
- **Scope:** Plugin/skill system — skill manifest parsing, sandbox execution, registry integration, OpenCode skill export
- **Dir:** `src/plugins/`, `skills/`
- **Checks:** `cargo test`, `cargo clippy`, plugin isolation tests

#### `lane-ai`
- **Scope:** Codex integration — prompt construction, response parsing, JSON plan validation, model management, velocity model
- **Dir:** `src/ai/`
- **Checks:** `cargo test`, `cargo clippy`, integration tests with mock Codex responses

#### `lane-data`
- **Scope:** Data layer — SQLite schema, migrations, queries, audit log chaining, model hash tracking
- **Dir:** `src/data/`
- **Checks:** `cargo test`, migration tests, schema validation

---

## Operational Roles (5-Agent Roster)

When processing an issue, map work to these roles:

| Role | Responsibility | Maps To |
|------|---------------|---------|
| **supervisor** | Decomposition, lane assignment, guardrail compliance | Primary agent |
| **research_primary** | Discovery, codebase exploration, context collection | `explore` subagent |
| **research_secondary** | Assumption review, risk analysis, security audit | `explore` subagent |
| **code_editor** | Applies approved changes via lane dispatch | Lane subagents |
| **tester** | Runs validation matrix, reports residual risk | Final validation |

---

## Session Handshake (Mandatory)

### Phase 1 — Intake (read-only)

1. Read `PRD.md` for product requirements and feature specs.
2. Read this `AGENTS.md` file for orchestration rules.
3. Parse the issue and classify affected lanes.
4. Use `explore` subagent to discover relevant code.
5. Build an orchestration strategy with:
   - Issue summary
   - Lane assignment
   - Implementation sequence
   - Validation matrix
   - Risks and open questions

### Phase 2 — Acknowledgment Gate

- Execution starts only after explicit user acknowledgment.
- Accepted: `ack`, `approved`, `proceed`, `start`.
- Before acknowledgment: read-only discovery only.

### Phase 3 — Execution

- Dispatch to lane subagents.
- Run lane validation checks.
- Report changed files, validations executed, and residual risks.

---

## Validation Matrix

| Lane | Checks | Command |
|------|--------|---------|
| `lane-core` | Unit tests, lint, type check | `cargo test --lib && cargo clippy -- -D warnings` |
| `lane-tui` | Unit tests, lint, visual review | `cargo test && cargo clippy -- -D warnings` |
| `lane-connectors` | Unit tests, lint, integration tests | `cargo test && cargo clippy -- -D warnings && cargo test -- --ignored` |
| `lane-scanner` | Unit tests, lint, detection accuracy | `cargo test && cargo clippy -- -D warnings && cargo test scanner` |
| `lane-security` | Unit tests, lint, audit, supply chain | `cargo test && cargo clippy -- -D warnings && cargo audit && cargo vet` |
| `lane-plugins` | Unit tests, lint, isolation tests | `cargo test && cargo clippy -- -D warnings && cargo test plugins` |
| `lane-ai` | Unit tests, lint, mock integration | `cargo test && cargo clippy -- -D warnings && cargo test ai` |
| `lane-data` | Unit tests, migration tests | `cargo test && cargo clippy -- -D warnings && cargo test data` |
| **All lanes** | Full check | `cargo test && cargo clippy -- -D warnings && cargo audit` |

---

## Lane Handoff Rules

1. `lane-core` hands off to `lane-tui` when new engine features need UI representation.
2. `lane-core` hands off to `lane-ai` when new reasoning capabilities are needed.
3. `lane-connectors` hands off to `lane-security` when new API credentials or OAuth flows are added.
4. `lane-ai` hands off to `lane-security` when prompt handling or agent behavior changes.
5. `lane-scanner` hands off to `lane-core` when scan results affect blast radius calculation.
6. Any lane hands off to `lane-data` when schema or storage changes are needed.
7. `lane-security` reviews ALL lanes before merge — security is a cross-cutting concern.

---

## Security Guardrails

These apply to ALL lanes without exception:

1. **No credential in code.** API keys, tokens, and secrets must come from env vars or OS keychain, never hardcoded.
2. **No auto-execution.** Destructive operations require human confirmation unless `SHADOWLINE_AUTO_CONFIRM=1` is set.
3. **Audit everything.** All destructive actions must produce an `AuditEntry`.
4. **Zeroize secrets.** Any struct holding credentials must implement `Zeroize` and `ZeroizeOnDrop`.
5. **No `unsafe` without review.** Every `unsafe` block must have a `// SAFETY:` comment and PR review from `lane-security`.
6. **Seccomp compliance.** No new syscall without updating the seccomp allowlist.
7. **Network allowlist.** No new outbound destination without updating `config.toml` defaults.
8. **Reproducible builds.** `Cargo.lock` must always be committed. No `cargo update` without PR review.
9. **No `execve`.** Shadowline must never spawn child processes for user-supplied commands.
10. **Prompt firewall.** All telemetry passed to Codex must be preprocessed through the prompt firewall.

---

## Multi-Tenancy Rules

Shadowline v1 is single-tenant (one org per installation). For enterprise multi-tenant deployment (v2):

1. Each tenant's integration graph must be isolated in separate SQLite databases.
2. Kill switch actions must be scoped to the authenticated tenant.
3. Audit logs must be tenant-tagged.
4. Velocity model data must be tenant-partitioned.

---

## Code Style

- Follow `rustfmt` defaults (run `cargo fmt` before commit).
- `clippy` warnings are errors (`-D warnings`).
- No comments unless explicitly requested.
- Structs and enums use `#[derive(Debug, Clone)]` at minimum.
- All public functions must have doc comments.
- Error handling via `thiserror` for library errors, `anyhow` for application errors.
- Async via `tokio` runtime.

---

## File Structure

```
~/Dev/Shadowline/
├── PRD.md                    # Product Requirements Document
├── AGENTS.md                 # This file — agent orchestration
├── Cargo.toml                # Rust project manifest
├── Cargo.lock                # Locked dependencies (committed)
├── src/
│   ├── main.rs               # Entry point
│   ├── lib.rs                # Library root
│   ├── core/                 # lane-core
│   │   ├── mod.rs
│   │   ├── velocity.rs       # Attack velocity estimation
│   │   ├── kill_switch.rs    # Vendor kill chain execution
│   │   ├── graph.rs          # Integration graph
│   │   ├── blast_radius.rs   # Blast radius calculator
│   │   └── validator.rs      # Action validation
│   ├── tui/                  # lane-tui
│   │   ├── mod.rs
│   │   ├── dashboard.rs
│   │   ├── panels/
│   │   └── command.rs
│   ├── connectors/           # lane-connectors
│   │   ├── mod.rs
│   │   ├── salesforce.rs
│   │   ├── github.rs
│   │   ├── slack.rs
│   │   └── common.rs
│   ├── scanner/              # lane-scanner
│   │   ├── mod.rs
│   │   ├── npm.rs
│   │   ├── pypi.rs
│   │   ├── go.rs
│   │   ├── rust.rs
│   │   └── agent_skills.rs
│   ├── security/             # lane-security
│   │   ├── mod.rs
│   │   ├── prompt_firewall.rs
│   │   ├── credential_vault.rs
│   │   ├── audit_log.rs
│   │   ├── sandbox.rs
│   │   └── seccomp.rs
│   ├── plugins/              # lane-plugins
│   │   ├── mod.rs
│   │   ├── manifest.rs
│   │   ├── executor.rs
│   │   └── registry.rs
│   ├── ai/                   # lane-ai
│   │   ├── mod.rs
│   │   ├── codex_client.rs
│   │   ├── plan_parser.rs
│   │   └── model_manager.rs
│   └── data/                 # lane-data
│       ├── mod.rs
│       ├── schema.rs
│       ├── migrations.rs
│       └── queries.rs
├── skills/                   # Built-in plugins
│   ├── supply-chain-scanner/
│   │   ├── SKILL.toml
│   │   └── src/
│   └── secret-scanner/
│       ├── SKILL.toml
│       └── src/
├── tests/                    # Integration tests
│   ├── core_integration.rs
│   ├── connector_sandbox.rs
│   ├── scanner_accuracy.rs
│   └── plugin_isolation.rs
├── docs/
│   ├── architecture.md
│   ├── connectors.md
│   └── security-model.md
└── .github/
    └── workflows/
        ├── ci.yml
        ├── release.yml
        └── supply-chain.yml
```

---

## CI/CD Rules

1. **PR required** for all changes to `main`.
2. **Lane checks must pass** before merge — determined by which directories changed.
3. **`lane-security` review required** for changes to `src/security/`, `src/ai/`, `Cargo.toml` dependency additions.
4. **Reproducible build check** on every release — binary hash must match locally built hash.
5. **`cargo audit`** runs on every PR — zero known vulnerabilities in dependencies.
6. **`cargo vet`** runs on every PR — all new dependencies must be audited.

---

## Quick Reference

```
# Start a development session
cd ~/Dev/Shadowline

# Run all checks
cargo test && cargo clippy -- -D warnings && cargo fmt --check

# Run specific lane tests
cargo test core
cargo test tui
cargo test connectors
cargo test scanner
cargo test security
cargo test plugins
cargo test ai
cargo test data

# Security checks
cargo audit
cargo vet
cargo deny check advisories
cargo deny check licenses

# Build release binary
cargo build --release --locked

# Run TUI
cargo run

# Run CLI command
cargo run -- scan ./test-project --json
```

---

*End of AGENTS.md.*
