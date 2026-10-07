# Coding Standards

## Validation
- Prefer a named test: `cargo test <test-name>`; scope lint/type checks to the affected package when possible.
- Security audits are selected when dependency or security surfaces change.
- Bare `cargo test`, repository-wide Clippy, the all-lanes matrix, and full security audit chains are broad and run only after an explicit user request.

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
- Outside required `// SAFETY:` and public-function doc comments, add comments only when explicitly requested.
- Structs and enums use `#[derive(Debug, Clone)]` at minimum.
- All public functions must have doc comments.
- Error handling via `thiserror` for library errors, `anyhow` for application errors.
- Async via `tokio` runtime.

---

## CI/CD Rules

1. **PR required** for all changes to `main`.
2. **Lane checks must pass** before merge — determined by which directories changed.
3. **`lane-security` review required** for changes to `src/security/`, `src/ai/`, `Cargo.toml` dependency additions.
4. **Reproducible build check** on every release — binary hash must match locally built hash.
5. **`cargo audit`** runs on every PR — zero known vulnerabilities in dependencies.
6. **`cargo vet`** runs on every PR — all new dependencies must be audited.

---
