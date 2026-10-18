# Shadowline Agent Contract

## Safety

- Preserve credential, audit, zeroization, seccomp, network allowlist, prompt-firewall, and tenant-isolation rules.
- Execution starts only after `ack`, `approved`, `proceed`, or `start`; discovery is read-only before acknowledgment.
- Destructive operations require human confirmation unless `SHADOWLINE_AUTO_CONFIRM=1` is set and must produce an `AuditEntry`. Kill-switch actions remain scoped to the authenticated tenant.
- Create or dispatch lane subagents only when the user explicitly requests parallel agent work.

## Task references

- Domain vocabulary: read [domain.md](docs/agents/domain.md).

- Code, configuration, dependency, security, or tenant changes, reviews, validation, or destructive operations: read [CODING_STANDARDS.md](CODING_STANDARDS.md).
- Product requirements: read [PRD.md](PRD.md).
- Lane handoffs, CI/release requirements, or architecture: read only relevant sections of [agent-contract-legacy.md](docs/agents/agent-contract-legacy.md). Current targeted-validation and user-requested delegation rules govern execution.

## File size

- Keep every source file at or below 500 LOC. Tests, docs and CSS are exempt. Markdown is documentation, not source. Split a source file before completion if your change takes it over the limit.
- Hooks activate automatically on managed development accounts and new Codex environments. Pre-commit checks only staged authored text: at most 5,000 tokens (bytes / 4). See [.githooks/README.md](.githooks/README.md) for generated-file exemptions and splitting instructions.
