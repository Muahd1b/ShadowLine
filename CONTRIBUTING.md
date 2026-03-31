# Contributing to Shadowline

Thank you for your interest in contributing to Shadowline! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Lane-Based Development](#lane-based-development)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)
- [Skill Development](#skill-development)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Prioritize security and safety

## Getting Started

### Prerequisites

- Rust 1.75+ (2024 edition)
- Cargo
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/shadowline-dev/shadowline.git
cd shadowline

# Build the project
cargo build --release

# Run tests
cargo test

# Run the TUI
cargo run
```

## Development Workflow

1. **Read AGENTS.md** - This is our orchestration guide for agent-driven development
2. **Check existing issues** - Look for issues labeled `good-first-issue` or `help-wanted`
3. **Create a branch** - Use descriptive names: `feature/velocity-prediction`, `fix/memory-leak`
4. **Follow lane conventions** - See [Lane-Based Development](#lane-based-development)
5. **Run validation** - Ensure tests pass before submitting
6. **Submit PR** - Include clear description and link related issues

## Lane-Based Development

Shadowline uses a lane-based architecture. Choose your lane based on what you're modifying:

### `lane-core`
**Scope:** Velocity clock, kill switch, integration graph, blast radius calculator
**Directory:** `src/core/`
**Checks:** `cargo test --lib && cargo clippy -- -D warnings`

### `lane-tui`
**Scope:** Terminal UI, dashboard, panels, event handling
**Directory:** `src/tui/`
**Checks:** `cargo test && cargo clippy -- -D warnings`

### `lane-connectors`
**Scope:** SaaS platform connectors, OAuth flows, API clients
**Directory:** `src/connectors/`
**Checks:** `cargo test && cargo clippy -- -D warnings`

### `lane-scanner`
**Scope:** Supply chain scanning, package analysis, skill auditing
**Directory:** `src/scanner/`
**Checks:** `cargo test && cargo clippy -- -D warnings && cargo test scanner`

### `lane-security`
**Scope:** Prompt firewall, credential vault, audit log, sandbox
**Directory:** `src/security/`, `src/sandbox/`
**Checks:** `cargo test && cargo clippy -- -D warnings && cargo audit && cargo vet`

### `lane-plugins`
**Scope:** Skill system, manifest parsing, registry integration
**Directory:** `src/plugins/`, `skills/`
**Checks:** `cargo test && cargo clippy -- -D warnings && cargo test plugins`

### `lane-ai`
**Scope:** Codex integration, prompt construction, response parsing
**Directory:** `src/ai/`
**Checks:** `cargo test && cargo clippy -- -D warnings && cargo test ai`

### `lane-data`
**Scope:** SQLite schema, migrations, queries
**Directory:** `src/data/`
**Checks:** `cargo test && cargo clippy -- -D warnings && cargo test data`

## Submitting Changes

### Pull Request Process

1. **Update documentation** if changing behavior
2. **Add tests** for new functionality
3. **Run lane validation** from the matrix above
4. **Update CHANGELOG.md** with your changes
5. **Link related issues** in PR description
6. **Request review** from appropriate lane maintainers

### Commit Message Format

```
[lane-prefix] Brief description

Detailed explanation of what changed and why.

- Bullet points for multiple changes
- Reference issues: Fixes #123
```

Examples:
- `[tui] Add scroll indicators to dashboard panes`
- `[security] Implement credential vault with OS keychain`
- `[core] Fix velocity calculation edge case`

## Coding Standards

### Rust Style

- Follow `rustfmt` defaults: `cargo fmt`
- All clippy warnings are errors: `cargo clippy -- -D warnings`
- No comments unless explicitly requested
- Use `#[derive(Debug, Clone)]` at minimum for structs/enums
- Doc comments for all public functions

### Error Handling

- Library errors: `thiserror`
- Application errors: `anyhow`
- Always propagate errors with context

### Async

- Use `tokio` runtime
- Prefer `async/await` over manual futures
- Handle cancellation properly

### Security

See [Security](#security) section below.

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run specific lane tests
cargo test core
cargo test tui
cargo test scanner
```

### Integration Tests

```bash
# Run integration tests
cargo test --test core_integration
cargo test --test connector_sandbox
cargo test --test scanner_accuracy
```

### Security Tests

```bash
# Audit dependencies
cargo audit

# Vet new dependencies
cargo vet

# Check licenses
cargo deny check licenses
```

## Documentation

### Required Documentation

- **README.md** - User-facing documentation
- **AGENTS.md** - Agent orchestration guide (keep updated)
- **PRD.md** - Product requirements (for major features)
- **Inline docs** - All public APIs

### Skill Documentation

Skills in `.agents/skills/` must include:

- Description and purpose
- When to use
- Workflow steps
- Example invocations
- Parameters table
- Related skills

## Security

### Security Guardrails (Mandatory)

1. **No credentials in code** - Use env vars or OS keychain
2. **No auto-execution** - Destructive ops require confirmation
3. **Audit everything** - All actions produce AuditEntry
4. **Zeroize secrets** - Implement `Zeroize` + `ZeroizeOnDrop`
5. **No unsafe without review** - Requires `// SAFETY:` comment
6. **Seccomp compliance** - Update allowlist for new syscalls
7. **Network allowlist** - Update config.toml for new destinations
8. **Reproducible builds** - Commit Cargo.lock
9. **No execve** - Never spawn user-supplied commands
10. **Prompt firewall** - All AI telemetry filtered

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: security@shadowline.dev

Include:
- Description of vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if known)

We will respond within 48 hours.

## Skill Development

### Creating a New Skill

1. Create `.agents/skills/<skill-name>.md`
2. Follow the template in existing skills
3. Include workflow, parameters, and examples
4. Reference from AGENTS.md if needed

### Skill Manifest Structure

```markdown
# Skill: skill-name

## Description
Brief description of what the skill does.

## When to Use
Context for when to invoke this skill.

## Workflow
1. Step one
2. Step two
3. Step three

## Example Invocation
```bash
shadowline command args
```

## Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| name | type | Yes/No | Description |

## Related Skills
- other-skill - Why related
```

## Questions?

- Check [AGENTS.md](AGENTS.md) for detailed orchestration
- Open a discussion for architecture questions
- Join our community Discord (coming soon)

Thank you for contributing to Shadowline!
