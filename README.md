# Shadowline

The agentic incident response engine. Velocity clock, kill switch, supply chain scanner — one binary, one terminal.

## What It Does

Shadowline unifies attack velocity forecasting, vendor breach kill-switching, supply chain scanning, and agentic security reasoning into a single Rust-based TUI application.

| Feature | Description |
|---------|-------------|
| **Velocity Clock** | Predicts time-to-exfiltration during active incidents based on observed TTPs |
| **Kill Switch** | One-command severance of all vendor integrations across your SaaS stack |
| **Integration Graph** | Maps every OAuth app, API key, webhook, and vendor agent |
| **Blast Radius** | Shows downstream impact of any vendor compromise |
| **Supply Chain Scanner** | Detects malicious npm packages, typosquats, dependency confusion |
| **Agent Skill Scanner** | Finds prompt injection and excessive permissions in AI agent configs |
| **Severing Drills** | Simulated vendor breach exercises to measure response speed |
| **Audit Log** | Cryptographically chained, append-only record of all actions |

## The Problem

Unit42's 2026 Global IR Report shows:
- Attacks reach data exfiltration in **72 minutes** (fastest quartile, down from 285 in 2024)
- **39% of C2 channels** abuse trusted vendor tools
- **87% of incidents** span multiple attack surfaces
- SOC analysts switch between 5+ tools during an incident

Shadowline is the single pane that replaces the tool-switching.

## Quick Start

```bash
git clone https://github.com/Muahd1b/ShadowLine.git
cd ShadowLine
cargo build
```

### Interactive TUI

```bash
cargo run -- tui
```

Layout:
- **Top 2/3**: 4 dashboard panes (Commands, Status, Velocity, Scan)
- **Bottom 1/3**: Command output (scrollable with up/down arrows)
- **Bottom line**: Command input

### CLI Mode

```bash
# Velocity clock
cargo run -- clock incident:4721

# Kill switch (dry run)
cargo run -- kill vendor:drift --dry-run

# Integration graph
cargo run -- graph

# Blast radius
cargo run -- blast vendor:drift

# Scan for compromised packages
cargo run -- scan .

# Severing drill
cargo run -- drill --simulate

# Audit log verification
cargo run -- audit --verify

# First-run setup
cargo run -- init
```

## Commands

| Command | Description |
|---------|-------------|
| `clock <incident>` | Show velocity estimate for an active incident |
| `kill <vendor>` | Execute kill chain for a vendor |
| `kill <vendor> --dry-run` | Preview kill chain without executing |
| `graph` | Show integration graph |
| `graph --vendor <name>` | Filter graph by vendor |
| `blast <vendor>` | Show blast radius for a vendor |
| `scan [path]` | Scan for compromised packages |
| `scan [path] --json` | Scan output as JSON (for CI/CD) |
| `drill --simulate` | Run a severing drill |
| `drill --history` | Show drill score history |
| `audit --verify` | Verify audit log integrity |
| `audit --show` | Show recent audit entries |
| `skills list` | List installed skills/plugins |
| `init` | First-run setup (creates ~/.shadowline/) |
| `tui` | Launch interactive TUI |
| `help` | Show all commands |

## Architecture

```
TUI (ratatui) --> CLI (clap) --> Core Engine
                                    |
                    +---------------+---------------+
                    |               |               |
              Velocity Clock   Kill Switch    Integration Graph
                    |               |               |
                    +-------+-------+-------+-------+
                            |               |
                      SQLite Store    Codex AI (propose-only)
                            |               |
                      OS Keychain     Action Validator --> Executor
```

**Principle**: Codex proposes. Rust disposes. The AI can suggest actions but never execute directly.

## Security Model

7 layers of defense, each assuming the layer above is compromised:

1. **Codex sandbox** — Prompt firewall, propose-only, multi-model consensus
2. **Command sandbox** — Capability-based auth, blast radius caps, rate limiting
3. **Credential vault** — OS keychain storage, JIT fetch, zeroize on drop
4. **Agent harness** — Trusted data pipeline, anomaly detection, human approval for updates
5. **Binary supply chain** — Reproducible builds, SLSA Level 3, Sigstore signing
6. **Audit log** — Append-only, cryptographically chained, replicated
7. **Runtime** — Seccomp profiles, memory locking, network allowlisting

## Project Structure

```
src/
├── main.rs              # CLI + TUI entry point
├── lib.rs               # Library root
├── core/                # Velocity clock, kill switch, graph, blast radius
├── data/                # SQLite schema and migrations
├── security/            # Audit log, credential vault, prompt firewall
├── connectors/          # GitHub, Salesforce, Slack connectors
├── scanner/             # npm + agent skill scanning
├── ai/                  # Codex client and plan parser
├── plugins/             # Skill manifest, executor, registry
└── tui/                 # Dashboard and command parser
```

## Development

```bash
# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Build release
cargo build --release
```

### Test Coverage

29 passing tests covering:
- Velocity estimation (archetype classification, stage progression)
- Kill switch (plan generation, dry-run execution)
- Integration graph (vendor management, risk filtering)
- Blast radius calculation
- Scanner (npm malicious packages, typosquats, agent skill injection)
- Prompt firewall (injection detection, sanitization)
- Audit log (chain integrity, tamper detection)
- Plugin manifest parsing
- Command parsing

## Status

v0.1.0 — Alpha. Core engines working. Real SaaS connectors require API tokens.

| Feature | Status |
|---------|--------|
| Velocity clock | Working |
| Kill switch | Working (demo data) |
| Package scanner | Working |
| Integration graph | Demo data |
| Blast radius | Working |
| Drill simulator | Demo |
| TUI | Working |
| Real SaaS connectors | Stubbed (needs API tokens) |

## Setting Up Real Connectors

```bash
export SHADOWLINE_GITHUB_TOKEN=ghp_...
export SHADOWLINE_SALESFORCE_TOKEN=...
export SHADOWLINE_SLACK_TOKEN=xoxb-...
```

## License

MIT
