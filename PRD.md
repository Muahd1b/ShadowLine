# Shadowline — Product Requirements Document

**Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft
**Author:** Jonas Knöppel

---

## 1. Executive Summary

Shadowline is a single-binary, Rust-based TUI application that unifies attack velocity forecasting, vendor breach kill-switching, supply chain scanning, and agentic security reasoning into one terminal interface. Powered by Codex as the AI reasoning layer. Extensible via a plugin system. Usable as a skill by other tools (OpenCode, Codex, Cursor, Claude Code).

Shadowline solves the critical gap between attacker speed and defender response. Unit42's 2026 Global IR Report shows the fastest quartile of intrusions reach data exfiltration in 72 minutes (down from 285 in 2024). SOC analysts need one tool that tells them how much time they have, what to kill, and where the blast radius reaches — in a single pane.

---

## 2. Problem Statement

### 2.1 Market Problem

Modern incident response is fragmented across too many tools:

| Problem | Current Tools | Gap |
|---------|--------------|-----|
| Attack velocity | No tool forecasts time-to-exfiltration per incident | Defenders don't know urgency |
| Vendor breach response | Manual: search 10+ SaaS admin panels, revoke tokens one by one | Too slow for 72-min windows |
| Supply chain scanning | Socket, Snyk — scan packages but don't map blast radius | No connection to infra impact |
| Agent skill security | Snyk Skill Inspector — single registry only | No unified trust layer |
| Integration visibility | Obsidian, Grip — monitoring, not response | No kill switch |

### 2.2 User Problem

SOC analyst receives alert at 14:23. Current workflow:

1. Check SIEM (5 min)
2. Check EDR (5 min)
3. Google vendor name + "breach" (5 min)
4. Search Salesforce admin for OAuth connections (10 min)
5. Search Slack, GitHub, Google Workspace for same vendor (15 min)
6. Manually revoke tokens one by one (20 min)
7. Check if compromised packages exist in codebase (switch to Socket/Snyk) (10 min)

**Total: ~70 minutes. Exfiltration happened at minute 72. They made it by 2 minutes — if at all.**

Shadowline workflow:

1. `shadowline clock incident:4721` → 43 minutes remaining
2. `shadowline kill vendor:drift` → 6 tokens revoked in 3 seconds
3. `shadowline scan ./project --with-blast-radius` → 2 malicious packages found, blast radius mapped

**Total: ~3 minutes. 40 minutes of buffer remaining.**

### 2.3 Business Problem

- Median ransom demand: $1.5M (Unit42 2026)
- Median payment: $500K
- Organizations that pay have 61% negotiation reduction
- But organizations that respond faster pay less or not at all
- Every minute of faster response = reduced financial exposure

---

## 3. Goals and Non-Goals

### 3.1 Goals

| ID | Goal | Success Metric |
|----|------|---------------|
| G1 | Reduce mean-time-to-vendor-severance from hours to <60 seconds | MTTS < 60s in drill tests |
| G2 | Provide real-time attack velocity estimates with >70% accuracy | Post-incident prediction accuracy |
| G3 | Discover 100% of SaaS integrations per connected platform | Integration coverage ratio |
| G4 | Detect malicious packages in scanned repos | True positive rate > 95% |
| G5 | Detect prompt injection in AI agent skills | True positive rate > 90% |
| G6 | Operate as a single binary with zero external runtime dependencies | Binary size < 50MB, startup < 100ms |
| G7 | Function in air-gapped environments | Full velocity + kill capability offline |
| G8 | Be usable as a skill by OpenCode/Codex | Skill integration working |

### 3.2 Non-Goals

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | Replace SIEM/EDR/XDR | Shadowline consumes their telemetry, doesn't replace them |
| NG2 | Provide managed detection and response (MDR) | Tool, not service (v1) |
| NG3 | Scan proprietary/binary-only applications | Covered by GhostSurface concept (future) |
| NG4 | Support Windows as primary platform | v1: macOS + Linux. Windows: v2 |
| NG5 | Provide browser-based UI | Terminal-native is a core design principle |

---

## 4. Target Users

### 4.1 Primary: SOC Analyst

- Works in tmux/zellij panes
- Needs answers in seconds, not minutes
- Keyboard-driven, no mouse
- Monitors SIEM, EDR, Slack simultaneously
- Pain point: context switching between tools during incidents

### 4.2 Secondary: Security Engineer / DevSecOps

- Runs security scans in CI/CD
- Audits dependencies before deployment
- Manages SaaS integrations and access controls
- Pain point: no unified tool for supply chain + incident response

### 4.3 Tertiary: CISO / Security Leadership

- Needs velocity metrics for board reporting
- Wants drill scores to measure team readiness
- Needs blast radius reports for risk assessment
- Pain point: no quantifiable metrics for "how fast can we respond?"

---

## 5. System Architecture

### 5.1 High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        SHADOWLINE                             │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  TUI Layer (Rust: ratatui)                             │  │
│  │  Dashboard • Command prompt • Live panels              │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │                                 │
│  ┌──────────────────────────┴─────────────────────────────┐  │
│  │  Core Engine (Rust)                                    │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ Velocity │ │ Kill     │ │ Integra- │ │ Blast    │  │  │
│  │  │ Clock    │ │ Switch   │ │ tion     │ │ Radius   │  │  │
│  │  │          │ │          │ │ Graph    │ │ Calc     │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │                                 │
│  ┌──────────────────────────┴─────────────────────────────┐  │
│  │  AI Agent Layer (Codex API / Local Model)              │  │
│  │  Prompt firewall → Codex reasoning → JSON plan output  │  │
│  │  Proposes only. Never executes directly.               │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │                                 │
│  ┌──────────────────────────┴─────────────────────────────┐  │
│  │  Action Validator (Rust)                               │  │
│  │  Policy engine • Capability check • Blast radius cap   │  │
│  │  Rate limiter • Human confirmation gate                │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │                                 │
│  ┌──────────────────────────┴─────────────────────────────┐  │
│  │  Execution Engine (Rust)                               │  │
│  │  HTTP client • OAuth revoker • Webhook disabler        │  │
│  │  Audit logger                                          │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │                                 │
│  ┌──────────────────────────┴─────────────────────────────┐  │
│  │  Plugin Host (Rust)                                    │  │
│  │  Supply Chain Scanner • Secret Scanner • Compliance    │  │
│  │  Community skills • Skill sandbox                      │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │                                 │
│  ┌──────────────────────────┴─────────────────────────────┐  │
│  │  Data Layer                                            │  │
│  │  SQLite (graph, velocity, audit) • OS Keychain (creds) │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Rust 2024 edition | Memory safety, performance, single binary |
| TUI | ratatui + crossterm | Mature, performant terminal UI framework |
| Database | SQLite (rusqlite) | Local, fast, single-file, zero infra |
| HTTP | reqwest + rustls | TLS 1.3, async HTTP client |
| Crypto | ring, zeroize | AEAD encryption, secure memory wipe |
| Serialization | serde + serde_json | JSON plan interchange with Codex |
| CLI | clap | Command parsing, subcommands |
| Keychain | keyring-rs | OS-native secret storage |
| AI | OpenAI Codex API (primary), local model (fallback) | Agentic reasoning |

### 5.3 Data Models

```rust
// Integration Graph
struct Vendor {
    id: String,
    name: String,
    vendor_type: VendorType,      // SaaS, RMM, MDM, AI Agent, etc.
    risk_score: f64,              // 0.0 - 1.0
    connections: Vec<Connection>,
    last_scanned: DateTime<Utc>,
}

struct Connection {
    id: String,
    platform: Platform,           // Salesforce, GitHub, Slack, etc.
    connection_type: ConnectionType, // OAuth, API Key, Webhook, Agent
    permissions: Vec<Permission>,
    token_ref: TokenRef,          // UUID pointer to OS keychain
    status: ConnectionStatus,     // Active, Dormant, Revoked
    discovered_at: DateTime<Utc>,
    last_used: Option<DateTime<Utc>>,
}

// Velocity Model
struct Incident {
    id: u64,
    status: IncidentStatus,       // Active, Monitoring, Contained, Closed
    created_at: DateTime<Utc>,
    ttps_observed: Vec<Technique>,
    current_stage: AttackStage,
    velocity_estimate: VelocityEstimate,
    blast_radius: BlastRadius,
}

struct VelocityEstimate {
    minutes_remaining: f64,
    confidence: f64,              // 0.0 - 1.0
    range_low: f64,
    range_high: f64,
    archetype: VelocityArchetype, // Blitz, Standard, APT Slow, Opportunistic
    similar_incidents: Vec<IncidentRef>,
}

struct BlastRadius {
    systems_affected: u32,
    data_records_at_risk: u64,
    teams_affected: Vec<String>,
    downstream_vendors: Vec<VendorRef>,
}

// Audit Log
struct AuditEntry {
    sequence: u64,
    timestamp: DateTime<Utc>,
    actor: Identity,
    action: AuditAction,
    target: Target,
    result: ActionResult,
    reasoning: Option<String>,    // Codex explanation
    prev_hash: [u8; 32],
    hash: [u8; 32],
}

// Skill Plugin
struct Skill {
    id: String,
    name: String,
    version: String,
    author: String,
    permissions: SkillPermissions,
    resource_limits: ResourceLimits,
    trust_score: f64,
    triggers: Vec<String>,
}

struct SkillPermissions {
    read_filesystem: bool,
    write_filesystem: bool,
    read_network: bool,
    write_network: bool,
    execute_api: bool,
    execute_shell: bool,
}
```

### 5.4 Security Architecture

7-layer defense model. Each layer assumes the layer above is compromised.

```
Layer 1: Codex Sandbox
  - Prompt firewall strips injection patterns from telemetry
  - Codex produces structured JSON plans only
  - Multi-model consensus for destructive actions
  - Rate-limited agent calls per incident

Layer 2: Command Sandbox
  - Capability-based authorization per command
  - Blast radius cap: max systems per single kill
  - Rate limiter: max kills per hour
  - Human confirmation for all destructive operations

Layer 3: Credential Vault
  - Tokens stored in OS keychain (macOS Keychain, Linux SecretService)
  - SQLite contains UUID pointers only, never token values
  - Just-in-time fetch: token retrieved only when needed
  - Zeroize: token overwritten in memory immediately after use

Layer 4: Agent Harness (Self-Evolving)
  - Training data classified: internal (trusted), partner (verified), community (sanitized)
  - Statistical anomaly detection on velocity model inputs
  - Weighted model updates: community data weight = 0.1
  - Model validation gate: accuracy must exceed threshold before deploy
  - Human approval required for model updates
  - Append-only model hash log for rollback

Layer 5: Binary Supply Chain
  - Reproducible builds: `cargo build --release --locked`
  - SLSA Level 3 provenance
  - Sigstore keyless signing
  - Transparency log (Rekor)
  - No auto-update: explicit consent required

Layer 6: Audit Log
  - Append-only: no delete/modify operations exist
  - Cryptographically chained: SHA-256 hash chain
  - Replicated to remote immutable store (S3 Object Lock)
  - Verification tool validates entire chain

Layer 7: Runtime
  - Seccomp profiles (Linux): allow read/write/connect, deny execve/mount/ptrace
  - Memory locking: mlock sensitive buffers
  - Network allowlist: only known SaaS API endpoints
  - Dedicated OS user: `shadowline` with minimal filesystem permissions
```

---

## 6. Feature Requirements

### 6.1 Velocity Clock (P0 — MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| VC-01 | Display real-time estimated time-to-exfiltration for active incidents | P0 |
| VC-02 | Update estimate as new TTPs are observed during incident | P0 |
| VC-03 | Show confidence interval and range | P0 |
| VC-04 | Classify attack archetype (Blitz, Standard, APT Slow, Opportunistic) | P0 |
| VC-05 | List time-sensitized recommended actions ranked by urgency | P0 |
| VC-06 | Show similar historical incidents with actual exfil times | P1 |
| VC-07 | Live-updating countdown display in TUI | P0 |
| VC-08 | Support `--json` output for SIEM/SOAR integration | P1 |
| VC-09 | Contribute anonymized incident data to improve model | P2 |
| VC-10 | Executive velocity reports (detection-to-containment metrics) | P2 |

### 6.2 Kill Switch (P0 — MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| KS-01 | Kill all OAuth tokens, API keys, webhooks for a named vendor | P0 |
| KS-02 | Show full blast radius before execution | P0 |
| KS-03 | Execute kill chain in <3 seconds across all platforms | P0 |
| KS-04 | Human confirmation required before destructive execution | P0 |
| KS-05 | Generate audit log entry for every kill action | P0 |
| KS-06 | Notify affected teams after kill execution | P1 |
| KS-07 | Support dry-run mode (`--dry-run`) | P0 |
| KS-08 | Support `--json` output | P1 |
| KS-09 | Kill multiple vendors in single command | P2 |
| KS-10 | Threat intelligence auto-trigger on vendor breach announcement | P2 |

### 6.3 Integration Graph (P0 — MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| IG-01 | Discover all OAuth apps across connected SaaS platforms | P0 |
| IG-02 | Discover all API keys and their permissions | P0 |
| IG-03 | Discover all webhooks (inbound/outbound) | P0 |
| IG-04 | Discover vendor agents and service accounts | P0 |
| IG-05 | Show data flow between connected systems | P0 |
| IG-06 | Calculate blast radius for any vendor or connection | P0 |
| IG-07 | Auto-refresh graph on schedule (configurable interval) | P1 |
| IG-08 | Support 20+ SaaS platform connectors at launch | P1 |
| IG-09 | Export graph as JSON for external tooling | P1 |
| IG-10 | Detect dormant/unused integrations | P1 |

### 6.4 Supply Chain Scanner (P1 — Post-MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| SC-01 | Scan npm, PyPI, Go, Rust, PHP, Maven dependencies | P1 |
| SC-02 | Detect malicious packages (data exfil, C2 beacons) | P1 |
| SC-03 | Detect typosquatting | P1 |
| SC-04 | Detect dependency confusion | P1 |
| SC-05 | Scan AI agent skill configs for prompt injection | P1 |
| SC-06 | Cross-reference scan results with integration graph for blast radius | P1 |
| SC-07 | Support `--json` output for CI/CD gates | P1 |
| SC-08 | Support `--fail-on` flag for CI/CD (exit non-zero on findings) | P1 |
| SC-09 | Transitive dependency tree visualization | P2 |
| SC-10 | License compliance checking | P2 |

### 6.5 Severing Drills (P1 — Post-MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| SD-01 | Simulate vendor compromise and execute dry-run kill | P1 |
| SD-02 | Measure time-to-full-severance | P1 |
| SD-03 | Detect missed integrations not in graph | P1 |
| SD-04 | Generate drill score (0-100) | P1 |
| SD-05 | Schedule recurring drills | P2 |
| SD-06 | Track drill scores over time for trend analysis | P2 |

### 6.6 Plugin System (P1 — Post-MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| PS-01 | Install, enable, disable, remove skills | P1 |
| PS-02 | Skill sandboxing with per-skill permission model | P1 |
| PS-03 | Skill manifest (TOML) defining triggers and permissions | P1 |
| PS-04 | Community skill registry | P2 |
| PS-05 | Skill trust scoring based on author, installations, code review | P2 |
| PS-06 | Export Shadowline as an OpenCode/Codex skill | P1 |

### 6.7 Audit System (P0 — MVP)

| Req ID | Requirement | Priority |
|--------|-------------|----------|
| AU-01 | Append-only log with cryptographic chaining | P0 |
| AU-02 | Log all destructive actions with actor, target, result, reasoning | P0 |
| AU-03 | Replicate audit log to remote immutable store | P1 |
| AU-04 | Verify audit log integrity | P0 |
| AU-05 | Search/filter audit log | P1 |

---

## 7. Platform Connectors (Launch Set)

### 7.1 Tier 1 — MVP Connectors

| Platform | OAuth | API Keys | Webhooks | Priority |
|----------|-------|----------|----------|----------|
| Salesforce | ✓ | ✓ | ✓ | P0 |
| GitHub | ✓ | ✓ | ✓ | P0 |
| Slack | ✓ | ✓ | ✓ | P0 |
| Google Workspace | ✓ | ✓ | ✓ | P0 |
| Microsoft 365 | ✓ | ✓ | ✓ | P0 |
| Okta | ✓ | ✓ | - | P0 |
| AWS IAM | - | ✓ | - | P0 |

### 7.2 Tier 2 — Post-MVP Connectors

| Platform | Priority |
|----------|----------|
| Azure AD | P1 |
| GCP IAM | P1 |
| Jira / Confluence | P1 |
| Zendesk | P1 |
| HubSpot | P1 |
| Datadog | P1 |
| PagerDuty | P1 |
| 1Password Business | P2 |
| HashiCorp Vault | P2 |
| CrowdStrike Falcon | P2 |
| SentinelOne | P2 |

---

## 8. User Interface Specification

### 8.1 TUI Layout (4-Pane Default)

```
┌──────────────────────── SHADOWLINE ────────────────────────┐
│                                                             │
│  ┌─ INCIDENTS ────────┐  ┌─ VELOCITY CLOCK ──────────────┐│
│  │                     │  │                               ││
│  │  #4721 ACTIVE       │  │  ████████████░░░  43 MIN     ││
│  │  Stage: Lat.Movement│  │  Confidence: 78%             ││
│  │  MTTE: ~43min       │  │  Range: 28-67 min            ││
│  │  Blast: 5 systems   │  │  Archetype: Blitz            ││
│  │                     │  │                               ││
│  │  #4719 MONITORING   │  │  Actions:                    ││
│  │  Stage: Discovery   │  │  [NOW] Isolate 10.0.3.47     ││
│  │  MTTE: ~3.2hr       │  │  [NOW] Revoke jsmith tokens  ││
│  │                     │  │  [5m] Block C2 IP            ││
│  └─────────────────────┘  └───────────────────────────────┘│
│                                                             │
│  ┌─ VENDOR GRAPH ──────┐  ┌─ ACTIVITY LOG ────────────────┐│
│  │                     │  │                               ││
│  │  47 vendors mapped  │  │  ▶ 14:23 Login from 10.0.3.47││
│  │  12 active          │  │  ▶ 14:31 T1087 Account Disc.  ││
│  │  ⚠ 3 high-risk      │  │  ▶ 14:38 T1003 Cred Dump     ││
│  │                     │  │  ▶ 14:42 T1021 Lat. Movement  ││
│  │  > drill --next     │  │                               ││
│  └─────────────────────┘  └───────────────────────────────┘│
│                                                             │
│  Commands: [k]kill [s]scan [c]clock [g]graph [d]drill [q]  │
│  > _                                                        │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `clock <incident>` | Show velocity estimate | `clock incident:4721` |
| `clock <incident> --watch` | Live-updating velocity | `clock incident:4721 --watch` |
| `kill <vendor>` | Execute kill chain | `kill vendor:drift` |
| `kill <vendor> --dry-run` | Show kill plan without executing | `kill vendor:drift --dry-run` |
| `kill <vendor> --json` | Output kill plan as JSON | `kill vendor:drift --json` |
| `graph` | Show integration graph | `graph` |
| `graph vendor:<name>` | Show connections for specific vendor | `graph vendor:drift` |
| `blast <vendor>` | Show blast radius | `blast vendor:drift` |
| `scan <path>` | Scan repo for compromised packages | `scan ./my-project` |
| `scan --agents <file>` | Scan agent skill config | `scan --agents config.yaml` |
| `scan <path> --with-blast-radius` | Scan + map blast radius | `scan . --with-blast-radius` |
| `drill --simulate` | Run severing drill | `drill --simulate vendor:random` |
| `drill --history` | Show drill scores over time | `drill --history` |
| `audit verify` | Verify audit log integrity | `audit verify` |
| `audit show` | Show recent audit entries | `audit show --last 20` |
| `skills list` | List installed plugins | `skills list` |
| `skills install <name>` | Install a plugin | `skills install community/sbom` |
| `init` | First-run setup | `init` |
| `update` | Check for updates (manual) | `update` |

### 8.3 CLI Mode (Non-Interactive)

All TUI commands work as pure CLI for scripting/CI:

```bash
# CI/CD gate
shadowline scan . --json --fail-on malicious,confusion

# SOAR integration
shadowline clock incident:4721 --json | jq '.minutes_remaining'

# Automated kill (with confirmation bypass for SOAR)
SHADOWLINE_AUTO_CONFIRM=1 shadowline kill vendor:drift --json
```

---

## 9. Data Storage

### 9.1 Local Storage

```
~/.shadowline/
├── config.toml              # User configuration
├── data.db                  # SQLite: integration graph, velocity history, audit
├── audit.log                # Replicated audit log (append-only)
├── credentials/             # DEPRECATED — use OS keychain
├── skills/
│   ├── supply-chain-scanner/
│   │   ├── SKILL.toml
│   │   └── src/
│   ├── secret-scanner/
│   │   ├── SKILL.toml
│   │   └── src/
│   └── community/
│       └── ...
└── models/
    └── velocity-v3.bin      # Local velocity model (if using local inference)
```

### 9.2 Credential Storage

- **macOS**: Keychain Access (`security` framework)
- **Linux**: SecretService (GNOME Keyring / KWallet)
- **Fallback**: AES-256-GCM encrypted file with Argon2id key derivation

Tokens never stored in SQLite. SQLite contains UUID pointers only.

### 9.3 Audit Log Replication

- **Local**: `~/.shadowline/audit.log` (append-only file)
- **Remote**: S3-compatible object store with Object Lock enabled
- **Config**: `config.toml` specifies remote endpoint

---

## 10. Configuration

```toml
# ~/.shadowline/config.toml

[general]
theme = "dark"
refresh_interval_seconds = 5
default_panes = 4

[codex]
provider = "openai"             # openai | local
model = "codex-mini-latest"
api_key_env = "SHADOWLINE_CODEX_KEY"  # read from env var, never stored in config
max_tokens = 4096
timeout_seconds = 30
multi_model_consensus = false   # enable for enterprise
consensus_models = ["codex-mini-latest", "claude-sonnet-4-20250514"]

[security]
auto_confirm = false            # require human confirmation for kills
max_single_kill_radius = 20     # max systems in one kill action
max_kills_per_hour = 10
blast_radius_cap = true
seccomp_enabled = true          # Linux only
memory_lock = true
network_allowlist = [
    "api.salesforce.com:443",
    "slack.com:443",
    "api.github.com:443",
    "accounts.google.com:443",
    "graph.microsoft.com:443",
]

[velocity]
model_source = "remote"         # remote (API) | local (binary model)
data_contribution = true         # contribute anonymized incident data
confidence_threshold = 0.5      # minimum confidence to show estimate

[audit]
remote_replication = false
remote_endpoint = "s3://shadowline-audit-bucket"
remote_region = "eu-west-1"

[connectors]
salesforce = { enabled = true, auto_refresh_minutes = 60 }
github = { enabled = true, auto_refresh_minutes = 30 }
slack = { enabled = true, auto_refresh_minutes = 60 }
google_workspace = { enabled = true, auto_refresh_minutes = 60 }
microsoft_365 = { enabled = true, auto_refresh_minutes = 60 }
okta = { enabled = true, auto_refresh_minutes = 30 }
aws = { enabled = true, auto_refresh_minutes = 60 }

[skills]
auto_update = false             # never auto-update skills
sandbox_enabled = true
community_registry = "https://registry.shadowline.dev"
```

---

## 11. Performance Requirements

| Metric | Requirement |
|--------|-------------|
| Binary startup time | < 100ms |
| Integration graph scan (1K nodes) | < 2 seconds |
| Kill chain execution (single vendor) | < 3 seconds |
| Velocity estimate generation | < 5 seconds |
| Package scan (1000 dependencies) | < 30 seconds |
| Memory footprint (idle) | < 50MB |
| Memory footprint (active scan) | < 512MB |
| Binary size | < 50MB |
| SQLite query latency | < 10ms |

---

## 12. Security Requirements

| Req ID | Requirement |
|--------|-------------|
| SEC-01 | All destructive operations require human confirmation (unless `SHADOWLINE_AUTO_CONFIRM=1`) |
| SEC-02 | Codex agent cannot execute API calls directly |
| SEC-03 | Tokens stored in OS keychain, never in SQLite or config files |
| SEC-04 | Tokens zeroized from memory immediately after use |
| SEC-05 | All destructive actions logged to append-only, cryptographically chained audit log |
| SEC-06 | Binary built reproducibly with SLSA Level 3 provenance |
| SEC-07 | Binary signed with Sigstore |
| SEC-08 | No auto-update mechanism; updates require explicit consent |
| SEC-09 | Seccomp profiles enforced on Linux |
| SEC-10 | Outbound network restricted to allowlisted endpoints |
| SEC-11 | Skills sandboxed with per-skill permission model |
| SEC-12 | Prompt firewall on all telemetry before Codex ingestion |
| SEC-13 | Rate limiting on all destructive operations |
| SEC-14 | Blast radius cap enforced per policy |

---

## 13. Distribution and Installation

| Channel | Method | Target |
|---------|--------|--------|
| Homebrew | `brew install shadowline` | macOS primary |
| Curl | `curl -sSL https://shadowline.dev/install \| sh` | macOS + Linux |
| Cargo | `cargo install shadowline` | Rust developers |
| Docker | `docker run -it shadowline` | CI/CD, containers |
| Arch (AUR) | `pacman -S shadowline` | Arch Linux |
| Debian/Ubuntu | `.deb` package | Debian-based |
| Fedora/RHEL | `.rpm` package | Red Hat-based |

---

## 14. Revenue Model

| Tier | Price | Includes |
|------|-------|----------|
| **Free** | $0 | Velocity clock (read-only), 3 SaaS integrations, supply chain scanner (community), CLI mode |
| **Pro** | $X/seat/month | Full kill switch, Codex brain, unlimited connectors, drills, all core skills, priority support |
| **Enterprise** | Custom | On-prem Codex, air-gapped build, custom connectors, SSO, audit export, SLA, dedicated support |
| **Incident** | Pay-per-use | Per-minute Codex compute during active incidents. Cyber insurer can cover as add-on. |

---

## 15. Success Metrics

| Metric | Target (6 months post-launch) |
|--------|-------------------------------|
| Active installations | 1,000 |
| SOC teams using drills monthly | 200 |
| Mean drill score improvement | +15 points over baseline |
| Avg. kill execution time (measured) | < 3 seconds |
| Velocity prediction accuracy | > 70% |
| Malicious package detection rate | > 95% |
| Agent skill prompt injection detection | > 90% |
| User satisfaction (terminal tool comparison) | Top 3 alongside k9s/lazygit |

---

## 16. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| Codex prompt injection via telemetry | Critical | High | Prompt firewall, propose-only model, multi-model consensus |
| Supply chain attack on Shadowline binary | Critical | Medium | Reproducible builds, SLSA L3, Sigstore signing |
| Token theft from memory | High | Low | OS keychain, JIT fetch, zeroize, memory locking |
| False positive kills (unwarranted vendor severance) | High | Medium | Blast radius preview, dry-run mode, human confirmation |
| SaaS API changes break connectors | Medium | High | Connector test suite, CI against sandbox APIs, rapid patch cycle |
| Velocity model inaccuracy causes panic or complacency | Medium | Medium | Confidence intervals, archetype classification, model validation gate |
| Competition from CrowdStrike/SentinelOne adding similar features | Medium | Medium | Terminal-native focus, single-binary simplicity, air-gap capability |

---

## 17. Milestones

| Phase | Timeline | Deliverable |
|-------|----------|-------------|
| **Alpha** | Month 1-3 | Core engine, TUI, 3 connectors (GitHub, Slack, Salesforce), velocity clock (basic), kill switch (single vendor), SQLite store, OS keychain |
| **Beta** | Month 4-6 | All 7 MVP connectors, full velocity model, blast radius calculator, audit system, prompt firewall, seccomp profiles |
| **v1.0** | Month 7-9 | Supply chain scanner, agent skill scanner, severing drills, plugin system, CI/CD integration, Homebrew/Cargo distribution |
| **v1.5** | Month 10-12 | Community skill registry, Shadowline as OpenCode skill, executive velocity reports, threat intel auto-trigger, 10 additional connectors |

---

## 18. Open Questions

| ID | Question | Status |
|----|----------|--------|
| OQ-1 | Should velocity model training data be contributed to a shared pool or kept per-org? | Open |
| OQ-2 | Which local model to use for air-gapped velocity estimation (Qwen, Llama, distilled)? | Open |
| OQ-3 | Should we partner with cyber insurers directly or let them integrate via API? | Open |
| OQ-4 | Do we build our own package registry intelligence or integrate Socket's API? | Open |
| OQ-5 | Windows support timeline — v1.x or v2? | Deferred |

---

*End of PRD.*
