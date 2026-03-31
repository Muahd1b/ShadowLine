# Security Model

Shadowline implements a defense-in-depth security model with seven distinct layers of protection. This document describes the security architecture, threat model, and operational security practices.

## Table of Contents

- [7-Layer Defense Architecture](#7-layer-defense-architecture)
- [Threat Model](#threat-model)
- [Security Features](#security-features)
- [Operational Security](#operational-security)
- [Incident Response](#incident-response)
- [Vulnerability Disclosure](#vulnerability-disclosure)
- [Compliance](#compliance)

## 7-Layer Defense Architecture

Shadowline's security model follows the principle of defense in depth. Each layer provides independent protection, ensuring that no single failure compromises the entire system.

### Layer 1: Prompt Firewall

**Purpose:** Filter and sanitize all AI-bound telemetry

**Implementation:**
- Preprocesses all prompts sent to Codex AI
- Removes sensitive data patterns (PII, credentials, tokens)
- Rate limiting to prevent prompt injection
- Output validation to detect hallucinations
- Audit logging of all AI interactions

**Code:** `src/security/prompt_firewall.rs`

**Key Features:**
- Regex-based PII detection
- Token counting and budget enforcement
- Response schema validation
- Anomaly detection for suspicious prompts

### Layer 2: Capability-Based Authorization

**Purpose:** Fine-grained access control with principle of least privilege

**Implementation:**
- Each operation requires explicit capability grants
- Capabilities are scoped and time-limited
- Role-based access control (RBAC) for multi-user deployments
- Hierarchical permissions (user → team → organization)

**Code:** `src/security/capability.rs`

**Key Features:**
- Capability tokens with expiration
- Scope restrictions (vendor:drift vs vendor:*)
- Audit trail for capability grants
- Automatic revocation on compromise detection

### Layer 3: OS Keychain Integration

**Purpose:** Secure credential storage using OS-native vaults

**Implementation:**
- macOS: Keychain Services
- Linux: Secret Service API (libsecret)
- Windows: Credential Manager / Windows Data Protection
- No credentials in memory longer than necessary
- Automatic credential rotation support

**Code:** `src/security/credential_vault.rs`

**Key Features:**
- Zero-knowledge credential storage
- Automatic key rotation
- Integration with enterprise SSO
- Biometric authentication where available

### Layer 4: Audit Chaining

**Purpose:** Tamper-evident logging of all security-relevant events

**Implementation:**
- Cryptographic hash chain linking entries
- Append-only log structure
- Immutable storage with integrity verification
- Export to SIEM and compliance systems

**Code:** `src/security/audit_log.rs`

**Key Features:**
- SHA-256 hash chain
- Digital signatures on critical events
- Verification command: `shadowline audit --verify`
- Chain continuity checks

### Layer 5: Seccomp Sandboxing

**Purpose:** Restrict available system calls

**Implementation:**
- Whitelist-based syscall filtering
- Capability dropping after initialization
- Sandboxed execution of external skills
- Network isolation for untrusted code

**Code:** `src/sandbox/seccomp.rs`

**Key Features:**
- Minimal syscall surface
- Deny by default policy
- Skill-specific profiles
- No execve() for user-supplied commands

### Layer 6: Memory Safety

**Purpose:** Prevent memory corruption vulnerabilities

**Implementation:**
- Rust's ownership model prevents use-after-free
- `zeroize` crate for secure memory clearing
- No unsafe code without explicit safety comments
- Regular fuzzing of parser components

**Code:** Cross-cutting (all modules)

**Key Features:**
- `ZeroizeOnDrop` for credential structs
- Secure memory allocation for sensitive data
- Constant-time operations for cryptographic code
- AddressSanitizer in CI builds

### Layer 7: Supply Chain Security

**Purpose:** Prevent compromise via dependencies

**Implementation:**
- Dependency pinning (Cargo.lock committed)
- `cargo audit` for vulnerability scanning
- `cargo vet` for manual dependency auditing
- Reproducible builds with locked dependencies

**Code:** `Cargo.toml`, `Cargo.lock`, `.github/workflows/`

**Key Features:**
- Reproducible binary hashes
- Supply chain verification in CI
- Vendor dependency auditing
- Automated security updates

## Threat Model

### Assets

1. **OAuth Tokens** - Access to SaaS platforms
2. **API Keys** - Service account credentials
3. **Audit Logs** - Immutable security event history
4. **Integration Graph** - Topology of vendor connections
5. **User Credentials** - OS keychain entries

### Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| External Attacker | Data exfiltration | Remote, limited access |
| Malicious Insider | Sabotage, data theft | Internal, authenticated |
| Compromised Vendor | Lateral movement | Valid OAuth tokens |
| Supply Chain Attacker | Backdoor injection | Package repository access |
| Nation State | Espionage | Significant resources |

### Attack Scenarios

#### Scenario 1: OAuth Token Compromise
**Threat:** Attacker steals OAuth token from compromised vendor
**Defense:** Kill switch execution (Layer 1, 2, 4)
**Mitigation:** Immediate token revocation with audit trail

#### Scenario 2: Malicious Dependency
**Threat:** Supply chain attack via compromised npm package
**Defense:** Supply chain scanner (Layer 7)
**Mitigation:** Detection before deployment, automated blocking

#### Scenario 3: Prompt Injection
**Threat:** AI manipulation via crafted input
**Defense:** Prompt firewall (Layer 1)
**Mitigation:** Pattern detection, output validation

#### Scenario 4: Credential Dumping
**Threat:** Memory scraping for credential extraction
**Defense:** Memory safety, zeroize (Layer 6)
**Mitigation:** Automatic memory clearing, no long-lived secrets

#### Scenario 5: Privilege Escalation
**Threat:** Lateral movement via capability abuse
**Defense:** Capability-based auth (Layer 2)
**Mitigation:** Scope-limited tokens, automatic revocation

## Security Features

### Kill Switch

Emergency vendor disconnection with guaranteed execution:
- Revokes all OAuth tokens
- Disables webhooks
- Invalidates API keys
- Immutable audit log entry
- Confirmation required (unless auto-confirm enabled)

### Velocity Clock

Attack timeline estimation:
- ML-based prediction of time-to-exfiltration
- MITRE ATT&CK technique progression modeling
- Prioritizes actions by urgency
- Confidence intervals for estimates

### Blast Radius Calculator

Impact assessment for compromised vendors:
- Downstream system enumeration
- Data record counting
- Team impact analysis
- Dependency chain mapping

### Supply Chain Scanner

Malicious package detection:
- Typosquatting detection
- Known-bad package lists
- Metadata anomaly detection
- Agent skill validation

## Operational Security

### Deployment Security

1. **Environment Isolation**
   - Separate production/staging configs
   - No hardcoded credentials
   - Encrypted secrets in transit and at rest

2. **Network Security**
   - TLS 1.3 for all API calls
   - Certificate pinning for critical endpoints
   - Network allowlist enforcement

3. **Runtime Security**
   - Seccomp profiles active
   - No root privileges required
   - Read-only filesystem where possible

### Credential Management

1. **Storage**
   - OS keychain only
   - Encrypted at rest
   - Memory-protected during use

2. **Rotation**
   - Automatic on breach detection
   - Scheduled rotation support
   - Audit trail of all rotations

3. **Access Control**
   - Role-based permissions
   - Time-limited access
   - MFA where supported

### Monitoring & Alerting

1. **Security Events**
   - All actions logged
   - Real-time alerting on anomalies
   - SIEM integration

2. **Audit Trail**
   - Immutable logs
   - Regular integrity verification
   - Compliance reporting

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| P0 (Critical) | Active breach, data exfiltration | 15 minutes |
| P1 (High) | Suspicious activity, potential compromise | 1 hour |
| P2 (Medium) | Security finding requiring remediation | 24 hours |
| P3 (Low) | Hardening recommendation | Next release |

### Response Playbooks

#### P0: Active Breach
1. Execute kill switch for affected vendor(s)
2. Revoke all associated tokens
3. Preserve audit logs
4. Notify security team
5. Activate incident commander
6. Begin forensic timeline reconstruction

#### P1: Suspicious Activity
1. Enable additional logging
2. Isolate suspected connections
3. Analyze blast radius
4. Prepare kill switch for execution
5. Document findings

### Post-Incident

1. Root cause analysis
2. Timeline reconstruction
3. Mitigation effectiveness review
4. Process improvements
5. Knowledge sharing

## Vulnerability Disclosure

### Reporting

**DO NOT** open public issues for security vulnerabilities.

**Email:** security@shadowline.dev

**Include:**
- Description of vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if known)
- Your contact information (optional)

### Response Process

1. Acknowledge receipt within 48 hours
2. Triage within 5 business days
3. Develop fix and coordinate disclosure
4. Credit reporter (if desired)
5. Release security advisory

### Security Advisories

Security advisories are published at:
- GitHub Security Advisories
- security@shadowline.dev mailing list
- In-app notifications (for critical issues)

## Compliance

### Standards Alignment

Shadowline is designed to support compliance with:
- SOC 2 Type II
- ISO 27001
- GDPR (data protection)
- HIPAA (healthcare, via configuration)

### Audit Support

1. **Audit Trail**
   - Immutable logs
   - Integrity verification
   - Export formats (JSON, CSV, SIEM)

2. **Access Controls**
   - Role-based permissions
   - Least privilege enforcement
   - Regular access reviews

3. **Data Protection**
   - Encryption at rest
   - Encryption in transit
   - Secure deletion

### Certifications

- Security controls documented
- Penetration tested (annual)
- Bug bounty program (planned)
- Security certifications (roadmap)

## Security Team

For security questions or concerns:

- **Email:** security@shadowline.dev
- **GPG Key:** [security.asc](https://shadowline.dev/security.asc)
- **Key Fingerprint:** `ABCD 1234 5678 90EF ABCD 1234 5678 90EF ABCD 1234`

---

*This document is versioned. Check [CHANGELOG.md](CHANGELOG.md) for security-related changes.*
