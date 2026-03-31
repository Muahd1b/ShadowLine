# Skill: supply-chain-scan

## Description
Scan project dependencies and agent skills for compromised packages, typosquatting, and malicious code patterns.

## When to Use
- Pre-commit hooks for repositories
- CI/CD pipeline gates
- Periodic security audits
- After CVE announcements

## Workflow

1. **Ecosystem Detection**
   - Identify package managers (npm, PyPI, Cargo, Go)
   - Find agent skill configurations
   - Locate lock files and manifests

2. **Package Analysis**
   - Check against known-bad lists
   - Detect typosquatting patterns
   - Analyze package metadata for anomalies

3. **Skill Scanning**
   - Parse agent skill manifests
   - Check for excessive permissions
   - Validate skill signatures

4. **Report Findings**
   - Categorize by severity (malicious/risky/info)
   - Provide remediation steps
   - Update TUI Scan pane

## Example Invocation

```bash
# Scan current directory
shadowline scan .

# Scan with blast radius analysis
shadowline scan . --with-blast-radius

# Fail on malicious findings
shadowline scan . --fail-on malicious
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | No | Path to scan (default: current directory) |
| `--json` | flag | No | JSON output |
| `--with-blast-radius` | flag | No | Include impact analysis |
| `--fail-on` | string | No | Exit code 1 on severity (malicious/confusion/critical) |

## Output

- Ecosystems detected
- Package counts by status
- Malicious/risky findings with details
- Remediation recommendations

## Related Skills

- blast-radius - Analyze impact of findings
- integration-graph - Find dependency connections
