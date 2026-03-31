# Skill: blast-radius

## Description
Calculate the blast radius for a compromised vendor. Shows downstream impact including affected systems, teams, and data records.

## When to Use
- After vendor breach notification
- Before kill switch execution (understand impact)
- During incident triage
- For compliance impact assessments

## Workflow

1. **Analyze Vendor Access**
   - Query vendor connections
   - Map accessible resources
   - Identify data stores accessed

2. **Calculate Impact**
   - Count affected systems
   - Enumerate data records at risk
   - Identify downstream vendor dependencies

3. **Generate Risk Assessment**
   - Assign risk level (LOW/MEDIUM/HIGH/CRITICAL)
   - Calculate blast radius score
   - Prioritize response actions

4. **Report**
   - Display in TUI Status pane
   - Export for stakeholder communication
   - Update incident ticket

## Example Invocation

```bash
shadowline blast vendor:drift
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vendor` | string | Yes | Vendor to analyze |

## Output

- Systems affected count
- Data records at risk
- Teams impacted
- Downstream vendor dependencies
- Risk level assessment

## Related Skills

- kill-switch - Contain the blast
- integration-graph - View connections
- velocity-clock - Time to full impact
