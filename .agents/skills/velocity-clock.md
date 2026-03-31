# Skill: velocity-clock

## Description
Execute attack velocity estimation for an active incident. Calculates time-to-exfiltration based on observed TTPs and current attack stage.

## When to Use
- When a new incident is detected and velocity estimation is needed
- During incident response to update time estimates
- Before executing kill switches to prioritize actions

## Workflow

1. **Collect Incident Data**
   - Query incident ID from system
   - Gather observed TTPs (MITRE ATT&CK techniques)
   - Determine current attack stage

2. **Run Velocity Analysis**
   - Calculate estimated time to exfiltration
   - Compute confidence interval
   - Identify attacker archetype

3. **Generate Recommendations**
   - Prioritize actions by time sensitivity
   - Suggest immediate containment steps
   - Estimate blast radius progression

4. **Update Dashboard**
   - Display velocity in TUI Velocity pane
   - Show countdown timer
   - Alert on threshold crossings

## Example Invocation

```bash
shadowline clock incident:4721 --watch
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `incident` | string | Yes | Incident identifier (format: incident:ID) |
| `--watch` | flag | No | Enable live-updating mode |
| `--json` | flag | No | Output JSON for automation |

## Output

Velocity estimate with:
- Minutes remaining
- Confidence percentage
- Attack archetype
- Recommended actions prioritized by urgency

## Related Skills

- kill-switch - Execute containment actions
- blast-radius - Calculate impact scope
- drill - Practice incident response
