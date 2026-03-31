# Skill: severing-drill

## Description
Practice incident response with simulated vendor compromises. Test kill switch execution speed and identify gaps.

## When to Use
- Regular security training (recommended: monthly)
- Onboarding new security engineers
- Testing new vendor integrations
- After process changes

## Workflow

1. **Simulation Setup**
   - Select target vendor (or random)
   - Configure compromise scenario
   - Set evaluation criteria

2. **Execute Drill**
   - Simulate breach notification
   - Time kill switch execution
   - Track missed integrations

3. **Score Performance**
   - Calculate response time
   - Penalize missed connections
   - Generate drill score

4. **Review & Improve**
   - Show drill history
   - Identify improvement areas
   - Update integration discovery

## Example Invocation

```bash
# Run simulated drill
shadowline drill --simulate --vendor drift

# Show drill history
shadowline drill --history
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--simulate` | flag | No | Run simulated drill |
| `--vendor` | string | No | Target vendor for drill |
| `--history` | flag | No | Show past drill results |

## Scoring

- Base score: 100 points
- Penalty: -5 points per missed integration
- Time bonus: +10 points if under 3 seconds
- Perfect score: 100 (no misses, fast execution)

## Related Skills

- kill-switch - Practice execution
- integration-graph - Know your targets
- velocity-clock - Beat the clock
