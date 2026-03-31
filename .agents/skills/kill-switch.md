# Skill: kill-switch

## Description
Execute emergency vendor kill chain to sever all connections and revoke access tokens. Critical for containing active breaches.

## When to Use
- Vendor breach confirmed
- Compromised OAuth tokens detected
- Supply chain attack affecting dependencies
- After blast radius analysis shows critical impact

## Workflow

1. **Validate Context**
   - Confirm vendor identification
   - Check integration graph for connections
   - Verify user has authorization to execute

2. **Build Kill Plan**
   - Enumerate all active connections
   - Identify connection types (OAuth, Webhook, API key)
   - Calculate execution order

3. **Execute Kill Chain**
   - Revoke OAuth tokens
   - Disable webhooks
   - Invalidate API keys
   - Deactivate service accounts

4. **Verify Completion**
   - Confirm all connections severed
   - Audit log the actions
   - Update integration graph status

5. **Post-Execution**
   - Monitor for connection attempts
   - Alert on unauthorized re-authentication
   - Document lessons learned

## Example Invocation

```bash
# Dry run first
shadowline kill vendor:drift --dry-run

# Execute kill switch
shadowline kill vendor:drift
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vendor` | string | Yes | Vendor identifier (format: vendor:NAME) |
| `--dry-run` | flag | No | Preview actions without execution |
| `--json` | flag | No | Output JSON for automation |

## Safety Guardrails

- Dry run required before first execution
- All actions logged to immutable audit chain
- Requires confirmation for destructive operations
- Can be interrupted mid-execution

## Related Skills

- velocity-clock - Time remaining before impact
- blast-radius - Scope of affected systems
- integration-graph - Visualize connections before killing
