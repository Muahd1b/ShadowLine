# Skill: integration-graph

## Description
Discover and visualize all vendor integrations and their connection relationships. Essential for understanding attack surface.

## When to Use
- Initial system setup and discovery
- Before incident response to understand scope
- Regular audits of integration inventory
- Planning kill switch execution

## Workflow

1. **Discovery**
   - Scan configured connectors (GitHub, Salesforce, Slack)
   - Query OAuth token stores
   - Detect webhooks and API keys

2. **Build Graph**
   - Create vendor nodes
   - Map connection edges
   - Calculate risk scores per vendor

3. **Visualize**
   - Display in TUI Status pane
   - Show vendor risk levels
   - Highlight dormant vs active connections

4. **Export**
   - Generate dependency reports
   - Export for compliance documentation
   - Share with security teams

## Example Invocation

```bash
# Show full integration graph
shadowline graph

# Filter by vendor
shadowline graph --vendor drift
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--vendor` | string | No | Filter to specific vendor |

## Output

- Vendor count and connection totals
- Per-vendor risk scores
- Connection status (active/dormant/revoked)
- Platform types per connection

## Related Skills

- blast-radius - Calculate downstream impact
- kill-switch - Sever connections
- scan - Detect new integrations
