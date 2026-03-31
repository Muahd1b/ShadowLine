# Skill: audit-chain

## Description
Verify and query the tamper-evident audit log. All Shadowline actions are recorded in a cryptographically chained log.

## When to Use
- Compliance audits
- Incident forensics
- Security reviews
- Troubleshooting

## Workflow

1. **Query Entries**
   - Retrieve recent audit entries
   - Filter by action type
   - Search by user or target

2. **Verify Integrity**
   - Check chain continuity
   - Validate hashes
   - Detect tampering

3. **Export**
   - Generate compliance reports
   - Export for SIEM ingestion
   - Archive old entries

## Example Invocation

```bash
# Show last 10 audit entries
shadowline audit --show --last 10

# Verify chain integrity
shadowline audit --verify
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--verify` | flag | No | Check chain integrity |
| `--show` | flag | No | Display entries |
| `--last` | number | No | Number of entries to show |

## Output

- Entry sequence number
- Timestamp
- Actor and action
- Target and result
- Chain hash

## Security Properties

- Append-only (no deletions)
- Cryptographically chained
- Hash verification prevents tampering
- Immutable storage

## Related Skills

- All skills write to audit log automatically
