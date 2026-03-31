# Skill: skill-management

## Description
Manage Shadowline skills/plugins. Install, remove, and list available skills from the registry.

## When to Use
- Adding new capabilities
- Updating existing skills
- Auditing installed skills
- Removing unused skills

## Workflow

1. **Discovery**
   - List installed skills
   - Query registry for available skills
   - Check for updates

2. **Installation**
   - Download skill package
   - Verify signature
   - Install to skills directory

3. **Activation**
   - Load skill manifest
   - Register commands
   - Enable in TUI

4. **Removal**
   - Deactivate skill
   - Remove files
   - Clean up configuration

## Example Invocation

```bash
# List installed skills
shadowline skills list

# Install a skill
shadowline skills install supply-chain-scanner

# Remove a skill
shadowline skills remove old-skill
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | Yes | list, install, or remove |
| `name` | string | Conditional | Skill name (for install/remove) |

## Security

- Skills run in sandboxed environment
- Signature verification required
- Permission manifest enforced
- Audit logged on all skill operations

## Related Skills

- supply-chain-scan - Verify skill integrity
