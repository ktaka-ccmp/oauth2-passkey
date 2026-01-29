# Issue Management

Create, update, or close an issue for task/bug tracking.

## Directory Structure

```
.claude/issues/
├── open/           # New issues go here
├── completed/      # Move here when resolved
├── deferred/       # Move here when postponed
└── README.md
```

## Instructions

### Creating a New Issue

Create a markdown file in `.claude/issues/open/` with:
- Filename: `YYYY-MM-DD-<short-slug>.md` (e.g., `2026-01-30-move-info-endpoint.md`)
- Use the template below

### Issue Template

```markdown
# Issue: <Title>

## Status: open

## Priority: <high | medium | low>

## Description

<What needs to be done and why>

## Related Files

- `path/to/file.rs`

## Notes

<Additional context, discussion, decisions>

## Resolution

<Leave empty until resolved>
```

### Updating an Issue

When updating an existing issue:
1. Read the current issue file
2. Update the relevant sections (Status, Notes, Resolution)
3. If status changes, move file to appropriate directory:
   - `completed` or `wontfix` -> move to `completed/`
   - `deferred` -> move to `deferred/`

### Status Values

| Status | Directory | Description |
|--------|-----------|-------------|
| `open` | `open/` | New or in-progress |
| `completed` | `completed/` | Resolved and committed |
| `wontfix` | `completed/` | Closed without implementation |
| `deferred` | `deferred/` | Postponed for later |

### After Creating/Updating

Inform the user of:
1. The file path
2. A brief summary of what was created/changed
3. If moved, the new location
