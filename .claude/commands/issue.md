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
- ID: `YYYY-MM-DD-NN` where NN is the sequential number for that day
- Check existing issues to determine the next sequence number for today
- Use the template below

### Issue Template

```markdown
# Issue: <Title>

## ID: YYYY-MM-DD-NN

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

1. **Update README.md**: Update the "Current Issues" section in `.claude/issues/README.md`
   - The section is between `<!-- AUTO-UPDATED -->` and `<!-- END AUTO-UPDATED -->` markers
   - Regenerate the tables for Open, Completed, and Deferred issues
   - Sort Open issues by priority (high > medium > low), then by ID

2. **Inform the user** of:
   - The file path
   - A brief summary of what was created/changed
   - If moved, the new location
