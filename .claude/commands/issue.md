# Issue Management

Create, update, or close an issue for task/bug tracking.

## Directory Structure

```
.claude/issues/
├── open/           # New issues go here
├── completed/      # Move here when resolved
├── wontfix/        # Move here when closed without implementation
├── deferred/       # Move here when postponed
└── README.md
```

## Instructions

### Creating a New Issue

Create a markdown file in `.claude/issues/open/` with:
- Filename: `YYYYMMDD-HHMM-<short-slug>.md` (e.g., `20260210-1430-login-history-enhancement.md`)
- ID: `YYYYMMDD-HHMM` matching the filename timestamp
- Created: `YYYY-MM-DD-HH-MM` (same timestamp in readable format)
- Use the template from `.claude/issues/README.md`

### Updating an Issue

When updating an existing issue:
1. Read the current issue file
2. Update the relevant sections (Status, Notes, Resolution)
3. If status changes, move file to appropriate directory:
   - `completed` -> move to `completed/`
   - `wontfix` -> move to `wontfix/`
   - `deferred` -> move to `deferred/`
4. When closing an issue, set the `Closed:` field to `YYYY-MM-DD-HH-MM`

### Status Values

| Status | Directory | Description |
|--------|-----------|-------------|
| `open` | `open/` | New or in-progress |
| `completed` | `completed/` | Resolved and committed |
| `wontfix` | `wontfix/` | Closed without implementation |
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
