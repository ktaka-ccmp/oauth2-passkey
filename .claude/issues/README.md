# Issue Tracking

This directory contains issue/task tracking files for the project.

## Directory Structure

```
.claude/issues/
├── open/           # Active issues
├── completed/      # Resolved issues
├── deferred/       # Postponed issues
└── README.md       # This file
```

Issues are organized by status. When status changes, move the file to the appropriate directory.

## File Naming Convention

```
YYYY-MM-DD-<short-slug>.md
```

Example: `2026-01-30-move-info-endpoint.md`

## Issue Template

```markdown
# Issue: <Title>

## Status: open | completed | wontfix | deferred

## Priority: high | medium | low

## Description

<What needs to be done and why>

## Related Files

- `path/to/file.rs`

## Notes

<Additional context, discussion, decisions>

## Resolution

<What was done to resolve this issue>
```

## Status Values

| Status | Directory | Description |
|--------|-----------|-------------|
| `open` | `open/` | New or in-progress |
| `completed` | `completed/` | Resolved and committed |
| `wontfix` | `completed/` | Closed without implementation |
| `deferred` | `deferred/` | Postponed for later |

## Commands

- `/issue` - Create or update an issue
- `/backlog` - View all open issues
- `/snapshot` - Create a session snapshot (different from issues)

## Workflow

1. Create new issue in `open/` directory
2. Work on the issue
3. When resolved, update Resolution section and move to `completed/`
4. If postponed, move to `deferred/`

## Difference from Sessions

- **Sessions** (`.claude/sessions/`): Work context snapshots for transferring between machines
- **Issues** (`.claude/issues/`): Task/bug tracking that persists across sessions
