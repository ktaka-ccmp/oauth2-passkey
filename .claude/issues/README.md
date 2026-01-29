# Issue Tracking

This directory contains issue/task tracking files for the project.

## Current Issues

<!-- AUTO-UPDATED: Do not edit manually. Updated by /issue command. -->

### Open (4)

| ID | Priority | Title |
|----|----------|-------|
| `2026-01-23-01` | medium | [Bearer Token Authentication Support](open/2026-01-23-bearer-token-support.md) |
| `2026-01-29-01` | medium | [Change PASSKEY_USER_HANDLE_UNIQUE default to false](open/2026-01-29-change-user-handle-default.md) |
| `2026-01-30-01` | medium | [Move /info and /csrf_token to default.rs](open/2026-01-30-move-info-csrf-endpoints.md) |
| `2026-01-29-03` | low | [Create Terminology/Glossary Document](open/2026-01-29-terminology-document.md) |

### Completed (3)

| ID | Title |
|----|-------|
| `2026-01-28-01` | [WebAuthn Signal API Implementation](completed/2026-01-28-signal-api-implementation.md) |
| `2026-01-29-02` | [Filter remaining_credential_ids by user_handle](completed/2026-01-29-filter-remaining-credentials.md) |
| `2026-01-29-04` | [Review SESSION_CONFLICT_POLICY Default](completed/2026-01-29-session-conflict-policy-review.md) |

### Deferred (1)

| ID | Title |
|----|-------|
| `2026-01-24-01` | [Documentation Improvement Planning](deferred/2026-01-24-docs-improvement-planning.md) |

<!-- END AUTO-UPDATED -->

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

```text
YYYY-MM-DD-<short-slug>.md
```

Example: `2026-01-30-move-info-endpoint.md`

## Issue ID Format

```text
YYYY-MM-DD-NN
```

- `YYYY-MM-DD`: Creation date
- `NN`: Sequential number for that day (01, 02, ...)

Example: `2026-01-30-01`, `2026-01-30-02`

## Issue Template

```markdown
# Issue: <Title>

## ID: YYYY-MM-DD-NN

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
