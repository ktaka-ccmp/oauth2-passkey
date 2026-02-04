# Issue Tracking

This directory contains issue/task tracking files for the project.

## Current Issues

<!-- AUTO-UPDATED: Do not edit manually. Updated by /issue command. -->

### Open (7)

| ID | Priority | Difficulty | Title |
|----|----------|------------|-------|
| `2026-01-23-01` | medium | large | [Bearer Token Authentication Support](open/2026-01-23-bearer-token-support.md) |
| `2026-01-30-02` | medium | medium | [Admin Force Logout Feature](open/2026-01-30-admin-force-logout.md) |
| `2026-01-30-03` | medium | large | [Admin Login History View](open/2026-01-30-admin-login-history.md) |
| `2026-01-30-07` | medium | large | [Passkey Registration Promotion After Login](open/2026-01-30-conditional-creation.md) |
| `2026-01-30-08` | low | medium | [Demo Site Deployment (Fly.io)](open/2026-01-30-demo-site-deployment.md) |
| `2026-01-31-01` | low | medium | [Sequential Primary Keys Optimization](open/2026-01-31-sequential-pkey-optimization.md) |
| `2026-01-31-02` | low | small | [Remove HTTPS Support from Demo Apps](open/2026-01-31-demo-remove-https.md) |

### Completed (19)

| ID | Title |
|----|-------|
| `2025-01-23-01` | [CI/CD Documentation](completed/2025-01-23-ci-cd-documentation.md) |
| `2026-01-29-01` | [Change PASSKEY_USER_HANDLE_UNIQUE default to false](completed/2026-01-29-change-user-handle-default.md) |
| `2026-01-29-03` | [Create Terminology/Glossary Document](completed/2026-01-29-terminology-document.md) |
| `2026-01-30-04` | [Update README.md with Links and Demo Info](completed/2026-01-30-readme-links-update.md) |
| `2026-01-30-05` | [getClientCapabilities Feature Detection](completed/2026-01-30-client-capabilities-detection.md) |
| `2025-01-23-02` | [CSRF Documentation & Snapshot System](completed/2025-01-23-csrf-docs-snapshot-system.md) |
| `2026-01-24-02` | [Demo Apps Implementation](completed/2026-01-24-demo-apps-implementation.md) |
| `2026-01-26-01` | [Demo Apps Database Configuration](completed/2026-01-26-demo-apps-db-config.md) |
| `2026-01-26-02` | [Documentation and Demo Cleanup](completed/2026-01-26-docs-and-demos-cleanup.md) |
| `2026-01-27-01` | [Admin Route Refactoring](completed/2026-01-27-admin-route-refactoring.md) |
| `2026-01-27-02` | [Unified Router API Design](completed/2026-01-27-unified-router-api.md) |
| `2026-01-27-03` | [Demo Cleanup & Unification](completed/2026-01-27-demo-cleanup-unification.md) |
| `2026-01-28-01` | [WebAuthn Signal API Implementation](completed/2026-01-28-signal-api-implementation.md) |
| `2026-01-28-02` | [Session Conflict Policy Implementation](completed/2026-01-28-session-conflict-policy.md) |
| `2026-01-28-03` | [Fix Windows Hello TPM Attestation (RS1)](completed/2026-01-28-tpm-rs1-attestation-fix.md) |
| `2026-01-29-02` | [Filter remaining_credential_ids by user_handle](completed/2026-01-29-filter-remaining-credentials.md) |
| `2026-01-29-04` | [Review SESSION_CONFLICT_POLICY Default](completed/2026-01-29-session-conflict-policy-review.md) |
| `2026-01-30-01` | [Move /info and /csrf_token to default.rs](completed/2026-01-30-move-info-csrf-endpoints.md) |
| `2026-01-30-09` | [Cross-Origin Same-Site Demo (Pattern 2)](completed/2026-01-30-cross-origin-same-site-demo.md) |

### Deferred (2)

| ID | Title |
|----|-------|
| `2026-01-24-01` | [Documentation Improvement Planning](deferred/2026-01-24-docs-improvement-planning.md) |
| `2026-01-30-06` | [Passkey Endpoint (.well-known) Support](deferred/2026-01-30-passkey-endpoint-wellknown.md) |

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

## Difficulty: small | medium | large

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
