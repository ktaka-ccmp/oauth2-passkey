# Session Snapshot: CSRF Documentation & Snapshot System

**Date**: 2025-01-23

## Current Task

1. CSRF documentation reorganization - completed
2. Session snapshot system setup - completed

## Files Modified

### Documentation
- `docs/src/integration/csrf-handling.md` - Major rewrite to cover both AJAX and Form submissions (was Forms-only)

### Snapshot System
- `.claude/sessions/` - Directory created for session snapshots
- `.claude/commands/snapshot.md` - Command to create snapshots via `/snapshot`
- `~/.claude/commands/snapshot.md` - Global copy of snapshot command
- `CLAUDE.md` - Added "Session Snapshots" section

## Key Decisions

1. **Keep CSRF docs separate**: `security/csrf.md` (reference) and `integration/csrf-handling.md` (tutorial) remain as separate documents with cross-links
2. **CSRF in own section**: CSRF handling stays in csrf-handling.md, not embedded in custom-pages.md
3. **Snapshot location**: `.claude/sessions/` directory for transferring context between machines

## Context

### CSRF Documentation Structure
- **AJAX requests**: Token in `X-CSRF-Token` header → middleware verifies automatically
- **Form submissions**: Token in body → manual verification required (Axum consumes body only once)
- Key point: Always use `ct_eq` (constant-time comparison), never `==`

### Document Roles
- `security/csrf.md` = Reference, best practices, troubleshooting
- `integration/csrf-handling.md` = Tutorial, step-by-step implementation

## Next Steps

No pending tasks. Documentation work is complete.

To continue on another machine:
```
Read .claude/sessions/ and continue from the latest snapshot
```
