# Issue: Admin Deletion Safeguard (Prevent Deleting Last Admin)

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260210-1930

## Created: 2026-02-10-19-30

## Closed:

## Status: open

## Priority: high

## Difficulty: medium

## Description

The system has no safeguard against deleting the last admin user. Once all admin users
are deleted, the system becomes permanently locked out of admin functionality because:

1. New users are created with `is_admin: false`
2. Auto-promotion to admin only occurs for `sequence_number = 1` (first user ever)
3. Once the first user is deleted, `sequence_number = 1` no longer exists
4. No remaining admin can promote other users

This is a data integrity bug in the core library that should be fixed regardless of
the demo deployment.

### Current Admin Logic

- First user (`sequence_number = 1`) is auto-promoted to admin during upsert
- `has_admin_privileges()` returns true if `is_admin = true` OR `sequence_number == 1`
- First user cannot be demoted (explicit check in `update_user_admin_status()`)
- **No check prevents deleting the last admin**

## Related Issues

- `2026-01-30-08` Demo Site Deployment (related: discovered during deployment planning)

## Approach

1. Add a check in the admin user deletion function to prevent deleting the last admin
2. Before deleting an admin user, count remaining admins
3. If the user being deleted is the last admin, return an error
4. Consider also preventing demotion of the last admin (not just deletion)

## Related Files

- `oauth2_passkey/src/coordination/admin.rs` (delete function, lines 248-275)
- `oauth2_passkey/src/coordination/admin.rs` (update_user_admin_status, lines 308-341)
- `oauth2_passkey/src/userdb/storage/store_type.rs` (upsert with auto-admin, lines 93-109)
- `oauth2_passkey/src/session/types.rs` (has_admin_privileges, lines 116-118)

## Implementation Tasks

- [ ] Add admin count query to UserStore (count users where is_admin = true)
- [ ] Add last-admin check in delete_user (coordination/admin.rs)
- [ ] Add last-admin check in update_user_admin_status (prevent demotion of last admin)
- [ ] Write unit tests for last-admin protection
- [ ] Update error types to include LastAdminProtection variant

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-10: Identified admin lockout risk

- Context: During demo site deployment planning, discovered that deleting all admins
  leaves the system in an unrecoverable state
- Decision: Create dedicated issue for core library fix
- Reason: This is a data integrity bug, not a demo-specific issue

### 2026-02-13: "Last admin" guard vs "first user" protection; performance

- Context: Considered two approaches: (1) prevent deleting the last admin, (2) prevent
  deleting the first user (sequence_number = 1)
- Decision: Guard the invariant "at least one admin exists" rather than protecting a
  specific user
- Reason: "First user" approach creates a permanently undeletable user. "Last admin"
  approach is more flexible -- any admin can be deleted as long as another admin remains.
  Decouples security from the arbitrary "first user" concept
- Performance: The admin count query (`SELECT COUNT(*) WHERE is_admin = true`) is
  negligible. Admin operations (delete/demote) are extremely rare (manual admin actions),
  not a hot path. Additionally, the count query is only executed when the target user
  is actually an admin, skipped entirely for non-admin deletions

## Resolution
