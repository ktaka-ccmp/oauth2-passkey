# Issue: User Deletion Lacks Atomicity Across Multiple Stores

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260322-0927

## Created: 2026-03-22

## Closed: 2026-03-23

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

In `coordination/user.rs`, user deletion performs multiple sequential operations across three different Store modules without atomicity. This has two sub-problems:

### Problem 1: Non-atomic multi-store deletion (lines ~140-154)

```rust
// These are separate, independent database operations
OAuth2Store::delete_oauth2_accounts_by(UserId(user_id.clone())).await?;
PasskeyStore::delete_credential_by(UserId(user_id.clone())).await?;
UserStore::delete_user(user_id).await?;
```

If the function fails after deleting OAuth2 accounts but before deleting the user, orphaned credentials remain in the database.

### Problem 2: Admin count check race condition (lines ~126-154)

```rust
// CHECK: Count admins
let admin_count = UserStore::count_admin_users().await?;
if admin_count <= 1 {
    return Err(CoordinationError::Conflict(...));
}

// ... later ...

// DELETE: Remove the user
UserStore::delete_user(user_id).await?;
```

Between the count check and the delete, another concurrent request could delete a different admin, violating the last-admin constraint.

### Why this is harder than previous transaction fixes

- Three different Store modules (OAuth2Store, PasskeyStore, UserStore) each independently use `pool`
- The current storage trait API does not support passing a shared transaction object
- Fixing requires either a cross-store transaction mechanism or a storage layer redesign

## Related Issues

- `20260322-0926` Passkey counter verification race (completed) -- same category
- `20260322-0907` upsert_oauth2_account post-tx SELECT race (completed) -- simpler transaction issue

## Approach

Option A: Add a transaction-aware API to the storage layer that allows coordination-level code to create a transaction and pass it to multiple Store methods.

Option B: Move all user deletion logic into a single storage-layer function that handles the transaction internally (denormalized but simpler).

Option C: Use database-level foreign key CASCADE DELETE so that deleting the user automatically removes related OAuth2 accounts and credentials. The admin count check would still need a separate solution (e.g., `DELETE ... WHERE (SELECT count(*) ...) > 1`).

## Related Files

- `oauth2_passkey/src/coordination/user.rs` (lines ~126-154)
- `oauth2_passkey/src/oauth2/storage/` (delete methods)
- `oauth2_passkey/src/passkey/storage/` (delete methods)
- `oauth2_passkey/src/userdb/storage/` (delete and count methods)

## Implementation Tasks

- [x] Evaluate approach -> Option C (CASCADE DELETE)
- [x] Add `ON DELETE CASCADE` to FK in CREATE TABLE for all 3 backends
- [x] Enable `PRAGMA foreign_keys = ON` for SQLite connections
- [x] Simplify `coordination/user.rs` and `admin.rs`: remove explicit OAuth2/Passkey deletes
- [x] Remove migration functions (pre-1.0, DB recreation required)
- [x] Add atomic admin count check via `delete_user_if_not_last_admin()`
- [x] Update coordination layer to use atomic admin delete
- [x] Add login_history orphan retention comment
- [x] Add atomic admin demotion via `demote_user_if_not_last_admin()`
- [x] Update coordination/admin.rs `update_user_admin_status` to use atomic demotion
- [x] Remove now-unused `count_admin_users` from all 3 backends
- [x] Verify tests pass

## Decision Log

### 2026-03-22: Issue created from codebase transaction audit

- Context: Deep audit found that user deletion in coordination/user.rs performs multiple store operations without atomicity. Two related problems: non-atomic deletion and admin count race.
- Decision: Create single issue covering both sub-problems since they share the same root cause (cross-store operations without shared transactions) and the fix will likely address both together.
- Reason: The fix requires a storage layer design change, making this the largest of the transaction audit findings.

### 2026-03-23: Chose Option C (CASCADE DELETE)

- Context: Investigation revealed FK constraints already exist on all 3 backends (`REFERENCES users(id)`), just without CASCADE. User/OAuth2/Passkey have clear parent-child relationships. Registration order already correct (user first, then children).
- Decision: Add `ON DELETE CASCADE` to existing FK constraints. Simplify coordination layer to single `UserStore::delete_user()`. Add atomic admin count check in the DELETE statement.
- Reason: Minimal change -- FK constraints are already in place, CASCADE is the standard RDB pattern for parent-child deletion. No Store API redesign needed. Option A (transaction-aware API) deferred to 1.0 API design.

### 2026-03-23: Atomic admin count check via DELETE with subquery

- Context: PR #286 review identified that the admin count TOCTOU race (Problem 2) was not addressed by CASCADE DELETE.
- Decision: Add `UserStore::delete_user_if_not_last_admin()` using `DELETE FROM users WHERE id = ? AND (SELECT COUNT(*) FROM users WHERE is_admin = true) > 1`. Same atomic pattern as the passkey counter fix. Coordination layer uses this for admin users, regular `delete_user` for non-admins. Remove separate `count_admin_users` + check.
- Reason: Single SQL statement is inherently atomic. No transaction API changes needed.

### 2026-03-23: Atomic admin demotion

- Context: Same TOCTOU pattern exists in `update_user_admin_status` when demoting an admin. count_admin_users + upsert_user are separate operations.
- Decision: Add `UserStore::demote_user_if_not_last_admin()` using `UPDATE users SET is_admin = false WHERE id = ? AND (SELECT COUNT(*) FROM users WHERE is_admin = true) > 1`. Same atomic pattern as deletion.
- Reason: Completes the fix for all admin count race conditions in one issue.

## Resolution

Both sub-problems resolved:

**Problem 1 (Non-atomic multi-store deletion):** Added `ON DELETE CASCADE` to FK constraints on `oauth2_accounts` and `passkey_credentials` tables. `UserStore::delete_user()` now atomically removes user + all related records at the database level. Explicit OAuth2/Passkey deletes removed from coordination layer.

**Problem 2 (Admin count race condition):** Replaced separate `count_admin_users` + `delete_user`/`upsert_user` TOCTOU pattern with atomic SQL:
- `delete_user_if_not_last_admin()`: `DELETE ... WHERE (SELECT COUNT(*) WHERE is_admin = true) > 1`
- `demote_user_if_not_last_admin()`: `UPDATE ... SET is_admin = false WHERE (SELECT COUNT(*) WHERE is_admin = true) > 1`

Additional: `PRAGMA foreign_keys = ON` enabled for SQLite. Migration functions removed (pre-1.0, DB recreation required). `login_history.user_id` intentionally has no FK (audit trail retention).
