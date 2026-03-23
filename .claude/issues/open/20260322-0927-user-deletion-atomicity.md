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

## Closed:

## Status: open

## Priority: medium

## Difficulty: large

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

- `20260322-0926` Passkey counter verification race (open) -- same category, also crosses abstraction boundaries
- `20260322-0907` upsert_oauth2_account post-tx SELECT race (open) -- simpler transaction issue

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

- [ ] Evaluate approach (transaction-aware API vs CASCADE DELETE vs single function)
- [ ] Implement chosen approach for SQLite
- [ ] Implement chosen approach for MySQL
- [ ] Implement chosen approach for PostgreSQL
- [ ] Add admin count + delete atomicity
- [ ] Verify tests pass

## Decision Log

### 2026-03-22: Issue created from codebase transaction audit

- Context: Deep audit found that user deletion in coordination/user.rs performs multiple store operations without atomicity. Two related problems: non-atomic deletion and admin count race.
- Decision: Create single issue covering both sub-problems since they share the same root cause (cross-store operations without shared transactions) and the fix will likely address both together.
- Reason: The fix requires a storage layer design change, making this the largest of the transaction audit findings.

## Resolution