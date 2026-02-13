# Session Snapshot: Admin Safeguard & OAuth2 Popup Error Handling

## Date: 2026-02-13

## Current Task

**Two features worked on this session:**

1. **OAuth2 Popup Error Handling (COMPLETED)** - Issue `2026-02-09-02`, closed
   - Branch: `dev-20260209-0902` (merged to dev via PR #214)
   - Commits: `ac43e38`, `a83aae8`, `09b2397`

2. **Admin Deletion Safeguard (IN PROGRESS)** - Issue `20260210-1930`
   - Branch: `dev-20260213-admin-safeguard` (created from dev)
   - Status: **Plan written, awaiting approval before implementation**
   - Plan file: `.claude/plans/vectorized-hopping-mccarthy.md`
   - No code changes yet, only issue file updated with decision log

## How to Resume

1. `git checkout dev-20260213-admin-safeguard`
2. Read this snapshot (contains full plan - the `.claude/plans/` file is local-only and won't be in git)
3. Read the issue: `.claude/issues/open/20260210-1930-admin-deletion-safeguard.md`
4. Update issue implementation tasks (add demotion check, note Conflict instead of new variant)
5. Approve the plan and begin implementation (6 steps detailed below)

## Files Modified This Session

### OAuth2 Popup Error Handling (completed & merged to dev)
- `oauth2_passkey_axum/src/error.rs` - Added Conflict -> 409 mapping
- `oauth2_passkey_axum/src/oauth2.rs` - Refactored get/post_authorized to catch errors and redirect to popup_close with user-friendly messages via `friendly_error_message()` helper
- `oauth2_passkey_axum/templates/popup_close.j2` - Redesigned: login-card style, error shows red message + Close button, success auto-closes, postMessage only on success
- `oauth2_passkey/tests-security/common/security_utils.rs` - Added `RedirectWithError` variant to `ExpectedSecurityError`
- `oauth2_passkey/tests-security/oauth2_security.rs` - Updated 13 assertions `BadRequest` -> `RedirectWithError`
- `oauth2_passkey/tests-security/cross_flow_security.rs` - Updated 1 assertion
- `.claude/issues/completed/2026-02-09-oauth2-popup-error-handling.md` - Closed

### Admin Safeguard (pending, on branch `dev-20260213-admin-safeguard`)
- `.claude/issues/open/20260210-1930-admin-deletion-safeguard.md` - Added decision log entries (performance concern, approach choice)

## Key Decisions

### OAuth2 Popup Error Handling
- Redirect errors to popup_close instead of returning raw HTTP error text
- Use `friendly_error_message()` in Axum layer (library error messages stay technical)
- Don't send `postMessage('auth_complete')` on error (avoids unnecessary parent reload)
- Use login-card styling, keep design simple (no large icons)

### Admin Safeguard (planned, not yet implemented)
- Guard "at least one admin exists" invariant (NOT "first user undeletable")
- Use existing `Conflict(String)` error variant (maps to 409, no new variant needed)
- Replace first-user protection (`sequence_number == 1` check) with more general last-admin check
- SQL count: `WHERE is_admin = true OR sequence_number = 1` (consistent with `has_admin_privileges()`)
- Only query admin count when target is actually an admin (performance optimization)

## Admin Safeguard Full Implementation Plan

> This is a complete copy of the plan from `.claude/plans/vectorized-hopping-mccarthy.md`
> (local file, not in git). Included here for cross-machine resumption.

### Design Decisions

1. **Guard "at least one admin" invariant** (not "first user is undeletable")
   - More flexible: any admin can be deleted/demoted as long as another exists
2. **Use existing `Conflict(String)` error variant** (maps to HTTP 409)
   - No new error variant needed, semantically correct
3. **Replace first-user protection** in `update_user_admin_status`
   - Current seq=1 protection is overly restrictive (blocks demotion even with other admins)
   - New last-admin check is strictly more general and correct
4. **Count `is_admin = true OR sequence_number = 1`** in SQL
   - Consistent with `has_admin_privileges()` logic
5. **Only query count when target is admin** (optimization, skip for non-admin targets)

### Step 1: Add `count_admin_users` SQL functions

**`oauth2_passkey/src/userdb/storage/sqlite.rs`** - Add `count_admin_users_sqlite()`
**`oauth2_passkey/src/userdb/storage/postgres.rs`** - Add `count_admin_users_postgres()`

```sql
SELECT COUNT(*) FROM {table_name} WHERE is_admin = true OR sequence_number = 1
```

### Step 2: Add `count_admin_users` dispatch to UserStore

**`oauth2_passkey/src/userdb/storage/store_type.rs`** - Add `UserStore::count_admin_users()`

Visibility: `pub(crate)` (consumed by coordination layer only). Follows the same
SQLite/PostgreSQL dispatch pattern as `get_all_users`, `delete_user`, etc.

### Step 3: Add last-admin guard to `delete_user_account_admin`

**`oauth2_passkey/src/coordination/admin.rs`**

After user existence check, before deletion:
```rust
if user.has_admin_privileges() {
    let admin_count = UserStore::count_admin_users().await
        .map_err(|e| CoordinationError::Database(e.to_string()))?;
    if admin_count <= 1 {
        return Err(CoordinationError::Conflict(
            "Cannot delete the last admin user".to_string(),
        ).log());
    }
}
```

### Step 4: Replace first-user protection with last-admin guard in `update_user_admin_status`

**`oauth2_passkey/src/coordination/admin.rs`**

Replace the existing `sequence_number == Some(1)` check with:
```rust
if !is_admin && user.has_admin_privileges() {
    let admin_count = UserStore::count_admin_users().await
        .map_err(|e| CoordinationError::Database(e.to_string()))?;
    if admin_count <= 1 {
        return Err(CoordinationError::Conflict(
            "Cannot demote the last admin user".to_string(),
        ).log());
    }
}
```

Guard conditions: only when demoting (`!is_admin`) AND target has admin privileges.

### Step 5: Fix Axum handler error mapping

**`oauth2_passkey_axum/src/admin/default.rs`**

Change `delete_user_account_handler` and `update_admin_status_handler` from:
```rust
.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
```
To:
```rust
.into_response_error()?;
```

This ensures `Conflict` -> 409, `ResourceNotFound` -> 404, `Unauthorized` -> 401
(instead of everything being 500).

### Step 6: Add tests

**`oauth2_passkey/src/coordination/admin/tests.rs`**:
- `test_delete_last_admin_prevented` - Only one admin, deletion returns Conflict
- `test_delete_admin_allowed_when_others_exist` - Multiple admins, deletion succeeds
- `test_demote_last_admin_prevented` - Only one admin, demotion returns Conflict
- `test_demote_admin_allowed_when_others_exist` - Multiple admins, demotion succeeds

**Update existing test**: `test_update_user_admin_status_protect_first_user`
- Old: expects `Coordination` error when demoting seq=1
- New: expects `Conflict` error when demoting last admin (regardless of seq number)

### Files Modified

| File | Change |
|------|--------|
| `oauth2_passkey/src/userdb/storage/sqlite.rs` | Add `count_admin_users_sqlite()` |
| `oauth2_passkey/src/userdb/storage/postgres.rs` | Add `count_admin_users_postgres()` |
| `oauth2_passkey/src/userdb/storage/store_type.rs` | Add `UserStore::count_admin_users()` |
| `oauth2_passkey/src/coordination/admin.rs` | Add guard in delete, replace first-user check in demote |
| `oauth2_passkey_axum/src/admin/default.rs` | Use `.into_response_error()` |
| `oauth2_passkey/src/coordination/admin/tests.rs` | Add 4 tests, update 1 existing test |

### Verification

1. `cargo fmt --all`
2. `cargo clippy --all-targets --all-features`
3. `cargo test` - all tests pass including new safeguard tests
4. Verify: single admin delete -> 409 Conflict
5. Verify: single admin demote -> 409 Conflict
6. Verify: multi-admin delete -> success
7. Verify: non-admin delete -> success (no count query)

## Context

- Branch `dev-20260213-admin-safeguard` is clean (no uncommitted code changes)
- Previous branch `dev-20260209-0902` merged to dev via PR #214
- All tests currently pass (502 unit + 21 security + doctests)
- Issue `20260210-1930` priority: high (deleting all admins causes permanent lockout)
- Issue implementation tasks in the issue file need updating to match the plan
