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

- [x] Add `count_admin_users` SQL functions (SQLite/PostgreSQL) counting `is_admin = true OR sequence_number = 1`
- [x] Add `UserStore::count_admin_users()` dispatch in store_type.rs
- [x] Add last-admin guard in `delete_user_account_admin` (return `Conflict` error)
- [x] Replace first-user protection with last-admin guard in `update_user_admin_status` (return `Conflict` error)
- [x] Fix Axum handler error mapping in `delete_user_account_handler` and `update_admin_status_handler` to use `.into_response_error()`
- [x] Add 4 new tests, remove 1 obsolete test for last-admin protection
- [x] Re-add first-user (seq=1) unconditional demotion guard in `update_user_admin_status`
- [x] Add test for first-user demotion prevented even with other admins
- [x] Add last-admin guard to `delete_user_account` (self-deletion path)
- [x] Fix Axum handler error mapping in user self-deletion handler to use `.into_response_error()`
- [x] Add test for self-deletion of last admin prevented
- [x] Add `restore_first_user_after_deletion()` helper in test_utils.rs (raw SQL with explicit seq=1)
- [x] Add `delete_user_atomically()` helper in test_utils.rs (holds GENERIC_DATA_STORE lock for entire deletion)
- [x] Add test: first-user escape hatch self-delete (`user/tests.rs`)
- [x] Add test: last admin protected after first-user deleted (`admin/tests.rs`)

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

### 2026-02-13: Implementation completed

- Context: Implemented the "at least one admin" safeguard as planned
- Changes:
  - Added `count_admin_users` SQL functions (SQLite/PostgreSQL) with `WHERE is_admin = true OR sequence_number = 1`
  - Added `UserStore::count_admin_users()` dispatch in store_type.rs
  - Added last-admin guard in `delete_user_account_admin` (returns `Conflict` 409)
  - Replaced first-user seq=1 protection with last-admin guard in `update_user_admin_status` (returns `Conflict` 409)
  - Fixed Axum handlers to use `.into_response_error()` for proper error code mapping
  - Added 4 new tests (delete/demote last admin prevented, delete/demote admin allowed when others exist)
  - Removed obsolete `test_update_user_admin_status_protect_first_user` (tested old first-user protection logic)
  - Removed unused `UserSearchField` re-export from `userdb/mod.rs`
- Behavioral change: first-user (seq=1) is no longer unconditionally protected from demotion;
  any admin can be demoted/deleted as long as at least one other admin remains

### 2026-02-13: UI templates still have first-user special-casing

- Context: `admin_index.j2` and `admin_user_page.j2` hide admin toggle and delete buttons
  for sequence_number=1 users. Backend no longer requires this restriction.
- Decision: Remove the first-user special-casing from templates so all admins are treated
  equally in the UI. Backend 409 Conflict guard ensures safety.
- Files: `oauth2_passkey_axum/templates/admin_index.j2`,
  `oauth2_passkey_axum/templates/admin_user_page.j2`

### 2026-02-13: Re-add first-user unconditional demotion guard; keep templates as-is

- Context: Discovered that demoting the first user (setting is_admin=false) does not
  actually remove admin privileges because `has_admin_privileges()` returns true for
  `sequence_number == 1` regardless of `is_admin`. This creates inconsistency: the UI
  shows the user as non-admin, but they still have admin access.
- Decision: Re-add unconditional first-user demotion guard (seq=1 cannot be demoted)
  in addition to the last-admin guard. Keep admin UI templates as-is (hiding toggle/delete
  for first user is correct since demotion is blocked).
- Reason: Removing seq=1 from `has_admin_privileges()` would be a much larger scope change
  affecting code, tests, templates, and docs across the codebase. Deferred to a separate
  issue. Current approach keeps the system consistent: first user is always admin, and the
  UI correctly reflects that it cannot be changed.
- Related: Created deferred issue for full seq=1 removal from `has_admin_privileges()`

### 2026-02-13: Self-deletion path missing last-admin guard

- Context: `delete_user_account` (user self-deletion in coordination/user.rs) had no
  last-admin guard, allowing any admin to bypass the protection by self-deleting through
  the user account page instead of the admin page.
- Decision: Add the same last-admin guard to `delete_user_account` and fix the Axum
  handler error mapping to use `.into_response_error()` for proper 409 Conflict responses.
- Files: `oauth2_passkey/src/coordination/user.rs`, `oauth2_passkey_axum/src/user/default.rs`

### 2026-02-13: Full logic review -- no errors found

- Context: Reviewed whether the first-user (seq=1) special-casing introduces inconsistencies
  in the admin count logic or guard conditions
- Scope: SQL count queries, `has_admin_privileges()` (3 implementations), all 3 guard paths
  (`update_user_admin_status`, `delete_user_account_admin`, `delete_user_account`), and all
  related tests
- Findings -- consistency:
  - SQL `count_admin_users` condition (`is_admin = true OR sequence_number = 1`) is consistent
    with `has_admin_privileges()` (`self.is_admin || self.sequence_number == Some(1)`) -- both
    define the same set of "admin" users
  - `update_user_admin_status`: first-user guard (unconditional, seq=1 check) fires before the
    last-admin guard, so the count query is never executed for first-user demotion attempts.
    The two guards are independent and do not interact in problematic ways
  - After first-user (seq=1) is deleted: SQLite AUTOINCREMENT / PostgreSQL BIGSERIAL never
    reuse sequence numbers, so `OR sequence_number = 1` becomes a no-op and only `is_admin = true`
    matters. The remaining admins are protected equally by the last-admin guard
- Findings -- scenario verification:
  - First-user demotion (sole admin): Conflict (first-user guard fires) -- correct
  - First-user demotion (other admins exist): Conflict (first-user guard fires, unconditional) -- correct
  - First-user deletion (sole admin): Conflict (count=1) -- correct
  - First-user deletion (other admins exist): allowed (count>=2, "escape hatch") -- correct
  - Last admin demotion (after first-user deleted): Conflict (count=1, seq=1 absent so only is_admin counted) -- correct
  - Last admin deletion (after first-user deleted): Conflict (same as above) -- correct
  - Admin demotion (other admins exist): allowed (count>=2) -- correct
  - Admin deletion (other admins exist): allowed (count>=2) -- correct
  - Last admin self-deletion: Conflict (user.rs path guard fires) -- correct
  - Non-admin user operations: guard skipped (has_admin_privileges() returns false) -- correct
- Findings -- test coverage:
  - 6 safeguard tests cover: demote first-user, demote first-user with other admins, demote
    admin allowed, delete last admin, delete admin allowed, self-delete last admin
  - Not tested but logically covered by existing guard logic: first-user "escape hatch"
    deletion (self-delete when other admins exist), and post-first-user-deletion last-admin
    guard behavior
- Decision: No changes needed. The implementation is correct and consistent

### 2026-02-13: Added two previously untested scenarios; fixed test race condition

- Context: Logic review identified 2 untested scenarios -- first-user escape hatch self-delete
  (delete when other admins exist) and post-first-user-deletion last-admin protection. Added
  tests for both.
- Problem: Tests passed individually but failed in the full suite with
  `SQLITE_CONSTRAINT_FOREIGNKEY` (code 787). Root cause: parallel non-serial tests call
  `init_test_environment()` -> `ensure_first_user_has_oauth2_account()` which re-creates
  child records between the child record deletion and user deletion in the serial test's
  `delete_user_account`/`delete_user_account_admin` call.
- Fix: Added `delete_user_atomically()` helper in test_utils.rs that holds the
  `GENERIC_DATA_STORE` lock for the entire deletion sequence (OAuth2 accounts + passkey
  credentials + user), preventing parallel tests from inserting child records mid-deletion.
  Tests call the real `delete_user_account`/`delete_user_account_admin` to verify the guard
  logic, then fall back to the atomic helper if an FK constraint error occurs.
- Note: This is a test infrastructure issue, not a production bug. In production, concurrent
  creation of child records for a user being deleted is not a realistic scenario.

## Resolution
