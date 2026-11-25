# Issue: Login History Retention Tests Fail on a Reused Database

## Metadata

- ID: 20261124-1130
- Created: 2026-11-24-11-30
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260321-1245` Multi-Database Integration Tests

## Problem

The `delete_old_entries` tests in
`oauth2_passkey/src/audit/storage/store_type/tests.rs` (added in
b22d4f5) pass on SQLite and in CI, but fail when run repeatedly against
a persistent PostgreSQL, MySQL or MariaDB database:

- `test_delete_old_entries_removes_old_keeps_recent`
- `test_delete_old_entries_no_old_entries`
- `test_delete_old_entries_multiple_old_entries`

SQLite is not affected because `init_test_environment()` deletes the
SQLite file at the start of each test process
(`test_utils.rs`). CI also starts from an empty database.

### Cause

The tests assume that `test_o2p_login_history` contains only the rows
they insert, but rows from earlier runs remain:

1. The cleanup at the end of each test calls
   `LoginHistoryStore::delete_old_entries(1)`. It removes only rows older
   than one day, so the rows inserted with `Utc::now()` are never
   removed. The comment in `removes_old_keeps_recent` says
   "Cleanup: delete the remaining entry", which this call does not do.
   `LoginHistoryStore` has no method to delete rows by user, so the
   cleanup cannot be written with the current API.
2. When an assertion fails, the test panics and the cleanup does not
   run, so the old rows it inserted (e.g. the 10-day-old row in
   `multiple_old_entries`) also remain.
3. `delete_old_entries` deletes across all users. Leftover rows that
   have become older than the cutoff are counted by the next test, so
   `deleted` no longer matches the expected value.
4. `get_by_user` returns leftover recent rows for the same fixed user
   IDs (`user_retention_test`, `user_retention_multi`), so the
   `remaining.len()` assertions fail.

The number of failures depends on the age of the leftover rows. On
2026-11-24 the same test list failed 2 tests on the first run (leftover
rows from a run a few days earlier) and 3 tests on a run two minutes
later (leftover rows from the first run).

Other tests also write to the same table: the OAuth2 and passkey login
flows (`coordination/{oauth2,passkey}.rs` via `record_login_success` /
`record_login_failure`) are exercised by
`coordination/oauth2/tests.rs`, `coordination/passkey/tests.rs` and the
axum integration tests. Their rows can become "old" and be counted by
`delete_old_entries` in the same way. No test reads the
`user_retention_*` rows, so they are not left on purpose for reuse.

## Timeline

## Latest Plan

Make each test independent of existing rows. Options:

- Delete all rows of `test_o2p_login_history` at the start of each test
  (the tests are already `#[serial]`), via a test-only helper.
- Or assert relative to the state before the test: use unique user IDs
  per run, and compare `deleted` against a count of rows older than the
  cutoff taken just before the call.

Either way, remove the misleading cleanup code at the end of the tests.

### Files

- `oauth2_passkey/src/audit/storage/store_type/tests.rs`
- `oauth2_passkey/src/test_utils.rs` (if a helper is added)

### Implementation Tasks

- [ ] Choose the approach (clear table vs. relative assertions)
- [ ] Update the three tests
- [ ] Remove the ineffective cleanup at the end of the tests

### Verification

- Run the four `delete_old_entries` tests twice in a row against
  PostgreSQL, MySQL and MariaDB without resetting the database; all
  pass both times.
- SQLite `cargo test` still passes.

## Resolution
