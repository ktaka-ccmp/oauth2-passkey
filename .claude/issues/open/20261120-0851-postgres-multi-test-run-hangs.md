# Issue: Core Crate Tests Hang on PostgreSQL When Several Run Together

## Metadata

- ID: 20261120-0851
- Created: 2026-11-20-08-51
- Closed:
- Status: open
- Priority: low
- Difficulty: medium
- Related Issues:
  - `20260321-1245` Multi-Database Integration Tests
  - `20261117-0727` Filtered Test Runs Fail with "ORIGIN must be set"

## Problem

With `.env_test` pointed at PostgreSQL, running several core crate
tests in one `cargo test` process hangs, while the same tests pass when
run one at a time.

Observed on 2026-11-17 (PostgreSQL 18.7 in `db/postgresql`):

- A run with three name filters (registration tests in
  `passkey::main::register::tests` plus `passkey::storage` tests)
  produced no progress for more than 5 minutes and was killed. The
  exact command line was not recorded.
- Each of the same 17 tests run alone with
  `cargo test -p oauth2-passkey --lib -- --exact <test>` passed in
  about 0.3 s.
- The same 17 tests run one at a time on MySQL 8.0.46 and
  MariaDB 11.8.9 also passed (0.03-0.24 s each). A multi-test run on
  those backends was not tried.

The cause was not investigated. Candidates (not verified): connection
pool exhaustion or a lock wait between concurrently running tests on
the shared `test_o2p_` tables, or interaction with the lazily
initialized globals described in `20261117-0727`.

Note: `test_utils.rs` loads `.env_test` with
`dotenvy::from_filename_override`, so environment variables cannot
switch the backend; the file must be edited.

## Timeline

## Latest Plan

1. Reproduce with a fixed command (e.g. `cargo test -p oauth2-passkey
   --lib passkey::storage`) and with `--test-threads=1` to tell
   concurrency from ordering problems.
2. While hung, inspect `pg_stat_activity` / `pg_locks` for waiting
   queries.
3. Fix the cause, then include PostgreSQL in the CI matrix planned in
   `20260321-1245`.

### Files

- `oauth2_passkey/src/test_utils.rs`
- `oauth2_passkey/src/storage/data_store/` (pool setup)
- `.env_test`

### Implementation Tasks

- [ ] Reproduce with a recorded command
- [ ] Identify the blocking point
- [ ] Fix and verify a full `cargo test` run on PostgreSQL

### Verification

- `cargo test --no-fail-fast` completes on PostgreSQL.

## Resolution
