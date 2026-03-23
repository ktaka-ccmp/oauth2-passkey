# Issue: Review delete_old_entries Dead Code and Retention Policy

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260321-1346

## Created: 2026-03-21-13-46

## Closed: 2026-03-23

## Status: completed

## Priority: low

## Difficulty: small

## Description

`delete_old_entries_sqlite`, `delete_old_entries_postgres`, and `delete_old_entries_mysql` exist in audit storage modules with `#[allow(dead_code)]`. They are not called from `LoginHistoryStore` (no dispatch in `store_type.rs`) and were presumably written in anticipation of a login history retention policy feature.

Issues to address:

1. **Necessity**: Is a retention policy needed? If yes, wire up the functions. If no, remove the dead code.
2. **Input validation**: If kept, `days_to_keep` (i64) should validate `> 0`. A negative value produces `DATE_SUB(NOW(), INTERVAL -N DAY)` which effectively becomes `DATE_ADD`, silently deleting future-dated records. Not a security issue (parameter is not user-controlled), but a correctness concern.
3. **Consistency**: If wired up, all 3 DB backends need the same validation and dispatch logic.

## Related Issues

- `20260226-2021` MySQL/MariaDB Database Support (completed) -- PR review identified this dead code

## Approach

Decide whether to:
- **A**: Wire up with a `LOGIN_HISTORY_RETENTION_DAYS` env var and scheduled cleanup
- **B**: Remove the dead code entirely (YAGNI)
- **C**: Keep as-is but add validation guard

## Related Files

- `oauth2_passkey/src/audit/retention.rs` (new: public API + spawn helper)
- `oauth2_passkey/src/audit/storage/config.rs` (O2P_LOGIN_HISTORY_RETENTION_DAYS)
- `oauth2_passkey/src/audit/storage/store_type.rs` (delete_old_entries dispatch)
- `oauth2_passkey/src/audit/storage/sqlite.rs` (delete_old_entries_sqlite)
- `oauth2_passkey/src/audit/storage/postgres.rs` (delete_old_entries_postgres)
- `oauth2_passkey/src/audit/storage/mysql.rs` (delete_old_entries_mysql)
- `oauth2_passkey/src/lib.rs` (re-export)
- `oauth2_passkey_axum/src/lib.rs` (re-export)
- `demo-both/src/main.rs`, `demo-live/src/main.rs` (spawn helper usage)

## Implementation Tasks

- [x] Decide: wire up, remove, or keep with validation -> Option A (wire up)
- [x] Add dispatch in store_type.rs with days_to_keep > 0 validation
- [x] Add `O2P_LOGIN_HISTORY_RETENTION_DAYS` env var (default 0 = disabled)
- [x] Add public `cleanup_old_login_history()` and `spawn_login_history_cleanup()` APIs
- [x] Remove `#[allow(dead_code)]` from all 3 backends
- [x] Replace SQL string interpolation with parameterized cutoff timestamp
- [x] Add 5 tests
- [x] Add to demo-both and demo-live

## Decision Log

### 2026-03-21: Issue created from PR #274 review

- Context: Second review of MySQL/MariaDB PR noted `delete_old_entries_mysql` interpolates `days_to_keep` into SQL. While safe (i64, not user input), negative values have unexpected behavior. Same pattern exists in SQLite and PostgreSQL.
- Decision: Create issue to review the dead code holistically rather than adding a point fix to MySQL only.
- Reason: The question is broader than input validation -- whether the retention policy feature itself is needed.

### 2026-03-23: Chose Option A (wire up) and implemented

- Context: Decided to wire up the existing dead code rather than remove it.
- Decision: Option A -- add env var, dispatch, public API, and background task helper. Also fixed SQL string interpolation (PR review feedback) by computing cutoff timestamp in Rust and binding as parameter.
- Reason: The code was already implemented for all 3 backends. Wiring up was minimal work. Retention policy is a reasonable feature for production deployments.

## Resolution

Chose Option A: wired up the existing `delete_old_entries_*` functions with full retention policy support.

- `O2P_LOGIN_HISTORY_RETENTION_DAYS` env var (default 0 = disabled)
- `cleanup_old_login_history()` public function for on-demand cleanup
- `spawn_login_history_cleanup()` opt-in background task (24h interval)
- `LoginHistoryStore::delete_old_entries()` dispatch with `days_to_keep > 0` validation
- Removed `#[allow(dead_code)]` from all 3 backends
- Replaced SQL string interpolation with parameterized cutoff timestamp (PR review fix)
- Tightened `O2P_LOGIN_HISTORY_RETENTION_DAYS` visibility to `pub(in crate::audit)`
- 5 tests covering delete/keep, multiple entries, validation, no-op, and disabled cases
- Integrated into demo-both and demo-live
- PR #285