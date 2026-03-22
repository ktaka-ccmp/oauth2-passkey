# Issue: Passkey Counter Verification TOCTOU Race Condition

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260322-0926

## Created: 2026-03-22

## Closed: 2026-03-22

## Status: completed

## Priority: high

## Difficulty: medium

## Description

In `passkey/main/auth.rs`, the WebAuthn authentication counter verification follows a GET -> CHECK -> UPDATE pattern across separate storage calls without atomicity. This is a classic TOCTOU (Time-of-Check-to-Time-of-Use) race condition with security implications.

### Current code flow

```rust
// 1. GET: Fetch credential from database (line ~134)
let stored_credential = PasskeyStore::get_credential(credential_id.clone()).await?;

// 2. CHECK: Compare counters in Rust logic (line ~262)
if auth_counter <= stored_credential.counter {
    return Err(PasskeyError::Authentication(...));
}

// 3. UPDATE: Write new counter to database (line ~281)
PasskeyStore::update_credential_counter(credential_id.clone(), auth_counter).await?;
```

### Risk

A concurrent authentication on the same credential could update the counter between the GET and UPDATE, potentially allowing counter inconsistency or replay attacks.

### Why this is harder than previous transaction fixes

The GET and UPDATE go through separate `PasskeyStore` trait methods. The current storage API passes `pool`, not a transaction object. Fixing requires either:
1. Changing the Store trait API to support transactions
2. Creating an atomic storage method (e.g., `UPDATE ... WHERE counter < ? RETURNING ...`)
3. Using database-level locking

## Related Issues

- `20260321-1234` SQLite last_insert_rowid() race (completed) -- same category of transaction consistency
- `20260322-0907` upsert_oauth2_account post-tx SELECT race (open) -- same category

## Approach

Option A (preferred): Add an atomic storage method that does CHECK + UPDATE in a single SQL statement:

```sql
-- SQLite/MySQL
UPDATE credentials SET counter = ? WHERE credential_id = ? AND counter < ?

-- PostgreSQL
UPDATE credentials SET counter = $1 WHERE credential_id = $2 AND counter < $1 RETURNING *
```

If rows_affected == 0, the counter check failed (either credential not found or counter not less than new value).

Option B: Pass a transaction through the Store trait API (larger refactor).

## Related Files

- `oauth2_passkey/src/passkey/main/auth.rs` (lines ~134, ~262, ~281)
- `oauth2_passkey/src/passkey/storage/sqlite.rs`
- `oauth2_passkey/src/passkey/storage/mysql.rs`
- `oauth2_passkey/src/passkey/storage/postgres.rs`

## Implementation Tasks

- [x] Design atomic counter verification approach
- [x] Implement atomic counter update in SQLite storage
- [x] Implement atomic counter update in MySQL storage
- [x] Implement atomic counter update in PostgreSQL storage
- [x] Update auth.rs to use atomic method
- [x] Verify tests pass

## Decision Log

### 2026-03-22: Issue created from codebase transaction audit

- Context: Deep audit of all SQL operations for missing transactions. Found that passkey counter verification uses a GET->CHECK->UPDATE pattern across separate storage calls.
- Decision: Create separate high-priority issue since this has security implications (replay attack risk) and requires a different fix approach than the simpler storage-layer transaction fixes.
- Reason: The fix crosses abstraction boundaries (auth logic <-> storage layer), making it more complex than wrapping queries in a transaction.

### 2026-03-22: Implemented Option A (atomic SQL statement)

- Context: Implementing the fix for the TOCTOU race condition.
- Decision: Used `UPDATE ... SET counter = ? WHERE credential_id = ? AND counter < ?` across all three backends. Also replaced old `update_credential_counter` with `atomic_update_credential_counter`, fixed i32 truncation in MySQL/PostgreSQL by using i64, and added security doc comments to `verify_counter()`.
- Reason: Option A is the simplest and most effective approach. No transaction API changes needed. Single SQL statement is inherently atomic.

## Resolution

Implemented Option A: atomic `UPDATE ... WHERE counter < ?` for all three database backends (SQLite, MySQL, PostgreSQL).

- Replaced separate CHECK + UPDATE with `atomic_update_credential_counter` that returns `bool` (true if counter was updated)
- Removed old non-atomic `update_credential_counter` (dead code)
- Fixed `counter as i32` truncation in MySQL/PostgreSQL by using i64 (consistent with SQLite)
- Added security background doc comments to `verify_counter()` explaining counter's role (clone detection, not replay prevention)
- Simplified test helper `verify_counter_with_mock` -> `verify_counter_without_db`
- PR #282
