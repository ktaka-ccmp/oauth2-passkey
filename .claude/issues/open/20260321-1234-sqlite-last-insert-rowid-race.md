# Issue: SQLite last_insert_rowid() Potential Race Condition

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260321-1234

## Created: 2026-03-21-12-34

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

In `audit/storage/sqlite.rs`, `insert_login_history_sqlite()` uses `last_insert_rowid()` in a separate SELECT after the INSERT, both executed on `pool` (not a transaction). While SQLite's single-writer constraint makes this unlikely to cause issues in practice, the same pattern was identified as a real bug in MySQL (fixed with a transaction in `audit/storage/mysql.rs`).

For consistency and correctness, the SQLite version should also wrap the INSERT + SELECT in a transaction, matching the MySQL fix and the PostgreSQL approach (which avoids the issue entirely via `RETURNING *`).

### Current code

```rust
// audit/storage/sqlite.rs
sqlx::query(...)
    .execute(pool)  // INSERT on connection A
    .await?;

sqlx::query_as(...)  // SELECT last_insert_rowid() potentially on connection B
    .fetch_one(pool)
    .await?;
```

### Risk assessment

- **SQLite**: Low risk. SQLite uses a single-writer lock, so concurrent INSERTs are serialized. However, with WAL mode and connection pooling, there's a theoretical window where `last_insert_rowid()` could return a stale value if another connection completed an INSERT between the two calls.
- **MySQL**: Fixed in commit `97b8ea6` by wrapping in a transaction.
- **PostgreSQL**: Not affected (uses `RETURNING *`).

## Related Issues

- `20260226-2021` MySQL/MariaDB Database Support (completed) -- same pattern discovered and fixed during MySQL implementation

## Approach

Wrap the INSERT + SELECT in a transaction, matching the MySQL fix:

```rust
let mut tx = pool.begin().await?;
sqlx::query(...).execute(&mut *tx).await?;
let result = sqlx::query_as(...).fetch_one(&mut *tx).await?;
tx.commit().await?;
```

## Related Files

- `oauth2_passkey/src/audit/storage/sqlite.rs` (lines 94-138)

## Implementation Tasks

- [ ] Wrap INSERT + SELECT `last_insert_rowid()` in a transaction in `audit/storage/sqlite.rs`
- [ ] Verify tests pass

## Decision Log

### 2026-03-21: Issue created from PR #274 review

- Context: PR review for MySQL/MariaDB support identified `LAST_INSERT_ID()` race condition in MySQL. The same pattern exists in SQLite with `last_insert_rowid()`. MySQL version was fixed with a transaction. SQLite version left as a separate issue due to lower practical risk.
- Decision: Create low-priority issue for consistency fix rather than fix inline, since SQLite's single-writer makes this unlikely to trigger in practice.
- Reason: Keeps the MySQL PR focused on its scope while tracking the pre-existing issue.

## Resolution