# Issue: upsert_oauth2_account SELECT after COMMIT race condition

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260322-0907

## Created: 2026-03-22

## Closed: 2026-03-22

## Status: completed

## Priority: low

## Difficulty: small

## Description

In `upsert_oauth2_account_sqlite()` and `upsert_oauth2_account_postgres()`, after the INSERT/UPDATE transaction is committed, a SELECT query is executed on `pool` to fetch the updated account. This creates a race condition where the SELECT could see stale data if another concurrent request modifies the same row between the COMMIT and the SELECT.

The MySQL version (`upsert_oauth2_account_mysql()`) already correctly executes the SELECT inside the transaction before committing.

### Current code (SQLite, lines 229-243)

```rust
// Commit transaction
tx.commit().await?;

// Return the updated account -- uses pool, not tx
let updated_account = sqlx::query_as::<_, OAuth2Account>(...)
    .bind(account_id)
    .fetch_one(pool)  // <-- race: another request could modify the row
    .await?;
```

### Current code (PostgreSQL, lines 221-237)

```rust
// Commit transaction
tx.commit().await?;

// Return the updated account -- uses pool, not tx
let updated_account = sqlx::query_as::<_, OAuth2Account>(...)
    .bind(account_id)
    .fetch_one(pool)  // <-- same race condition
    .await?;
```

### MySQL version (correct, lines 227-240)

```rust
// Fetch inside the transaction for read-your-writes consistency
let updated_account = sqlx::query_as::<_, OAuth2Account>(...)
    .bind(account_id)
    .fetch_one(&mut *tx)  // <-- inside transaction
    .await?;

tx.commit().await?;
```

### Risk assessment

- **SQLite**: Low risk due to single-writer lock, but still incorrect pattern with connection pooling
- **PostgreSQL**: Higher risk in production with concurrent requests
- **MySQL**: Already fixed

## Related Issues

- `20260321-1234` SQLite last_insert_rowid() Potential Race Condition (completed) -- same category of transaction consistency issue

## Approach

Move the SELECT inside the transaction (before `tx.commit()`), matching the MySQL implementation:

```rust
// Fetch inside the transaction for read-your-writes consistency
let updated_account = sqlx::query_as::<_, OAuth2Account>(...)
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

tx.commit().await?;

Ok(updated_account)
```

## Related Files

- `oauth2_passkey/src/oauth2/storage/sqlite.rs` (lines 229-243)
- `oauth2_passkey/src/oauth2/storage/postgres.rs` (lines 221-237)
- `oauth2_passkey/src/oauth2/storage/mysql.rs` (lines 227-240) -- reference implementation

## Implementation Tasks

- [x] Move SELECT inside transaction in `upsert_oauth2_account_sqlite()`
- [x] Move SELECT inside transaction in `upsert_oauth2_account_postgres()`
- [x] Verify tests pass

## Decision Log

### 2026-03-22: Issue created from codebase audit

- Context: After fixing `last_insert_rowid()` race in audit/storage/sqlite.rs, audited remaining codebase for similar patterns. Found two instances in oauth2/storage where SELECT runs on `pool` after transaction COMMIT.
- Decision: Create issue for consistency fix. MySQL version already has the correct implementation to use as reference.
- Reason: Same category of issue -- queries that should be inside a transaction are executed on the pool instead.

### 2026-03-22: Implemented fix

- Context: Fixing the post-COMMIT SELECT race condition.
- Decision: Moved SELECT before COMMIT using `&mut *tx`, matching the MySQL implementation.
- Reason: Standard sqlx pattern for read-your-writes consistency. No alternative approaches needed.

## Resolution

Moved SELECT inside the transaction (before `tx.commit()`) in both SQLite and PostgreSQL implementations, using `&mut *tx` instead of `pool`. This matches the MySQL implementation that already had the correct pattern. All three backends now consistently fetch inside the transaction for read-your-writes consistency.