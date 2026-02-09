# Issue: Sequential Primary Keys Optimization

## Table of Contents

- [Description](#description)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-31-01

## Status: open

## Priority: low

## Difficulty: medium

## Description

Consider adding sequential integer primary keys to `oauth2_accounts` and
`passkey_credentials` tables that currently use TEXT primary keys, following
the pattern already established in the `users` table.

### Background

The `users` table already follows the recommended pattern:
```sql
sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,  -- Internal pkey (sequential)
id TEXT NOT NULL UNIQUE,                             -- External public_id
```

However, `oauth2_accounts` and `passkey_credentials` tables use TEXT primary keys directly.

## Approach

### Current State

**oauth2_accounts:**
```sql
id TEXT PRIMARY KEY NOT NULL,  -- Random string as pkey
```

**passkey_credentials:**
```sql
credential_id TEXT PRIMARY KEY NOT NULL,  -- WebAuthn credential ID as pkey
```

### Proposed Change

**oauth2_accounts:**
```sql
sequence_number BIGSERIAL PRIMARY KEY,
id TEXT NOT NULL UNIQUE,  -- Keep as public identifier
```

**passkey_credentials:**
```sql
sequence_number BIGSERIAL PRIMARY KEY,
credential_id TEXT NOT NULL UNIQUE,  -- Keep as WebAuthn identifier
```

### Benefits

1. **B-tree locality**: Sequential inserts keep new data physically adjacent
2. **Space efficiency**: INTEGER/BIGINT foreign keys are 4-8 bytes vs ~43 bytes for base64url strings
3. **Join performance**: Smaller keys = more keys fit in CPU cache/memory
4. **Future scalability**: Avoids premature sharding needs at large scale

### Trade-offs

- Additional column in each table
- Migration complexity for existing data
- Current scale (small to medium) may not benefit significantly
- `passkey_credentials.credential_id` is WebAuthn-specified, must remain as unique identifier

### When to Implement

This optimization is primarily beneficial when:
- QPS reaches thousands per second
- Tables grow to millions of rows
- Foreign key joins become frequent

For small to medium scale deployments, the current design is sufficient.

## Related Files

- `oauth2_passkey/src/oauth2/storage/sqlite.rs`
- `oauth2_passkey/src/oauth2/storage/postgres.rs`
- `oauth2_passkey/src/passkey/storage/sqlite.rs`
- `oauth2_passkey/src/passkey/storage/postgres.rs`
- `oauth2_passkey/src/oauth2/types.rs`
- `oauth2_passkey/src/passkey/types.rs`

## Implementation Tasks

- [ ] Add `sequence_number` column to `oauth2_accounts` schema
- [ ] Add `sequence_number` column to `passkey_credentials` schema
- [ ] Update storage layer for both SQLite and PostgreSQL
- [ ] Handle migration for existing data
- [ ] Update type definitions

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-31: Issue created as future optimization

- Context: Analysis of database primary key design best practices (based on
  large-scale system experience with 30M+ users, 1B+ API hits/day)
- Decision: Track as low-priority issue; current design is already well-architected
  for most use cases
- Reason: The `users` table already implements the sequential pkey pattern correctly.
  Sessions are stored in cache (Redis/memory), avoiding B-tree locality issues.
  Benefits only materialize at very large scale (millions of rows, thousands of QPS).

## Resolution

