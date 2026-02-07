# Issue: Add Sequential Primary Keys to oauth2_accounts and passkey_credentials Tables

## ID: 2026-01-31-01

## Status: open

## Priority: low

## Difficulty: medium

## Description

Based on analysis of database primary key design best practices (Kenn Ejima's large-scale system experience), consider adding sequential integer primary keys to tables that currently use TEXT primary keys.

### Background

The `users` table already follows the recommended pattern:
```sql
sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,  -- Internal pkey (sequential)
id TEXT NOT NULL UNIQUE,                             -- External public_id
```

However, `oauth2_accounts` and `passkey_credentials` tables use TEXT primary keys directly.

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

## Notes

Reference: Kenn Ejima's analysis on UUID vs sequential primary keys in large-scale systems (3000万ユーザー・10億API hits/日規模での経験に基づく)

Key insight: The `users` table already implements this pattern correctly. Sessions are stored in cache (Redis/memory), avoiding the B-tree locality issue entirely.

Current design is already well-architected for most use cases. This issue is tracked for potential future optimization if the library is used at very large scale.

## Resolution

