# Issue: MySQL/MariaDB Compare Identifiers Case-Insensitively

## Metadata

- ID: 20261120-0852
- Created: 2026-11-20-08-52
- Closed:
- Status: open
- Priority: medium
- Difficulty: medium
- Related Issues:
  - `20260226-2021` MySQL/MariaDB Database Support (completed)
  - `20260321-1245` Multi-Database Integration Tests

## Problem

On MySQL and MariaDB, string comparisons on identifier columns ignore
case, while SQLite and PostgreSQL compare them exactly. Several
identifiers stored by the library are case-sensitive (for example
base64url credential IDs and user handles), so the backends behave
differently.

Based on examination of the code and test databases on 2026-11-20:

- The `CREATE TABLE` statements in
  `oauth2_passkey/src/{userdb,passkey,oauth2,audit}/storage/mysql.rs`
  specify no character set or collation, so the server default applies.
- Test tables were created with:
  - MySQL 8.0.46: `utf8mb4_0900_ai_ci`
  - MariaDB 11.8.9: `utf8mb4_uca1400_ai_ci`
- Both are case- and accent-insensitive. On both servers,
  `SELECT ... WHERE credential_id = UPPER('<stored lowercase id>')`
  returned the stored row.
- The same query returned no row on SQLite (default `BINARY`) and on
  PostgreSQL 18.7.
- Consequences (by reasoning, not tested):
  - Lookups by such a column can match a value that differs only in
    case.
  - `UNIQUE` constraints treat such values as duplicates.

Columns to review (VARCHAR identifiers):

| Table | Columns |
|-------|---------|
| users | `id` (UNIQUE) |
| passkey credentials | `credential_id` (UNIQUE), `user_id`, `user_handle`, `aaguid`, `rp_id` |
| oauth2 accounts | `id` (UNIQUE), `user_id`, `provider`, `provider_user_id` (UNIQUE with `provider`) |
| audit / login history | `user_id`, `credential_id`, `provider`, `provider_user_id` |

Whether any code path relies on exact matching in a way that matters
was not checked.

## Timeline

## Latest Plan

1. Decide the target: exact (binary) comparison for identifier columns,
   e.g. `COLLATE utf8mb4_bin` or `VARBINARY`. Display fields such as
   names and email can keep the default.
2. Apply it to new tables, and decide how existing tables are migrated
   (`oauth2_passkey/src/storage/schema_validation.rs` checks only
   column names and data types, not collation).
3. Add a test that stores an ID and confirms that a case-variant lookup
   finds nothing, run against all backends.

### Files

- `oauth2_passkey/src/userdb/storage/mysql.rs`
- `oauth2_passkey/src/passkey/storage/mysql.rs`
- `oauth2_passkey/src/oauth2/storage/mysql.rs`
- `oauth2_passkey/src/audit/storage/mysql.rs`
- `oauth2_passkey/src/storage/schema_validation.rs`

### Implementation Tasks

- [ ] Decide collation / type per column
- [ ] Update table creation
- [ ] Migration or startup check for existing tables
- [ ] Cross-backend test

### Verification

- Case-variant lookups return no row on MySQL and MariaDB, matching
  SQLite and PostgreSQL.

## Resolution
