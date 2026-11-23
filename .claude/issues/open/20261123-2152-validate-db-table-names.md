# Issue: Validate Configured DB Table Names and Centralize AssertSqlSafe

## Metadata

- ID: 20261123-2152
- Created: 2026-11-23-21-52
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

Table names are interpolated into SQL with `format!`, and nothing
checks that the configured names are valid identifiers.

- Table names come from environment variables: `DB_TABLE_PREFIX`
  (default `o2p_`, `storage/data_store/config.rs`) and
  `DB_TABLE_USERS`, `DB_TABLE_OAUTH2_ACCOUNTS`,
  `DB_TABLE_PASSKEY_CREDENTIALS`, `DB_TABLE_LOGIN_HISTORY` (each
  module's `storage/config.rs`).
- Identifiers cannot be bound as parameters, so the storage code builds
  SQL with `format!`. Values are still bound.
- Since sqlx 0.9 (PR #356), such strings must be wrapped in
  `sqlx::AssertSqlSafe`. There are 120 call sites in 14 files
  (`{audit,oauth2,passkey,userdb}/storage/{mysql,postgres,sqlite}.rs`,
  `storage/schema_validation.rs`, `test_utils.rs`).
- The values are operator configuration, not user input. However, a
  typo or unexpected character produces a confusing SQL error at first
  use instead of a clear error at startup.
- Some code derives index names with `table.replace('.', "_")`, so a
  schema-qualified name (`schema.table`) appears to be an intended
  form. Validation has to allow it.

## Timeline

## Latest Plan

1. Validate each configured table name at startup (for example
   `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`), and fail
   with a clear error naming the variable.
2. Introduce one helper (or a validated table-name newtype) that is the
   only place calling `AssertSqlSafe`, and use it from the storage
   modules.

### Files

- `oauth2_passkey/src/storage/data_store/config.rs`
- `oauth2_passkey/src/{audit,oauth2,passkey,userdb}/storage/config.rs`
- `oauth2_passkey/src/{audit,oauth2,passkey,userdb}/storage/{mysql,postgres,sqlite}.rs`
- `oauth2_passkey/src/storage/schema_validation.rs`

### Implementation Tasks

- [ ] Confirm which name forms must be supported (plain, `schema.table`)
- [ ] Add the validation and run it during initialization
- [ ] Add the helper and replace direct `AssertSqlSafe` uses
- [ ] Unit tests for accepted and rejected names

### Verification

- An invalid `DB_TABLE_PREFIX` fails at startup with a clear message.
- Storage tests pass on SQLite, PostgreSQL, MySQL and MariaDB.

## Resolution
