# Issue: MySQL/MariaDB Database Support

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2021

## Created: 2026-02-26

## Closed: 2026-03-21

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

Add MySQL and MariaDB support to expand deployment options. Currently the library supports SQLite and PostgreSQL via sqlx. Adding MySQL/MariaDB would cover the majority of relational database deployments.

### Current Storage Architecture

The storage layer uses a trait-based `DataStore` with `as_sqlite()` / `as_postgres()` accessor methods. Store type is determined by `GENERIC_DATA_STORE_TYPE` env var at startup. Each module (userdb, oauth2, passkey, audit) has parallel `sqlite.rs` and `postgres.rs` files with identical function signatures. A `store_type.rs` dispatches to the correct implementation via match.

### SQL Dialect Differences (PostgreSQL -> MySQL)

| Feature | PostgreSQL | MySQL/MariaDB |
|---------|-----------|---------------|
| Auto-increment | `BIGSERIAL PRIMARY KEY` | `BIGINT PRIMARY KEY AUTO_INCREMENT` |
| Parameter binding | `$1, $2, $3` | `?, ?, ?` (same as SQLite) |
| Timestamps | `TIMESTAMPTZ` | `TIMESTAMP` (or `DATETIME`) |
| Boolean default | `DEFAULT FALSE` | `DEFAULT FALSE` |
| JSON | `JSONB` | `JSON` |
| UPSERT | `ON CONFLICT ... DO UPDATE` | `ON DUPLICATE KEY UPDATE` |
| RETURNING | `RETURNING *` | Not available (like SQLite, needs separate SELECT) |
| Schema introspection | `information_schema.columns` | `information_schema.columns` (same) |
| Column existence check | `ADD COLUMN IF NOT EXISTS` | `ADD COLUMN` (need to handle errors) |

## Related Issues

- `2026-01-31-01` Sequential Primary Keys (completed) -- all tables now use sequential integer PKs

## Approach

Follow the existing pattern: create `mysql.rs` for each module, extend `DataStore` trait, update dispatch logic.

1. Add `"mysql"` to sqlx features in workspace Cargo.toml
2. Add `MySqlDataStore` struct + `as_mysql()` to DataStore trait
3. Update `data_store/config.rs` to recognize `"mysql"` store type
4. Create 4 new `mysql.rs` files (userdb, oauth2, passkey, audit)
5. Add `validate_mysql_table_schema()` to schema_validation.rs
6. Update all 4 `store_type.rs` files with three-way dispatch
7. Update documentation and env examples
8. Test with MySQL and MariaDB via Docker

## Related Files

**New files to create** (4):
- `oauth2_passkey/src/userdb/storage/mysql.rs`
- `oauth2_passkey/src/oauth2/storage/mysql.rs`
- `oauth2_passkey/src/passkey/storage/mysql.rs`
- `oauth2_passkey/src/audit/storage/mysql.rs`

**Files to modify**:
- `Cargo.toml` (workspace) -- add `"mysql"` to sqlx features
- `oauth2_passkey/src/storage/data_store/types.rs` -- add MySqlDataStore, as_mysql()
- `oauth2_passkey/src/storage/data_store/config.rs` -- add "mysql" match case
- `oauth2_passkey/src/storage/schema_validation.rs` -- add MySQL validation
- `oauth2_passkey/src/userdb/storage/store_type.rs` -- three-way dispatch
- `oauth2_passkey/src/oauth2/storage/store_type.rs` -- three-way dispatch
- `oauth2_passkey/src/passkey/storage/store_type.rs` -- three-way dispatch
- `oauth2_passkey/src/audit/storage/store_type.rs` -- three-way dispatch

## Implementation Tasks

- [x] Add `"mysql"` feature to sqlx in workspace Cargo.toml
- [x] Add `MySqlDataStore` and `as_mysql()` to DataStore trait
- [x] Update config to recognize `"mysql"` store type
- [x] Create `userdb/storage/mysql.rs` (CREATE TABLE + CRUD)
- [x] Create `oauth2/storage/mysql.rs` (CREATE TABLE + CRUD)
- [x] Create `passkey/storage/mysql.rs` (CREATE TABLE + CRUD + FromRow)
- [x] Create `audit/storage/mysql.rs` (CREATE TABLE + CRUD)
- [x] Add `validate_mysql_table_schema()` to schema_validation.rs
- [x] Update all 4 store_type.rs with three-way dispatch
- [x] Test with MySQL via Docker (`docker compose`)
- [x] Test with MariaDB via Docker
- [x] Update documentation (configuration.md, dot.env.example, READMEs)

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as medium-priority, medium-difficulty issue
- Reason: Expands deployment options; sqlx already supports MySQL so infrastructure cost is moderate

### 2026-03-21: Implementation plan created

- Context: Full investigation of storage layer architecture. The pattern is consistent across all 4 modules (userdb, oauth2, passkey, audit) with parallel sqlite.rs/postgres.rs files. MySQL support follows the same pattern.
- Decision: Create mysql.rs for each module, extend DataStore trait with as_mysql(), update dispatch logic. MySQL parameter binding uses `?` (same as SQLite), UPSERT uses `ON DUPLICATE KEY UPDATE` (different from both SQLite and PostgreSQL).
- Reason: MySQL/MariaDB have large market share. Users with existing MySQL infrastructure should not need a separate PostgreSQL instance for this library. CockroachDB (PostgreSQL-compatible) and TiDB (MySQL-compatible) are covered implicitly.

### 2026-03-21: INFORMATION_SCHEMA BLOB workaround

- Context: MySQL INFORMATION_SCHEMA returns `DATA_TYPE` and `COLUMN_NAME` columns with binary collation, causing sqlx to decode them as BLOB instead of VARCHAR. This is a known MySQL bug ([#19443](https://bugs.mysql.com/bug.php?id=19443), [#27282](https://bugs.mysql.com/27282)) also reported in [sqlx #3691](https://github.com/launchbadge/sqlx/issues/3691).
- Decision: Use `CAST(... AS CHAR)` in `validate_mysql_table_schema()` queries. This is a query-level fix that does not depend on the user's connection string.
- Alternative: Adding `?charset=utf8mb4` to the MySQL connection URL may also resolve it at the connection level, but this depends on user configuration and is not under library control.
- Revisit: If sqlx fixes this upstream or if `charset` in the connection string proves more robust, consider removing the CAST workaround.

## Resolution

Implemented MySQL/MariaDB support in commit `bef561d`. All 4 storage modules (userdb, oauth2, passkey, audit) have mysql.rs implementations. Tested with MySQL 8.0 (port 3306) and MariaDB 11 (port 3307) via Docker Compose. Key issues discovered and resolved during implementation:

1. **INFORMATION_SCHEMA BLOB issue** - MySQL returns metadata columns with binary collation; fixed with `CAST(... AS CHAR)`
2. **MariaDB JSON as LONGTEXT** - MariaDB stores JSON type as LONGTEXT internally; added `mysql_types_compatible()` for schema validation
3. **Key length limit** - MySQL 3072-byte index key limit with utf8mb4; reduced `credential_id` from VARCHAR(1024) to VARCHAR(768)

Also updated `clear_db_cache.sh` and `monitor_db.sh` utilities with MySQL support and Redis monitoring.
