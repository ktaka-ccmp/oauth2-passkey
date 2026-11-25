# Issue: Database-Backed Cache Store (Persistent Sessions Without Redis)

## Metadata

- ID: 20261125-0018
- Created: 2026-11-25-00-18
- Closed:
- Status: open
- Priority: medium
- Difficulty: medium
- Related Issues:
  - `20261124-1130` Login History Retention Tests Fail on a Reused Database
  - `20261120-0851` Core Crate Tests Hang on PostgreSQL When Several Run Together

## Problem

Without Redis, sessions do not survive a restart and cannot be shared
between processes.

Based on examination of the code on 2026-11-25 (origin/dev 13fde6c):

- There are two stores:
  - Data store (`GENERIC_DATA_STORE_TYPE`): SQLite, PostgreSQL,
    MySQL/MariaDB. Holds users, OAuth2 accounts, passkey credentials,
    login history.
  - Cache store (`GENERIC_CACHE_STORE_TYPE`): only `memory` or `redis`
    (`oauth2_passkey/src/storage/cache_store/config.rs:24-26`). Holds
    login sessions (`session/main/user_sessions.rs`), passkey
    challenges, OAuth2 state / nonce / PKCE, CSRF and page session
    data, JWKS, etc.
- With `memory`, every restart or deploy signs all users out (users and
  credentials remain in the database), and multiple processes behind a
  load balancer do not share sessions.
- Alternatives store sessions in SQL: `tower-sessions` with
  `tower-sessions-sqlx-store`, and Torii (SQLite repository). Found in
  the 2026-11-24 comparison study.
- Running Redis only to keep sessions is a burden for small
  deployments.

The `CacheStore` trait (`storage/cache_store/types.rs:37`) has five
operations: `put`, `put_with_ttl`, `get`, `remove`,
`put_if_not_exists`. Implementations live next to each other
(`memory.rs`, `redis.rs`).

## Timeline

## Latest Plan

Add a cache store implementation that uses the configured data store
(SQLite, PostgreSQL, MySQL/MariaDB), selected with e.g.
`GENERIC_CACHE_STORE_TYPE=database` (name to be decided), so no extra
connection settings are needed.

- Table `(prefix, key, value, expires_at)`, primary key
  `(prefix, key)`, created like the other tables (`DB_TABLE_PREFIX`).
- `get`: ignore expired rows.
- `put_if_not_exists`: atomic insert (`ON CONFLICT DO NOTHING` on
  SQLite / PostgreSQL, `INSERT IGNORE` or equivalent on MySQL), treating
  an expired existing row as absent.
- Expired-row cleanup: periodic task similar to the login history
  retention task (`audit/retention.rs:21`), and/or opportunistic
  deletion.
- Initialization order: the cache store now depends on the data store.

Positioning: an option for small deployments. SQLite allows one writer
at a time, and every sign-in and passkey ceremony writes to the cache,
so Redis remains the recommendation for larger sites.

### Files

- `oauth2_passkey/src/storage/cache_store/` (new implementation, config)
- `oauth2_passkey/src/storage/data_store/` (pool access)
- `dot.env.example`, `docs/src/` (configuration)

### Implementation Tasks

- [ ] Decide the setting name and table name
- [ ] Implement for SQLite, PostgreSQL, MySQL/MariaDB
- [ ] Expired-row cleanup
- [ ] Tests that do not depend on leftover rows (see `20261124-1130`)
- [ ] Docs and `dot.env.example`

### Verification

- With SQLite data store and the new cache store: sign in, restart the
  server, the session is still valid.
- Two processes sharing one PostgreSQL database share sessions.
- Storage tests on SQLite, PostgreSQL, MySQL and MariaDB.

## Resolution
