# Issue: Global Store Mutex Serializes All Database and Cache Access

## Metadata

- ID: 20261125-0121
- Created: 2026-11-25-01-21
- Closed:
- Status: open
- Priority: medium
- Difficulty: medium
- Related Issues:
  - `20261125-0018` Database-Backed Cache Store (Persistent Sessions Without Redis)
  - `20261120-0851` Core Crate Tests Hang on PostgreSQL When Several Run Together

## Problem

Both global stores are wrapped in a `tokio::sync::Mutex`, and callers
hold the lock while awaiting the query or cache operation. As a result,
only one database operation and one cache operation can run at a time
in the whole process, regardless of the sqlx pool size or Redis.

Based on examination of the code on 2026-11-25 (origin/dev 13fde6c):

- `GENERIC_DATA_STORE: LazyLock<Mutex<Box<dyn DataStore>>>`
  (`oauth2_passkey/src/storage/data_store/config.rs:17`), with
  `tokio::sync::Mutex` (`:4`).
- `GENERIC_CACHE_STORE: LazyLock<Mutex<Box<dyn CacheStore>>>`
  (`oauth2_passkey/src/storage/cache_store/config.rs:14`).
- Data store callers keep the guard across the query, e.g.
  `oauth2_passkey/src/passkey/storage/store_type.rs:45-48`:
  `let store = GENERIC_DATA_STORE.lock().await;` followed by
  `store_credential_sqlite(pool, ...).await`. 28 `lock()` call sites
  outside tests.
- Cache callers lock and await in one expression, so the temporary guard
  lives until the operation completes, e.g.
  `oauth2_passkey/src/storage/cache_operations.rs:36-41`
  (`GENERIC_CACHE_STORE.lock().await.get(...).await`); also
  `session/main/{session,user_sessions,page_session_token}.rs`.
- The lock is not needed for the data store: `DataStore` has only
  `&self` methods returning `&Pool<_>`
  (`storage/data_store/types.rs:20-24`), and sqlx pools are `Send + Sync`
  and cheap to clone.
- For the cache store, the trait methods take `&mut self` (e.g.
  `remove(&mut self, ...)`, `storage/cache_store/types.rs:64`), which is
  why the mutex exists. `InMemoryCacheStore` holds a plain `HashMap`
  (`types.rs:27-29`). `RedisCacheStore` holds a `redis::Client`
  (`types.rs:31-33`) and opens a new multiplexed connection on every
  operation (`cache_store/redis.rs:26, 41, 56, 68, 82`).

- `docs/src/appendix/storage-pattern.md:69` says
  `delete_user_atomically()` holds the data store mutex during user
  deletion to avoid foreign key errors. That function no longer exists
  (removed around `c293643`); user deletion now relies on
  `ON DELETE CASCADE` (`coordination/user.rs:133-147`). The doc is
  stale, but other code may still rely on the serialization implicitly.

History of the mutex:

- Introduced on 2025-02-11 (`0456239`, `57c3149`) when the stores were
  in-memory / Redis token stores. Its stated purpose was replacing the
  store at runtime (`*TOKEN_STORE.lock().await = new_store`, including
  switching via Unix signals; daily journal 2025-02-11).
- Free replacement ended the same day (`90a2596`, store can be set only
  once); the set-once setter was removed on 2025-03-04 (`27476a5`,
  stores are created lazily from env vars). Since then the mutex only
  serves the `&mut self` methods of the cache store trait, and it was
  applied to the data store as well.
- It caused a deadlock in `fetch_jwks_cache()` (issue `20260211-1742`,
  `.claude/issues/JOURNAL.md` 2026-02-11), and was used as an implicit
  transaction for user deletion in tests (`delete_user_atomically()`,
  2026-02-13, later removed).

Impact: every request that touches sessions or the database waits for
other requests' DB / Redis round trips. This includes every
authenticated request: `get_user_from_session` does a cache lookup and
`UserStore::get_user` (`session/main/session.rs:221-231`). Throughput is limited to one
in-flight operation per store. Not measured.

Possibly related: test hangs on PostgreSQL when several tests run
together (`20261120-0851`), unverified.

## Timeline

## Latest Plan

1. Measure first: a small load test (concurrent session lookups and
   passkey/credential reads) before and after, on SQLite, PostgreSQL and
   Redis.
2. Data store: drop the mutex. Store the boxed store (or the pool
   enum) directly, e.g. `LazyLock<Box<dyn DataStore>>` or
   `OnceLock<...>`; callers borrow the pool without locking.
3. Cache store: change the trait to `&self` and move synchronization
   inside the implementations:
   - memory: a sharded or `RwLock`/`Mutex`-protected map held only for
     the synchronous map operation (never across `.await`);
   - Redis: keep one `MultiplexedConnection` or
     `redis::aio::ConnectionManager` (clone per call) instead of
     opening a connection per operation.
4. Keep the public API unchanged.

This is independent of the env-var vs passed-state discussion and can
be done within the current global design.

### Files

- `oauth2_passkey/src/storage/data_store/{config,types}.rs`
- `oauth2_passkey/src/storage/cache_store/{config,types,memory,redis}.rs`
- `oauth2_passkey/src/storage/cache_operations.rs`
- `oauth2_passkey/src/session/main/*.rs`
- all `*/storage/store_type.rs` that call `GENERIC_DATA_STORE.lock()`

### Implementation Tasks

- [ ] Load test to measure current behavior
- [ ] Audit code that holds one guard across several queries and may
      rely on the serialization for atomicity; use transactions or
      single statements there
- [ ] Remove the data store mutex
- [ ] Update `docs/src/appendix/storage-pattern.md` (stale
      `delete_user_atomically()` description)
- [ ] `&self` cache store trait; internal synchronization for memory
- [ ] Reuse Redis connections
- [ ] Re-run the load test

### Verification

- Concurrent requests complete in parallel (load test numbers).
- `cargo test`, storage tests on SQLite, PostgreSQL, MySQL, MariaDB;
  axum tests; clippy, fmt.

## Resolution
