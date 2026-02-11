# Issue: OAuth2 Callback Deadlock on JWKS Cache Expiry

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260211-1742

## Created: 2026-02-11-17-42

## Closed: 2026-02-11

## Status: completed

## Priority: high

## Difficulty: medium

## Description

### Observed Behavior

During Docker container testing with in-memory cache (`GENERIC_CACHE_STORE_TYPE=memory`), the OAuth2 login flow deadlocks exactly 10 minutes after the first successful login:

1. First login succeeds (JWKS fetched and cached with 600s TTL)
2. Subsequent logins within 10 minutes succeed (JWKS served from cache)
3. After 10 minutes (JWKS cache expired), the next login attempt hangs permanently
4. Server logs show "Removing expired JWKs from cache" as the last message, with no further output
5. The 30-second HTTP timeout never fires because the code never reaches the HTTP request
6. The server becomes completely unresponsive for all authentication operations

### Root Cause: tokio::sync::Mutex Deadlock in `fetch_jwks_cache()`

In `idtoken.rs:146-203`, the `if let` pattern holds the `MutexGuard` as a temporary through the entire block body:

```rust
// Line 153: MutexGuard acquired as temporary in if-let scrutinee
if let Some(cached) = GENERIC_CACHE_STORE
    .lock()          // <-- MutexGuard created here
    .await
    .get(...)
    .await
    .map_err(...)?
{
    // MutexGuard STILL ALIVE here (temporary scope extends through body)

    if jwks_cache.expires_at > Utc::now() {
        return Ok(jwks_cache.jwks);  // Early return - guard dropped, OK
    }

    // Line 169: DEADLOCK - re-acquiring same non-reentrant Mutex
    GENERIC_CACHE_STORE
        .lock()      // <-- Waits forever: guard from line 153 still held
        .await
        .remove(...)
```

`tokio::sync::Mutex` is **not reentrant**. When the same task tries to acquire it twice, it deadlocks.

### Why It Only Manifests with In-Memory Cache

The deadlock path is only reached when `get()` returns an **expired** entry (triggers the `if let` body with re-lock). The cache backend determines whether this path is reachable:

- **Redis**: Implements TTL natively. After 600s, Redis auto-deletes the entry. `get()` returns `None`, code skips the `if let` body entirely -> **no deadlock**
- **In-memory**: `put_with_ttl()` ignores the `_ttl` parameter (`memory.rs:37-46`). Entries persist forever. `get()` returns the expired entry, code enters the `if let` body and re-locks -> **deadlock**

### Why It Was Not Caught During Development

During development with `cargo run`, the typical environment uses Redis for cache (`GENERIC_CACHE_STORE_TYPE=redis`). Redis auto-expires JWKS entries after the TTL, so the expired-entry code path is never reached and the deadlock never triggers. The Docker container uses `GENERIC_CACHE_STORE_TYPE=memory`, which exposed the bug.

### Additional Issue: `idtoken.rs` Bypasses `cache_operations` Module

`idtoken.rs` is the **only non-test file** that directly uses `GENERIC_CACHE_STORE`. All other cache operations go through `cache_operations.rs`, which properly scopes each lock acquisition in separate functions. If `idtoken.rs` had used the `cache_operations` module, the deadlock would have been structurally impossible.

## Related Issues

- `2026-01-30-08` Demo Site Deployment (Cloud Run) (related: discovered during Docker testing)
- `2026-02-09-02` Improve OAuth2 Popup Error Handling UX (related: popup UX during failures)

## Approach

### Fix 1: Eliminate the Deadlock (primary fix)

Refactor `fetch_jwks_cache()` in `idtoken.rs` to use `cache_operations` module functions (`get_data`, `remove_data`, `store_cache_keyed`) instead of directly using `GENERIC_CACHE_STORE`. Each `cache_operations` function acquires and releases the lock independently, making double-locking structurally impossible.

Required type implementations are already in place:
- `JwksCache: TryFrom<CacheData>` (idtoken.rs:137-143)
- `JwksCache: Into<CacheData>` via `From` (idtoken.rs:129-135)
- `TokenVerificationError: CacheErrorConversion` (idtoken.rs:98-102)

### Fix 2: Implement TTL for In-Memory Cache (defense in depth)

Add lazy expiration to `InMemoryCacheStore`:
- Store `expires_at: Option<Instant>` alongside each `CacheData` entry
- In `get()`: return `None` for expired entries (matches Redis semantics)
- In `put_with_ttl()`: set the expiration timestamp
- In `put_if_not_exists()`: treat expired entries as non-existent

This makes in-memory cache behave consistently with Redis, preventing the expired-entry code path from being reached in the first place.

## Related Files

- `oauth2_passkey/src/oauth2/main/idtoken.rs` - `fetch_jwks_cache()` with deadlock (lines 146-203)
- `oauth2_passkey/src/storage/cache_operations.rs` - Safe cache operations (`get_data`, `remove_data`, `store_cache_keyed`)
- `oauth2_passkey/src/storage/cache_store/memory.rs` - `InMemoryCacheStore` with lazy TTL expiration
- `oauth2_passkey/src/storage/cache_store/types.rs` - `CacheEntry` with `expires_at: Option<Instant>`
- `oauth2_passkey/src/storage/cache_store/memory/tests.rs` - TTL-specific unit tests
- `oauth2_passkey/src/storage/cache_store/config.rs` - `GENERIC_CACHE_STORE` global Mutex
- `oauth2_passkey/src/storage/data_store/config.rs` - SQLite pool `min_connections(1)` for in-memory DBs

## Implementation Tasks

### Fix 1: Deadlock Elimination
- [x] Refactor `fetch_jwks_cache()` to use `cache_operations` module
- [x] Remove `GENERIC_CACHE_STORE` import from `idtoken.rs`
- [x] Verify existing tests pass

### Fix 2: In-Memory TTL
- [x] Add `CacheEntry` wrapper with `expires_at: Option<Instant>` to `types.rs`
- [x] Update `InMemoryCacheStore` to use `HashMap<String, CacheEntry>`
- [x] Implement lazy expiration in `get()` (return `None` for expired)
- [x] Implement TTL in `put_with_ttl()` and `put_if_not_exists()`
- [x] Update existing tests in `memory/tests.rs`
- [x] Add 6 TTL-specific tests

### Fix 3: SQLite In-Memory Pool Stability
- [x] Set `min_connections(1)` for in-memory SQLite pools in `data_store/config.rs`

### Verification
- [x] Run `cargo test` (611 tests pass)
- [x] Run `cargo clippy --all-targets --all-features` (0 warnings)
- [x] Docker rebuild and test: login -> wait 10+ min -> login again
- [x] Verify no deadlock with in-memory cache
- [x] Verify SQLite tables persist after 10+ minutes idle

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-11: Issue identified during Docker testing

- Context: OAuth2 login popup hung during Docker container verification. Server log showed "Processing OAuth2 authorization core logic" with no follow-up. Other users were blocked from OAuth2 login entirely.
- Decision: Track as high-priority issue with two-phase approach (quick fixes + architecture improvement)
- Reason: The blocking affects all users when any single OAuth2 callback is slow, making the system unreliable under network latency conditions. Quick fixes (timeout + pre-warming) can mitigate immediately while the deeper architecture issue is addressed separately.

### 2026-02-11: Timeout value 30s -> 5s

- Context: Default `reqwest` timeout is effectively infinite; current code sets 30s which is too long for interactive login flows
- Decision: Reduce to 5s for `get_client()`
- Reason: Google APIs typically respond within 1-2s. 5s provides margin for slow networks while preventing 30s hangs. If needed, a separate client with longer timeout can be created for non-interactive operations.

### 2026-02-11: Root cause corrected - Mutex deadlock, not contention

- Context: Debug logging in Docker revealed the flow stops at "Removing expired JWKs from cache" and never proceeds to the HTTP request. Investigation of `fetch_jwks_cache()` in `idtoken.rs` showed the `if let` pattern holds a `MutexGuard` temporary while trying to re-acquire the same non-reentrant `tokio::sync::Mutex` inside the body. The 30-second timeout never fires because the code is stuck on Mutex acquisition, not an HTTP request.
- Decision: Withdraw previous proposals (timeout reduction, pre-warming, RwLock architecture). Replace with: (1) refactor `fetch_jwks_cache()` to use `cache_operations` module, (2) add TTL support to in-memory cache.
- Reason: The original analysis (Mutex contention during HTTP requests) was incorrect. The actual bug is a deadlock that occurs only when the in-memory cache returns an expired JWKS entry (after 600s TTL). Redis auto-expires entries so the deadlock path is never reached with Redis backend. The fix must address both the deadlock pattern (primary) and the missing TTL (defense in depth).

### 2026-02-11: Why in-memory cache exposes the bug but Redis does not

- Context: User pointed out the deadlock never occurred during `cargo run` development (which uses Redis). Investigation revealed `InMemoryCacheStore::put_with_ttl()` ignores the `_ttl` parameter, keeping entries forever. Redis implements TTL natively and auto-deletes expired entries.
- Decision: Add lazy TTL expiration to `InMemoryCacheStore` as a second fix (defense in depth)
- Reason: Makes in-memory and Redis backends behave consistently. Prevents the expired-entry code path from being reached regardless of the deadlock fix. Simple to implement: store `expires_at` alongside data, return `None` in `get()` for expired entries.

### 2026-02-11: SQLite in-memory database tables disappearing after idle timeout

- Context: After deploying the deadlock fix to Docker, `o2p_passkey_credentials` table disappeared after ~30 minutes of low traffic. The `shared_cache(true)` fix from commit `13b947f` was necessary but insufficient.
- Decision: Set `min_connections(1)` for in-memory SQLite pools via `SqlitePoolOptions::new().min_connections(1).connect_lazy_with(opts)`
- Reason: `SqlitePool::connect_lazy_with()` defaults to `min_connections=0`. After idle timeout (~10min) or max lifetime (~30min), all pool connections were evicted, destroying the shared in-memory database. `shared_cache(true)` only ensures connections share the same DB while alive; when all connections close, the DB is gone. Keeping at least one connection alive permanently solves this.

## Resolution

Three fixes were applied to resolve Docker container stability issues with in-memory backends:

1. **Deadlock elimination** (commit `66ab51f`): Refactored `fetch_jwks_cache()` to use `cache_operations` module functions (`get_data`, `remove_data`, `store_cache_keyed`) instead of directly locking `GENERIC_CACHE_STORE`. Each function acquires and releases the Mutex independently, making double-locking structurally impossible.

2. **In-memory cache TTL** (commit `66ab51f`): Added `CacheEntry` wrapper with `expires_at: Option<Instant>` to `InMemoryCacheStore`. `get()` returns `None` for expired entries (lazy expiration), matching Redis semantics. This prevents the expired-entry code path from being reached.

3. **SQLite pool stability** (commit `8b7839d`): Set `min_connections(1)` for in-memory SQLite pools so at least one connection is always maintained, preventing the shared in-memory database from being destroyed by idle connection eviction.

Verified in Docker: OAuth2 login works after 10+ minutes (no deadlock), SQLite tables persist beyond idle timeout.
