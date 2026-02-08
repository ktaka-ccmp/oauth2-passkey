# Issue: Login History DB Spam Risk from Brute-Force Attacks

## ID: 2026-02-08-02

## Status: open

## Priority: medium

## Difficulty: medium

## Description

Now that all passkey authentication failures are consistently recorded to the login history
database (regardless of whether the user can be identified from the credential ID), there is
a risk of database spam from brute-force attacks.

An attacker could flood the system with invalid authentication attempts, each generating a
row in `o2p_login_history`. This could lead to:
- Excessive database growth
- Degraded query performance for admin audit page and user login history views
- Potential disk space exhaustion

## Mitigation Options

1. **Rate limiting at the HTTP layer** - Limit authentication attempts per IP address
   (e.g., via middleware or reverse proxy). This is the primary defense.

2. **Retention policy** - Periodically purge old login history entries beyond a configurable
   retention period (e.g., 90 days). A `LoginHistoryStore::cleanup_older_than()` function
   could be added.

3. **Aggregation** - After a threshold, aggregate repeated failures from the same IP into
   a single summary row instead of individual entries.

4. **Database-level limits** - Add a maximum row count per user or per time window, with
   oldest entries automatically removed when the limit is reached.

5. **Separate audit database** - Use a dedicated database for audit/login history to isolate
   spam risk from main application data. See implementation notes below.

## Separate Audit Database Implementation Notes

The audit store can use a separate database via `AUDIT_DATA_STORE_TYPE` / `AUDIT_DATA_STORE_URL`
environment variables (falling back to `GENERIC_*` when not set).

### Changes required

1. **`storage/data_store/types.rs`** - Change `SqliteDataStore` and `PostgresDataStore`
   visibility from `pub(super)` to `pub(crate)` so the audit module can construct them.
   Also re-export the types from `storage/mod.rs`.

2. **`audit/storage/config.rs`** - Add `AUDIT_DATA_STORE` LazyLock with env var fallback:
   `AUDIT_DATA_STORE_TYPE` -> `GENERIC_DATA_STORE_TYPE`,
   `AUDIT_DATA_STORE_URL` -> `GENERIC_DATA_STORE_URL`.

3. **`audit/storage/store_type.rs`** - Replace `GENERIC_DATA_STORE` with `AUDIT_DATA_STORE`
   (simple find-and-replace, 5 occurrences).

### Backward compatibility

When `AUDIT_DATA_STORE_*` env vars are not set, the audit store falls back to the generic
data store, preserving existing behavior with zero configuration change.

## Related Files

- `oauth2_passkey/src/coordination/login_history.rs` - `record_login_failure()` now accepts `Option<UserId>`
- `oauth2_passkey/src/coordination/passkey.rs` - `record_auth_failure()` records all failures to DB
- `oauth2_passkey/src/audit/storage/` - Login history storage layer
- `oauth2_passkey/src/storage/data_store/types.rs` - `SqliteDataStore`/`PostgresDataStore` (currently `pub(super)`)
- `oauth2_passkey/src/storage/data_store/config.rs` - `GENERIC_DATA_STORE` LazyLock (reference implementation)

## Notes

- This was identified during the refactoring to make authentication failure logging consistent
  (all failures go to DB, not just identified users)
- The decision to log all failures consistently was made to avoid confusion during incident
  response - different logging behavior depending on attack conditions makes investigation harder
- Rate limiting at the HTTP/reverse proxy layer is the recommended primary mitigation
- Separate audit DB requires touching `storage/` module (visibility change) - deferred to
  a dedicated refactoring session

## Resolution

