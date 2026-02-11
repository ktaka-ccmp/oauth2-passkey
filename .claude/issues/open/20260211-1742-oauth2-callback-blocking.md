# Issue: OAuth2 Callback Blocking Under Network Latency

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

## Closed:

## Status: open

## Priority: high

## Difficulty: medium

## Description

### Observed Behavior

During Docker container testing, the OAuth2 login flow sometimes hangs:
1. User clicks "Login with Google" - popup opens
2. Google authentication completes and callback arrives at the server
3. Server logs "Processing OAuth2 authorization core logic" and then hangs (up to 30 seconds)
4. The popup does not close during this time
5. **Critical**: While one callback request is stuck, ALL other OAuth2 login attempts are also blocked - users cannot even be redirected to Google

### Root Cause Analysis

The OAuth2 callback flow (`process_oauth2_authorization` in `coordination/oauth2.rs`) calls `get_idinfo_userinfo()` which makes multiple external HTTP requests to Google APIs:

1. **Token exchange** (`exchange_code_for_token` -> POST to Google token endpoint)
2. **OIDC Discovery** (`get_discovered_endpoints` -> GET `/.well-known/openid-configuration`, cached in `OnceLock`)
3. **JWKS fetch** (`fetch_jwks_cache` -> GET JWKS URI, cached in `GENERIC_CACHE_STORE` with 600s TTL)
4. **UserInfo fetch** (`fetch_user_data_from_google` -> GET userinfo endpoint)

The global cache store is protected by a single `tokio::sync::Mutex<Box<dyn CacheStore>>` (`GENERIC_CACHE_STORE` in `storage/cache_store/config.rs`). This Mutex serializes **all** cache operations across the entire application, including:
- CSRF token storage/validation
- PKCE verifier storage/retrieval
- Nonce storage/validation
- JWKS caching
- Session management
- OAuth2 state storage

When external HTTP requests to Google are slow (network latency, Google API issues), the callback handler holds processing time for up to 30 seconds (the `reqwest` client timeout). Although the Mutex is not held continuously during HTTP requests, the high number of lock acquisitions per callback (CSRF check, PKCE retrieval, JWKS cache lookup/store, nonce validation, session creation, state cleanup) combined with slow interleaved HTTP requests creates contention that degrades the entire system.

Additionally, the HTTP client timeout of 30 seconds (`get_client()` in `utils.rs`) is excessively long for interactive login flows where users expect sub-second responses.

### Impact

- **User-facing**: Login popup appears frozen; users may close it and retry, creating more stuck requests
- **System-wide**: All cache-dependent operations are serialized, so one slow callback can cascade into delays for all authentication operations
- **Not Docker-specific**: This can happen in any deployment with network latency to Google APIs

## Related Issues

- `2026-01-30-08` Demo Site Deployment (Cloud Run) (related: discovered during Docker testing)
- `2026-02-09-02` Improve OAuth2 Popup Error Handling UX (related: popup UX during failures)

## Approach

### Phase 1: Quick Fixes (immediate)

1. **Reduce HTTP client timeout**: Change `get_client()` timeout from 30s to 5s. For OAuth2 callback flows, Google APIs should respond within 1-2 seconds under normal conditions. A 5-second timeout is generous while preventing long hangs.

2. **Pre-warm OIDC Discovery and JWKS at startup**: Fetch OIDC discovery document and JWKS during server initialization (alongside the existing AAGUID loading). This eliminates the first-request latency for these resources:
   - Populate `OIDC_DISCOVERY_CACHE` (OnceLock) at startup
   - Populate JWKS in `GENERIC_CACHE_STORE` at startup

### Phase 2: Architecture Improvement (longer-term)

3. **Replace global Mutex with RwLock or per-prefix locks**: The current `Mutex<Box<dyn CacheStore>>` serializes all operations. Options:
   - `RwLock<Box<dyn CacheStore>>` - allows concurrent reads (most cache operations are reads)
   - Per-prefix locking - separate locks for CSRF, session, JWKS, etc.
   - Lock-free in-memory store using `DashMap` or similar

4. **Background JWKS refresh**: Instead of lazy loading JWKS on each callback, refresh it periodically in the background to ensure it's always warm in cache.

## Related Files

- `oauth2_passkey/src/utils.rs` - `get_client()` with 30s timeout (line 182)
- `oauth2_passkey/src/storage/cache_store/config.rs` - `GENERIC_CACHE_STORE` global Mutex (line 14)
- `oauth2_passkey/src/coordination/oauth2.rs` - `process_oauth2_authorization()` (line 189)
- `oauth2_passkey/src/oauth2/main/core.rs` - `get_idinfo_userinfo()` (line 183)
- `oauth2_passkey/src/oauth2/main/google.rs` - `exchange_code_for_token()`, `fetch_user_data_from_google()`
- `oauth2_passkey/src/oauth2/main/idtoken.rs` - `fetch_jwks_cache()` with triple lock pattern (lines 146-203)
- `oauth2_passkey/src/oauth2/config.rs` - `get_discovered_endpoints()` with OnceLock (line 21)
- `oauth2_passkey/src/oauth2/discovery.rs` - `fetch_oidc_discovery()`

## Implementation Tasks

### Phase 1
- [ ] Reduce `get_client()` timeout from 30s to 5s
- [ ] Add OIDC Discovery pre-warm at startup
- [ ] Add JWKS pre-warm at startup
- [ ] Test with Docker container

### Phase 2
- [ ] Evaluate RwLock vs per-prefix locks vs DashMap
- [ ] Implement improved locking strategy
- [ ] Add background JWKS refresh
- [ ] Load testing under simulated latency

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

## Resolution
