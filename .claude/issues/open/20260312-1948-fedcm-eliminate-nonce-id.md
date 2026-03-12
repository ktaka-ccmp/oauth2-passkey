# Issue: Eliminate nonce_id from FedCM Flow

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260312-1948

## Created: 2026-03-12-19-48

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

The FedCM flow currently uses `nonce_id` (an auto-generated cache key) to look up the stored nonce during callback validation. This is unnecessary -- the nonce value itself can be used as the cache key.

### Why nonce_id exists in OAuth2 but is unnecessary in FedCM

**OAuth2 Authorization Code Flow**: `nonce_id` is embedded in the `state` parameter, which passes through Google's redirect. The `state` is CSRF-verified, so `nonce_id` in CSRF-verified state provides a defense-in-depth binding between the authorization request and callback. This has security value.

**FedCM Flow**: There is no redirect. The nonce is fetched via same-origin `fetch()`, passed to `navigator.credentials.get()`, and `nonce_id` is held in a JS variable and sent back in the callback POST. The `nonce_id` provides no security binding -- it's just a relay through JavaScript with no CSRF-verified envelope.

### Proposed change

Use the nonce value itself as the cache key:

- **Before**: Generate nonce + auto-generated nonce_id -> store nonce under nonce_id -> JS sends nonce_id back -> server looks up by nonce_id, compares stored value with JWT nonce ("password" pattern)
- **After**: Generate nonce -> store under nonce as key -> JWT contains nonce -> server looks up by nonce, checks existence, deletes ("bearer token" pattern)

The nonce is 32 bytes (256 bits) of randomness, and the JWT is signed by Google. Existence check is sufficient; the comparison adds no security value.

## Related Issues

- `20260311-1039` FedCM Integration (parent feature)

## Approach

1. `FedCMNonceResponse`: Remove `nonce_id` field
2. `FedCMCallbackRequest`: Remove `nonce_id` field
3. `prepare_fedcm_nonce()`: Use `store_cache_keyed` with nonce as key instead of `generate_store_token`
4. `validate_fedcm_token()`: Remove `nonce_id` parameter. Extract nonce from JWT, check cache existence, delete
5. New function `verify_and_consume_fedcm_nonce(nonce)`: existence check + expiration check + delete
6. `fedcm_authorized_core()`: No longer passes `request.nonce_id`
7. `oauth2.js`: Remove `nonce_id` from callback POST body
8. `docs/src/integration/fedcm.md`: Update API Endpoints section

## Related Files

- `oauth2_passkey/src/oauth2/types.rs` - FedCMNonceResponse, FedCMCallbackRequest
- `oauth2_passkey/src/oauth2/main/fedcm.rs` - prepare_fedcm_nonce, validate_fedcm_token
- `oauth2_passkey/src/coordination/oauth2.rs` - fedcm_authorized_core
- `oauth2_passkey_axum/static/oauth2.js` - FedCM login flow
- `docs/src/integration/fedcm.md` - API documentation

## Implementation Tasks

- [ ] Remove `nonce_id` from `FedCMNonceResponse`
- [ ] Remove `nonce_id` from `FedCMCallbackRequest`
- [ ] Rewrite `prepare_fedcm_nonce()` to use `store_cache_keyed`
- [ ] Add `verify_and_consume_fedcm_nonce()` function
- [ ] Update `validate_fedcm_token()` signature (remove nonce_id param)
- [ ] Update `fedcm_authorized_core()` call site
- [ ] Update `oauth2.js` callback body
- [ ] Update FedCM docs API Endpoints section
- [ ] Run tests, clippy, fmt

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-12: Analysis of nonce_id necessity

- Context: During FedCM code review, questioned why nonce_id is needed when nonce itself could serve as the cache key
- Decision: nonce_id is unnecessary in FedCM (but valuable in OAuth2 due to CSRF-verified state binding)
- Reason: In FedCM, nonce_id is just a JS variable relay with no security envelope. The "lookup by ID + compare value" pattern adds no security over "lookup by value + existence check" when the value is 256-bit random and the JWT is Google-signed. In OAuth2, nonce_id is embedded in CSRF-verified state parameter, providing defense-in-depth.

### 2026-03-12: Deferred to issue for further consideration

- Context: After completing mode_id elimination refactoring, considered whether to immediately proceed with nonce_id elimination
- Decision: Create issue rather than implement immediately
- Reason: The change is well-analyzed but not urgent. FedCM is still experimental. Deferring allows more reflection on whether the simplification is worth the churn.

## Resolution
