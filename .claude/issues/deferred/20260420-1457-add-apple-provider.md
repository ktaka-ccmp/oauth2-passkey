# Issue: Add Sign in with Apple as OAuth2 Provider

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1457

## Created: 2026-04-20-14-57

## Closed:

## Status: deferred

## Priority: low

## Difficulty: small

## Description

Add Sign in with Apple as an optional OIDC provider. Apple is OIDC-compliant
but requires a **dynamic JWT client_secret** generated from an ECDSA private
key (P8 file), which is a significant architectural change compared to the
static-secret providers (Google, Auth0, Keycloak, Entra, LINE).

### Key Apple Sign In characteristics

- **OIDC compliant**
- **Discovery URL**: `https://appleid.apple.com/.well-known/openid-configuration`
- **Issuer**: `https://appleid.apple.com`
- **Signing algorithm**: ES256 / RS256
- **`response_mode=form_post` required**

### Blocker: Dynamic client_secret as JWT

Unlike other providers where `client_secret` is a static string, Apple
requires the client_secret to be a JWT signed with ES256 using a private
key obtained from Apple Developer:

```
JWT header: { alg: "ES256", kid: "<key-id>" }
JWT claims: {
  iss: <team-id>,
  sub: <client-id>,
  aud: "https://appleid.apple.com",
  exp: <now + N minutes (max 6 months)>,
  iat: <now>
}
```

The secret expires (max 6 months) and must be regenerated periodically.

### Other Apple-specific behaviors

1. **`name` and `email` only on first authorization**
   - Apple only returns these claims the first time a user authorizes the app
   - oauth2-passkey already persists email/name in DB on first login, so
     subsequent logins reading from DB should work — but the initial
     authorization response shape must be handled correctly
   - **Edge case: user deleted from oauth2-passkey but not revoked on Apple side.**
     Apple still considers the app authorized, so `name` is not returned on
     re-registration. `email` is available in the ID token every time (with
     `email` scope), so account creation succeeds — but `name` will be empty.
     Workaround: user revokes the app in Apple ID settings first, which resets
     the authorization. Document this limitation clearly.
   
2. **Private email relay**
   - User can choose "hide my email" → Apple returns `@privaterelay.appleid.com` proxy
   - Valid email for storage purposes; no special handling needed
   - **Sending to relay addresses** requires registering outbound email
     domains in Apple Developer Console + SPF/DKIM DNS records. However,
     oauth2-passkey is passwordless (no password reset emails), so this
     is **not needed** unless the consuming application sends emails to
     users. Document this distinction: storing the relay address as an
     identifier requires zero email infrastructure.
   
3. **HTTPS redirect required in production**
   - localhost redirect not allowed in production app configuration
   - Development setup requires workarounds

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: part of, replaces Phase 3)
- `20260420-0552` Add Entra Provider (relationship: same lock-step pattern for the
  parts that don't require the JWT secret)

## Approach

### Phase A: Client secret strategy abstraction

Extend `ProviderConfig` to support runtime-generated secrets:

```rust
pub(crate) enum ClientSecret {
    Static(String),
    AppleJwt {
        team_id: String,
        key_id: String,
        private_key_pem: String,  // P8 content
    },
}

impl ClientSecret {
    async fn resolve(&self) -> Result<String, OAuth2Error> {
        match self {
            Self::Static(s) => Ok(s.clone()),
            Self::AppleJwt { .. } => generate_and_cache_apple_jwt(self).await,
        }
    }
}
```

- Cache generated JWT for N minutes (e.g. 5 minutes) to avoid re-signing on every request
- Token exchange site calls `ctx.client_secret.resolve().await?`

### Phase B: P8 private key loading

- Env vars:
  - `OAUTH2_APPLE_CLIENT_ID` (trigger)
  - `OAUTH2_APPLE_TEAM_ID`
  - `OAUTH2_APPLE_KEY_ID`
  - `OAUTH2_APPLE_PRIVATE_KEY_PATH` or `OAUTH2_APPLE_PRIVATE_KEY_PEM` (choose one)
  - `OAUTH2_APPLE_ISSUER_URL = https://appleid.apple.com`
  - `OAUTH2_APPLE_RESPONSE_MODE` (force `form_post`)
- P8 file parse: use `jsonwebtoken` crate's `EncodingKey::from_ec_pem` (already in Cargo.toml)

### Phase C: Lock-step provider edits

Standard 6 edits in `provider.rs` (same pattern as Entra) plus:
- `optional_env_contract` needs to account for team_id/key_id/private_key deps
- `provider_for` arm wires up the `ClientSecret::AppleJwt` variant

### Phase D: UI + docs

- `provider_view` arm: `display_name: "Apple"`, `button_class: "btn-oauth2 btn-apple"`
- CSS: black background, white Apple logo (Apple's brand guidelines strict)
- `docs/src/guides/apple.md`:
  - Apple Developer Portal walk-through (App ID, Service ID, Key)
  - P8 file download + secure storage guidance
  - Private email relay explanation
  - Secret rotation reminder (6-month max)

## Related Files

- `oauth2_passkey/src/oauth2/provider.rs` — 6 lock-step edits + `ClientSecret` enum
- `oauth2_passkey/src/oauth2/provider/tests.rs` — new tests including JWT generation
- `oauth2_passkey/src/oauth2/main/oidc.rs` — token exchange site uses `ctx.client_secret.resolve()`
- `oauth2_passkey/src/oauth2/main/apple.rs` — new module for Apple JWT generation/caching
- `oauth2_passkey_axum/src/oauth2.rs` — provider_view arm
- `oauth2_passkey_axum/static/o2p-base.css` — Apple-brand-compliant button styles
- `docs/src/guides/apple.md` — new setup guide

## Implementation Tasks

### Phase A: Client secret strategy abstraction
- [ ] Introduce `ClientSecret` enum with `Static` and `AppleJwt` variants
- [ ] Add `resolve()` method with caching
- [ ] Update `exchange_code_for_token` to call `ctx.client_secret.resolve().await?`
- [ ] Update all existing providers to use `ClientSecret::Static(...)` (no behavior change)
- [ ] Add unit tests for `ClientSecret::Static::resolve()`

### Phase B: P8 private key loading + JWT generation
- [ ] Implement `generate_apple_jwt` using `jsonwebtoken::encode` with ES256
- [ ] Add JWT cache (5-minute TTL) keyed by team_id/key_id
- [ ] Error handling for P8 parse failures, missing env vars
- [ ] Unit tests with synthetic P8 keys

### Phase C: Provider lock-step edits
- [ ] Add `Apple` variant + 6 lock-step edits in `provider.rs`
- [ ] Extend `optional_env_contract` for multi-dep (team_id, key_id, private_key)
- [ ] Add 3+ tests in `provider/tests.rs`

### Phase D: UI and docs
- [ ] Add `"apple"` arm in `provider_view`
- [ ] Add CSS vars + `.btn-apple` styles (Apple brand compliance)
- [ ] Write `docs/src/guides/apple.md` (Apple Developer Portal setup)
- [ ] Add entry to `docs/src/SUMMARY.md`

### Verification
- [ ] Verify `cargo fmt --all` + `cargo clippy --all-targets --all-features` + `cargo test` clean
- [ ] End-to-end: Apple login succeeds, DB row has `provider = "apple"`
- [ ] Private relay email test: `@privaterelay.appleid.com` accepted and stored
- [ ] Regression: all other providers still work
- [ ] Commit

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-05-05: Pre-generated client_secret as simpler alternative

- Context: The `ClientSecret` enum approach (Phase A) requires async
  `resolve()` at every token exchange, affects all providers, and adds
  caching logic. However, Apple's client_secret JWT can be valid for up
  to 6 months.
- Decision: Document a simpler alternative — pre-generate the JWT
  externally and pass it as a static `CLIENT_SECRET` env var. This
  allows Apple to work as a Custom OIDC slot with zero library changes.
  The `ClientSecret` enum approach remains an option if fully automated
  rotation inside the library is desired later.
- Reason: Eliminates the largest implementation cost (flow abstraction
  + async resolve + cache). Operator regenerates the secret every
  ~6 months via a script or CI pipeline. For Cloud Run / k8s deployments,
  this can be automated at deploy time. Tradeoff: operational burden on
  the operator, but minimal and automatable.

### 2026-05-05: Defer — preset + docs only, no core code changes

- Context: Apple is OIDC-compliant, `response_mode=form_post` is already
  supported, and pre-generated client_secret eliminates the need for
  `ClientSecret` enum. The only work needed is an `APPLE_PRESET` constant,
  icon SVG, and documentation (same pattern as LINE preset). However,
  verification requires Apple Developer Program ($99/year) which is not
  currently available.
- Decision: Defer the issue. Current status: Apple should work as a
  Custom OIDC slot with a pre-generated client_secret JWT (unverified).
  If demand justifies the cost, add preset + docs + verify E2E. Fully
  automated secret rotation inside the library is a separate future
  concern, only warranted if operator burden becomes a real problem.
- Reason: No code changes needed for basic support. Verification cost
  (Apple Developer subscription) is disproportionate to current demand.
  The information is documented here for when it becomes relevant.

## Resolution
