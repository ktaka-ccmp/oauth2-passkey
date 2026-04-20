# Issue: Add GitHub as OAuth2 Provider (non-OIDC)

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1458

## Created: 2026-04-20-14-58

## Closed:

## Status: open

## Priority: low

## Difficulty: large

## Description

Add GitHub as an OAuth2 provider. Unlike the currently-supported providers
(Google, Auth0, Keycloak, Entra), **GitHub does not implement OpenID Connect
for end-user login**. This requires the first architectural change since the
provider system was introduced: supporting a non-OIDC flow alongside the
existing OIDC flow.

### Why GitHub is not OIDC

- No `/.well-known/openid-configuration` discovery endpoint for user login
  - (GitHub Actions has an OIDC issuer for workflow federation, but that is
    not usable for Sign-In-with-GitHub)
- No ID token (JWT) issued
- No JWKS endpoint
- Identity info must be fetched from REST endpoints:
  - `https://api.github.com/user` — profile data
  - `https://api.github.com/user/emails` — email list (may be required if the
    primary email is private)

### Data shape mismatch with OIDC standard

| OIDC claim | GitHub equivalent |
|------------|-------------------|
| `sub: String` | `id: u64` (numeric ID) |
| `email: String` | `email` (may be null) |
| `name: String` | `name` (display name, may be null) |
| `preferred_username` | `login` (GitHub username) |
| `picture` | `avatar_url` |

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: part of, replaces Phase 2)
- `20260420-0552` Add Entra Provider (relationship: same provider-registration pattern,
  different flow path)

## Approach

### Phase A: Flow abstraction

Introduce a flow-type distinction at the `ProviderConfig` level:

```rust
pub(crate) enum ProviderFlow {
    Oidc,         // existing path: discovery + id_token + userinfo
    OAuth2Only,   // new path: no discovery, no id_token, REST userinfo
}
```

Or alternatively, promote to a trait if the paths diverge significantly:

```rust
#[async_trait]
pub(crate) trait AuthFlow {
    async fn exchange_code(&self, code: String, verifier: String) -> Result<TokenResponse, OAuth2Error>;
    async fn fetch_account(&self, tokens: &TokenResponse) -> Result<OAuth2Account, OAuth2Error>;
}
```

The enum approach is simpler if the non-OIDC path is "GitHub only" for now;
the trait approach is better if we anticipate more non-OIDC providers
(e.g. Twitter, Discord) later.

### Phase B: GitHub-specific flow

Bypass the existing OIDC machinery entirely for GitHub:

1. **Auth URL**: `https://github.com/login/oauth/authorize`
2. **Token exchange**: `POST https://github.com/login/oauth/access_token`
   - Request `Accept: application/json` to get JSON response instead of
     form-urlencoded default
3. **Profile fetch**: `GET https://api.github.com/user` with `Authorization: Bearer <token>`
4. **Email fetch** (if `email` is null in profile): `GET https://api.github.com/user/emails`
   - Find the entry with `"primary": true, "verified": true`
5. **Build `OAuth2Account`**:
   - `provider_user_id`: `format!("github_{}", user.id)`
   - `email`: from step 3 or fallback to step 4; error if none verified
   - `name`: `user.name` or `user.login` as fallback
   - `picture`: `user.avatar_url`

### Phase C: Security considerations

- **No nonce validation** — GitHub OAuth2 doesn't issue id_token
- **No at_hash verification** — same reason
- **State CSRF protection** — still required (use existing state machinery)
- **PKCE** — GitHub supports PKCE since 2022-04 (recommended)
- **Email verification** — only accept `verified: true` emails from `/user/emails`
  (a user can add an unverified email; do not use it as identity)

### Phase D: Lock-step provider edits

Standard provider registration (minus OIDC-specific env vars):

- `ProviderKind::GitHub` variant
- `optional_env_contract`:
  - Trigger: `OAUTH2_GITHUB_CLIENT_ID`
  - Deps: `OAUTH2_GITHUB_CLIENT_SECRET` only (no `_ISSUER_URL` — no discovery)
- `GITHUB_PROVIDER: LazyLock<Option<ProviderConfig>>` with `flow: ProviderFlow::OAuth2Only`

### Phase E: UI and docs

- `provider_view` arm: `display_name: "GitHub"`, `button_class: "btn-oauth2 btn-github"`
- CSS: GitHub black (`#24292e`) / white
- `docs/src/guides/github.md`:
  - OAuth App registration (github.com/settings/developers)
  - `user:email` scope requirement
  - Private email fallback explanation
  - Comparison table "why GitHub is treated differently"

## Related Files

- `oauth2_passkey/src/oauth2/provider.rs` — add `ProviderFlow` enum + GitHub variant
- `oauth2_passkey/src/oauth2/main/mod.rs` — dispatch to OIDC or GitHub flow
- `oauth2_passkey/src/oauth2/main/github.rs` — new module (auth URL, token exchange, user fetch)
- `oauth2_passkey/src/oauth2/types.rs` — `GitHubUser` struct + conversion to `OAuth2Account`
- `oauth2_passkey/src/coordination/oauth2.rs` — dispatch based on `ProviderFlow`
- `oauth2_passkey_axum/src/oauth2.rs` — provider_view arm
- `oauth2_passkey_axum/static/o2p-base.css` — GitHub button styles
- `docs/src/guides/github.md` — new setup guide

## Implementation Tasks

### Phase A: Flow abstraction
- [ ] Decide: enum `ProviderFlow` vs trait `AuthFlow` (revisit after prototype)
- [ ] Add `ProviderFlow` enum (or trait) to `provider.rs`
- [ ] Update `ProviderConfig` to carry the flow type
- [ ] Update coordination dispatch to branch on flow type
- [ ] Update existing providers to use `ProviderFlow::Oidc` (no behavior change)
- [ ] Verify existing tests still pass

### Phase B: GitHub flow implementation
- [ ] Create `oauth2/main/github.rs` module
- [ ] Implement GitHub auth URL builder
- [ ] Implement token exchange with `Accept: application/json`
- [ ] Implement `/user` fetch + `GitHubUser` struct
- [ ] Implement `/user/emails` fallback for private emails
- [ ] Implement `GitHubUser -> OAuth2Account` conversion
- [ ] Unit tests with mocked HTTP responses

### Phase C: Security
- [ ] Verify state CSRF protection works for GitHub flow
- [ ] Implement PKCE for GitHub (S256)
- [ ] Reject unverified emails from `/user/emails`
- [ ] Document absence of nonce/at_hash in security docs

### Phase D: Provider registration
- [ ] Add `GitHub` variant + lock-step edits in `provider.rs`
- [ ] Adapt `optional_env_contract` for GitHub's env-var shape (no ISSUER_URL)
- [ ] Add tests in `provider/tests.rs`

### Phase E: UI and docs
- [ ] Add `"github"` arm in `provider_view`
- [ ] Add CSS vars + `.btn-github` styles
- [ ] Write `docs/src/guides/github.md`
- [ ] Add entry to `docs/src/SUMMARY.md`

### Verification
- [ ] Verify `cargo fmt --all` + `cargo clippy --all-targets --all-features` + `cargo test` clean
- [ ] End-to-end: GitHub login (public email) succeeds, DB row has `provider = "github"`
- [ ] End-to-end: GitHub login (private email) succeeds via `/user/emails` fallback
- [ ] Regression: all OIDC providers still work
- [ ] Commit

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

## Resolution
