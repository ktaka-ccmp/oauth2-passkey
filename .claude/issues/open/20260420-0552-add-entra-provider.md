# Issue: Add Microsoft Entra ID as OAuth2 Provider

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-0552

## Created: 2026-04-20-05-52

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

Add Microsoft Entra ID (formerly Azure AD) as a fourth optional OIDC provider alongside
Google, Auth0, and Keycloak. Adding Entra surfaces a latent issue in the OIDC type
definitions that must be fixed as a prerequisite:

- `OidcUserInfo.email: String` and `OidcIdInfo.email: String` are required, but Entra does
  not always return `email` as a top-level claim
  - Personal Microsoft accounts: email only in `preferred_username`
  - Work/school accounts without email attribute: `email` claim absent
- With the current types, serde deserialization fails outright for these cases

This is a latent OIDC-compliance bug: the spec lists `email` and `name` as standard
claims, not required ones. Google / Auth0 / Keycloak all happened to return them
reliably, masking the issue.

The work therefore splits into two parts:

1. **Type relaxation (prerequisite)** — make `email` / `name` optional in `OidcIdInfo` /
   `OidcUserInfo`, add `preferred_username` as a documented fallback, and change
   `oauth2_account_from_*` to return `Result<OAuth2Account, OAuth2Error>`.
2. **Entra provider** — lock-step edits following the established Auth0/Keycloak pattern.

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: part of)
- `20260420-0307` Add Keycloak as OIDC Provider (relationship: same pattern, completed)

## Approach

### Part 1: Type relaxation (must compile/test green before Part 2)

**`oauth2_passkey/src/oauth2/types.rs`**
- `OidcUserInfo.email: String` → `Option<String>`
- `OidcUserInfo.name: String` → `Option<String>`
- Add `preferred_username: Option<String>`
- `oauth2_account_from_userinfo` returns `Result<OAuth2Account, OAuth2Error>`
  - Email fallback: `userinfo.email.or(userinfo.preferred_username)`, else `OAuth2Error::Validation`
  - Name fallback: `userinfo.name.unwrap_or(email.clone())`

**`oauth2_passkey/src/oauth2/main/idtoken.rs`**
- Same relaxation for `OidcIdInfo`
- `OidcIdInfo` is `pub`; this is a breaking API change, acceptable pre-1.0 (v0.5.1-dev)

**`oauth2_passkey/src/coordination/oauth2.rs`**
- `?` propagation at lines 264-266 and 499
- `impl From<OAuth2Error> for CoordinationError` already exists (`coordination/errors.rs:244`), so `?` works

**Tests:**
- Update existing `types/tests.rs` cases for new `Option<String>` shape + `Result` return
- Add: `test_userinfo_uses_preferred_username_when_email_absent`
- Add: `test_userinfo_missing_both_email_and_preferred_username_errors`
- Add: `test_idinfo_uses_preferred_username_when_email_absent`

### Part 2: Entra provider (lock-step edits, mirrors Keycloak)

**`oauth2_passkey/src/oauth2/provider.rs`** — all 6 edits:
1. `Entra` variant in `ProviderKind`
2. Include in `ProviderKind::ALL`
3. `as_str`: `Self::Entra => "entra"`
4. `from_path_segment`: `"entra" => Some(Self::Entra)`
5. `optional_env_contract`: trigger `OAUTH2_ENTRA_CLIENT_ID`, deps `OAUTH2_ENTRA_CLIENT_SECRET` + `OAUTH2_ENTRA_ISSUER_URL`
6. `ENTRA_PROVIDER: LazyLock<Option<ProviderConfig>>` + `provider_for` arm

Env vars:
- `OAUTH2_ENTRA_CLIENT_ID` (trigger)
- `OAUTH2_ENTRA_CLIENT_SECRET`
- `OAUTH2_ENTRA_ISSUER_URL` = `https://login.microsoftonline.com/{tenant_id}/v2.0`
- `OAUTH2_ENTRA_RESPONSE_MODE` (optional, default `form_post`)
- `OAUTH2_ENTRA_SCOPE` (optional, default `openid+email+profile`)

**`oauth2_passkey/src/oauth2/provider/tests.rs`**
- `test_provider_kind_from_path_segment_entra`
- `test_optional_env_contract_entra`

**`oauth2_passkey_axum/src/oauth2.rs`**
- New `"entra"` arm in `provider_view`: `display_name: "Microsoft"`, `button_class: "btn-oauth2 btn-entra"`

**`oauth2_passkey_axum/static/o2p-base.css`**
- CSS vars: `--o2p-entra: #0078D4` / `--o2p-entra-hover: #005A9E`
- `.btn-entra` + `.btn-entra:hover` styles

### Part 3: Docs

**`docs/entra.md`** — follow `docs/keycloak.md` / `docs/auth0.md` structure:
- Azure App Registration walk-through (tenant ID, client ID, secret)
- Redirect URI: `{ORIGIN}/oauth2/entra/authorized`
- Env var setup
- **Single-tenant only** — `common` / `organizations` issuer URLs fail discovery issuer validation
- **Email claim handling** — library falls back to `preferred_username`; work accounts should
  have email attribute set or enable `email` optional claim in app registration
- DB row assertion to confirm login

### Suggested commits

1. `refactor: make OIDC email/name optional and add preferred_username fallback`
2. `feat: add Microsoft Entra ID as OAuth2 provider`

## Related Files

- `oauth2_passkey/src/oauth2/types.rs` — OidcUserInfo + conversion functions
- `oauth2_passkey/src/oauth2/main/idtoken.rs` — OidcIdInfo
- `oauth2_passkey/src/coordination/oauth2.rs` — call sites (lines 264-266, 499)
- `oauth2_passkey/src/coordination/oauth2/tests.rs` — test call site (line 43)
- `oauth2_passkey/src/oauth2/types/tests.rs` — existing + new tests
- `oauth2_passkey/src/oauth2/provider.rs` — 6 lock-step edits
- `oauth2_passkey/src/oauth2/provider/tests.rs` — 2 new tests
- `oauth2_passkey_axum/src/oauth2.rs` — provider_view arm
- `oauth2_passkey_axum/static/o2p-base.css` — CSS vars + button styles
- `docs/entra.md` — new setup guide

## Implementation Tasks

### Part 1: Type relaxation
- [x] Relax `OidcUserInfo` (`email` / `name` → `Option<String>`, add `preferred_username`)
- [x] Relax `OidcIdInfo` (same) + add `preferred_username`
- [x] Change `oauth2_account_from_userinfo` return type + fallback logic
- [x] Change `oauth2_account_from_idinfo` return type + fallback logic
- [x] Update call sites in `coordination/oauth2.rs` (`?` propagation)
- [x] Update call site in `coordination/oauth2/tests.rs`
- [x] Update existing tests in `types/tests.rs`
- [x] Add new tests: preferred_username fallback, missing-both-errors path
- [x] Verify `cargo fmt --all` + `cargo clippy --all-targets --all-features` + `cargo test` clean
- [x] Regression: Google / Auth0 / Keycloak login still work in `demo-both`
- [ ] Commit Part 1

### Part 2: Entra provider
- [x] Add `Entra` variant + 6 lock-step edits in `provider.rs`
- [x] Add 2 tests in `provider/tests.rs`
- [x] Add `"entra"` arm in `provider_view`
- [x] Add CSS vars + `.btn-entra` styles
- [x] Write `docs/src/guides/entra.md`
- [x] Verify `cargo fmt --all` + `cargo clippy --all-targets --all-features` + `cargo test` clean
- [x] End-to-end: Entra work account login succeeds, DB row has `provider = "entra"`
- [x] End-to-end: Entra personal MS account login succeeds via `preferred_username` fallback
- [x] Regression: mis-configured Entra (trigger set, secret missing) fails at startup
- [ ] Commit Part 1 + Part 2

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Chose Option A (type relaxation) over docs-only approach

- Context: Investigation revealed that Entra does not reliably return `email` in standard
  claims. Considered three options: (A) relax types + add `preferred_username` fallback,
  (B) document strict setup requirements, (C) pick a different provider.
- Decision: Option A.
- Reason: The current struct shape is a latent OIDC spec-compliance bug regardless of
  Entra. `email`/`name` are "standard claims" in the OIDC spec, not required. Fixing this
  unblocks Entra and makes the library more correct for future providers. Docs-only
  approach (B) leaves personal MS accounts unsupported and still surfaces deserialization
  errors on misconfigured work accounts.

### 2026-04-20: Excluded multi-tenant Entra support

- Context: Entra supports `common` / `organizations` / `consumers` tenant endpoints for
  multi-tenant apps, but the discovery document returns an issuer URL containing a
  `{tenantid}` placeholder, which fails our strict issuer validation.
- Decision: Single-tenant only for this issue. Document the limitation in `docs/entra.md`.
- Reason: Multi-tenant issuer validation is non-trivial (pattern-match `{tenantid}` against
  the actual tenant ID from the id_token) and is orthogonal to the Entra-specific work.
  If demand appears, handle as a follow-up.

### 2026-04-20: Made `Jwk.alg` optional to fix Entra JWKS parsing

- Context: Entra's JWKS endpoint omits the `alg` field from key entries; the existing
  `Jwk` struct had `alg: String` (required), causing serde deserialization to fail with
  "error decoding response body" when the JWKS was fetched.
- Decision: Changed `Jwk.alg` to `Option<String>`. `convert_jwk_to_decoding_key` falls
  back to a `kty`-derived default (`RSA` → `RS256`, `EC` → `ES256`, `oct` → `HS256`).
- Reason: The fix is minimal and backward-compatible. Google and other providers that
  include `alg` continue to work unchanged; the fallback only activates when absent.

### 2026-04-20: Kept `OAuth2Account.email` / `.name` required

- Context: The fix could be propagated further by making `OAuth2Account.email` / `.name`
  also `Option<String>`.
- Decision: Keep them required. Error cleanly at the conversion step if both `email` and
  `preferred_username` are absent.
- Reason: DB schema and downstream UI code assume non-empty strings. Making the top-level
  struct nullable would be a large ripple. The fallback in the conversion function is
  sufficient for the realistic failure cases.

## Resolution
