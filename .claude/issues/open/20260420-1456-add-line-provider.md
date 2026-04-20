# Issue: Add LINE Login as OAuth2 Provider

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1456

## Created: 2026-04-20-14-56

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

Add LINE Login v2.1 as a fifth optional OIDC provider alongside Google,
Auth0, Keycloak, and Entra. LINE is OIDC-compliant and fits the established
lock-step pattern with no architectural changes required.

### Key LINE Login characteristics

- **OIDC compliant** (v2.1 and later)
- **Discovery URL**: `https://access.line.me/.well-known/openid-configuration`
- **Issuer**: `https://access.line.me`
- **Signing algorithm**: ES256 (already supported by `convert_jwk_to_decoding_key`)
- **Scopes**: `openid`, `profile`, `email`

### Caveats

1. **`email` claim requires LINE approval**
   - LINE Developer Console → "Email address permission" application required
   - Before approval, `email` claim is not returned in tokens
   - `preferred_username` is also typically absent → current fallback returns a
     clean `OAuth2Error::Validation` at the conversion step

2. **`name` is the LINE display name** — may contain emoji or spaces

3. **`picture`** — LINE profile image URL

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: part of)
- `20260420-0552` Add Entra Provider (relationship: same lock-step pattern, completed)

## Approach

Lock-step edits following the Entra pattern exactly. No new architectural work.

### Implementation (6 lock-step edits in `provider.rs`)

1. `Line` variant in `ProviderKind`
2. Include in `ProviderKind::ALL`
3. `as_str`: `Self::Line => "line"`
4. `from_path_segment`: `"line" => Some(Self::Line)`
5. `optional_env_contract`: trigger `OAUTH2_LINE_CLIENT_ID`, deps `OAUTH2_LINE_CLIENT_SECRET` + `OAUTH2_LINE_ISSUER_URL`
6. `LINE_PROVIDER: LazyLock<Option<ProviderConfig>>` + `provider_for` arm

### Env vars

- `OAUTH2_LINE_CLIENT_ID` (trigger)
- `OAUTH2_LINE_CLIENT_SECRET`
- `OAUTH2_LINE_ISSUER_URL` = `https://access.line.me`
- `OAUTH2_LINE_RESPONSE_MODE` (optional, default `form_post`)
- `OAUTH2_LINE_SCOPE` (optional, default `openid+email+profile`)

### UI

- `provider_view` arm: `display_name: "LINE"`, `button_class: "btn-oauth2 btn-line"`
- CSS: `--o2p-line: #06C755`, `--o2p-line-hover: #05A647`

### Docs

- `docs/src/guides/line.md` following Entra structure
- Clear explanation of email approval requirement
- Link to LINE Developers Console setup steps

## Related Files

- `oauth2_passkey/src/oauth2/provider.rs` — 6 lock-step edits
- `oauth2_passkey/src/oauth2/provider/tests.rs` — 2 new tests
- `oauth2_passkey_axum/src/oauth2.rs` — provider_view arm
- `oauth2_passkey_axum/static/o2p-base.css` — CSS vars + button styles
- `docs/src/guides/line.md` — new setup guide
- `docs/src/SUMMARY.md` — add entry

## Implementation Tasks

- [ ] Add `Line` variant + 6 lock-step edits in `provider.rs`
- [ ] Add 2 tests in `provider/tests.rs` (from_path_segment + optional_env_contract)
- [ ] Add `"line"` arm in `provider_view`
- [ ] Add CSS vars + `.btn-line` styles
- [ ] Write `docs/src/guides/line.md`
- [ ] Add entry to `docs/src/SUMMARY.md`
- [ ] Verify `cargo fmt --all` + `cargo clippy --all-targets --all-features` + `cargo test` clean
- [ ] End-to-end: LINE login succeeds with approved app (email present)
- [ ] Verify behavior with unapproved app (email absent) — clean error expected
- [ ] Regression: Google / Auth0 / Keycloak / Entra login still work
- [ ] Commit

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

## Resolution
