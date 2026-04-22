# Issue: Make `expires_in` in OidcTokenResponse optional

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260421-0045

## Created: 2026-04-21-00-45

## Closed: 2026-04-22-22-38

## Status: completed

## Priority: low

## Difficulty: trivial

## Description

`OidcTokenResponse.expires_in` is declared as `u64` (required) in
`oauth2_passkey/src/oauth2/types.rs:204`. Per RFC 6749 §5.1, `expires_in`
is RECOMMENDED, not REQUIRED — a spec-compliant token response may omit
it. If a provider does so, the current code fails token exchange with a
`missing field "expires_in"` deserialization error before the user is
ever signed in.

No caller actually reads the field today (it is deserialized and then
discarded), so the fix is a one-line type change:

```rust
expires_in: u64,          // before
expires_in: Option<u64>,  // after
```

### Motivation

Surfaced during E2E validation of issue `20260420-1511`
(Generic OIDC Provider Slots). Zitadel (v2.71.x) was found to omit the
`scope` field in token responses, which was fixed by the same change
(`scope: String -> Option<String>`) in PR associated with
`20260420-1511`. `expires_in` is in the same class of spec-optional
fields and some OIDC providers are known to omit it (older Keycloak
builds, some Ory Hydra configurations). Pre-empting the bug is cheaper
than another firefight.

`token_type` is REQUIRED by RFC 6749 §5.1 and stays `String`.

## Related Issues

- `.claude/issues/open/20260420-1511-add-generic-oidc-provider.md`
  — where `scope` was made optional
- RFC 6749 §5.1 — Successful Response
  <https://datatracker.ietf.org/doc/html/rfc6749#section-5.1>

## Approach

Single-line change:

```rust
// oauth2_passkey/src/oauth2/types.rs
pub(super) struct OidcTokenResponse {
    pub(super) access_token: String,
    token_type: String,
    expires_in: Option<u64>,      // <-- change
    refresh_token: Option<String>,
    scope: Option<String>,
    pub(super) id_token: Option<String>,
}
```

No call-site updates needed (field is currently unread).

## Related Files

- `oauth2_passkey/src/oauth2/types.rs:200-208` — struct definition
- `oauth2_passkey/src/oauth2/main/oidc/tests.rs` — existing tests
  (they all include `expires_in`; `Option<u64>` will deserialize them
  unchanged as `Some(3599)`)

## Implementation Tasks

- [x] Change type to `Option<u64>` in `types.rs`
- [x] Add a unit test: token response JSON without `expires_in`
  deserializes successfully (mirrors the existing `scope`-absent test
  pattern, if any; otherwise add a new one)
- [x] `cargo fmt --all` / `cargo clippy --all-targets --all-features` / `cargo test`

## Decision Log

- **2026-04-21**: Split out from `20260420-1511` to keep that PR
  scope-tight. `scope` was the immediate blocker (Zitadel);
  `expires_in` is preventive cleanup and can be shipped separately.

## Resolution

Landed on branch `fix/oidc-validation-hardening` (PR #317) as commit
`8863098` — `fix(oauth2): make OidcTokenResponse.expires_in optional`.
`expires_in` is now `Option<u64>`; regression test
`test_oidc_token_response_missing_expires_in` in
`oauth2_passkey/src/oauth2/main/oidc/tests.rs` deserializes a
token-response JSON lacking `expires_in` cleanly.
