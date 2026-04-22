# Issue: Merge `idinfo` and `userinfo` when building OAuth2Account

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260421-0105

## Created: 2026-04-21-01-05

## Closed: 2026-04-22

## Status: completed

## Priority: medium

## Difficulty: small

## Description

The OAuth2 callback path currently builds `OAuth2Account` from **either**
`idinfo` **or** `userinfo`, not both. As of `20260420-1511` (generic OIDC
slots) the main callback uses `oauth2_account_from_userinfo` exclusively
because `idinfo` alone is not enough for providers like Zitadel that do
not assert email in the ID token. But the inverse is also possible: some
providers (older Microsoft personal-account scenarios) omit fields from
the UserInfo endpoint that *are* present in the ID token.

A merged view — **prefer `userinfo` (canonical profile source), fall back
to `idinfo`** — removes both failure modes without adding risk, since
`get_idinfo_userinfo` already enforces `idinfo.sub == userinfo.sub`.

### Scope

Applies to the main OAuth2 callback only. The FedCM path
(`coordination/oauth2.rs:499`) stays on `oauth2_account_from_idinfo`
because FedCM does not obtain an access token and cannot call
`/userinfo`.

## Related Issues

- `20260420-1511` Add Generic OIDC Provider Slots (context for how this
  surfaced — Zitadel forced the switch from `idinfo` to `userinfo`)
- `20260420-1521` Remove `OAUTH2_GOOGLE_USER` Dead Code and
  `oauth2_account_from_userinfo` — **obsoleted by this issue**.
  `oauth2_account_from_userinfo` is now a live caller, so the "delete"
  plan is withdrawn. Leaving that issue open for the separate concern of
  removing the dead `match` arm + `OAUTH2_GOOGLE_USER` constant, which
  was already done as part of this Plan B change. See its decision log.

## Approach

Add a third free function (no new trait, no macro):

```rust
// oauth2/types.rs
pub(crate) fn oauth2_account_from_idinfo_and_userinfo(
    idinfo: &OidcIdInfo,
    userinfo: &OidcUserInfo,
    provider_name: &str,
) -> Result<OAuth2Account, OAuth2Error> {
    let email = userinfo.email.clone()
        .or_else(|| idinfo.email.clone())
        .or_else(|| userinfo.preferred_username.clone())
        .or_else(|| idinfo.preferred_username.clone())
        .ok_or_else(|| OAuth2Error::Validation(format!(
            "OIDC provider '{provider_name}' returned neither email nor \
             preferred_username in id_token or userinfo"
        )))?;
    let name = userinfo.name.clone()
        .or_else(|| idinfo.name.clone())
        .unwrap_or_else(|| email.clone());
    // picture, given_name, family_name, hd, email_verified:
    // prefer userinfo, fall back to idinfo using the same .or_else chain.
    // `sub` comes from userinfo (already verified == idinfo.sub).
    ...
}
```

Replace the call site in `coordination/oauth2.rs` (post-Plan-B) with
this new function. Existing call sites of `oauth2_account_from_idinfo`
(FedCM) and `oauth2_account_from_userinfo` (currently only the main
callback) stay — or the userinfo-only function gets inlined into the
merge function if it has no other callers by then.

### Tests

- New unit test: merge succeeds when `idinfo.email = None` but
  `userinfo.email = Some(...)` (Zitadel-style)
- New unit test: merge succeeds when `userinfo.email = None` but
  `idinfo.email = Some(...)` (inverse case)
- New unit test: both missing -> error message lists both sources
- Regression: existing `oauth2_account_from_idinfo` / `_from_userinfo`
  tests stay green

## Related Files

- `oauth2_passkey/src/oauth2/types.rs` — new merge function
- `oauth2_passkey/src/oauth2/types/tests.rs` — merge tests
- `oauth2_passkey/src/coordination/oauth2.rs` — switch main callback
  to the merge function
- (unchanged) `oauth2_passkey/src/oauth2/main/core.rs` —
  `get_idinfo_userinfo` already returns the pair

## Implementation Tasks

- [ ] Write `oauth2_account_from_idinfo_and_userinfo` in `types.rs`
- [ ] Swap the main callback site in `coordination/oauth2.rs`
- [ ] Decide whether to keep or inline `oauth2_account_from_userinfo`
      (pure cleanup decision — likely keep for symmetry)
- [ ] Add 3 unit tests above
- [ ] `cargo fmt --all` / `cargo clippy --all-targets --all-features` / `cargo test`
- [ ] Regression: Google / Auth0 / Keycloak / Entra / Zitadel login

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-21: Split from `20260420-1511`

- Context: Generic OIDC slots PR needed to unblock Zitadel E2E. Zitadel
  doesn't include `email` in the ID token, so the existing
  `oauth2_account_from_idinfo`-only call path failed with a validation
  error. Two fixes considered: (A) a merge function that prefers
  userinfo with idinfo fallback; (B) a one-line switch to
  `oauth2_account_from_userinfo`.
- Decision: Apply (B) now to unblock E2E verification, and file this
  issue for the proper (A) fix.
- Reason: (A) is the robust long-term answer, but it requires new code
  + tests and carries more review surface than the `20260420-1511` PR
  should absorb. (B) is a minimal pre-existing-dead-code swap that
  satisfies every currently tested provider (Google, Auth0, Keycloak,
  Entra, Zitadel) because their `/userinfo` all return email. Keeping
  the PR scope tight was the explicit user preference.

## Resolution

**Landed in commit `3f74d37`** (`fix(oauth2): merge idinfo+userinfo
when building OAuth2Account`) on branch
`feature/generic-oidc-provider-slots`, prompted by an external code
review flagging the userinfo-only callback as a regression for
providers that emit profile claims only in the ID token.

Implementation details:

- Added `oauth2_account_from_idinfo_and_userinfo(idinfo, userinfo,
  provider_name)` in `oauth2/types.rs`, replacing the userinfo-only
  builder.
- Removed `oauth2_account_from_userinfo` entirely (no remaining
  callers after the switch); FedCM stays on
  `oauth2_account_from_idinfo` since FedCM has no `/userinfo`.
- Switched `coordination/oauth2.rs` main callback to the merged
  builder, dropped the TODO marker.
- Replaced the 4 existing `oauth2_account_from_userinfo` tests with
  7 merged-view tests (idinfo-primary, userinfo fallback, id wins
  per-field, preferred_username fallback, email-only-in-idinfo,
  missing-everywhere error, name-falls-back-to-email).

### Deviation from the original Approach

The Approach section proposed *userinfo-first, idinfo fallback*
(Option A). Implementation used *idinfo-first, userinfo fallback*
(Option B). Reason: the ID token is cryptographically signed and its
`aud`/`iss`/`nonce` are already verified, making it the stronger
trust root for identity-critical claims; `/userinfo` is retrieved
over TLS using an access token and is not itself signed. When both
sources populate a field, the signed source should win and the
unsigned source should be used only to fill gaps. Option B also
keeps behavior closer to the pre-PR default (idinfo-only) with a
fallback added, which is the minimal change that fixes the Zitadel
case without introducing a new trust direction.

Verified green: 645 unit + 71 integration + 11 axum unit + 22 axum
integration + 24+10 doctests. Clippy clean.

### Follow-up

The merged builder currently cross-checks only `sub` (enforced
upstream by `get_idinfo_userinfo`). Silent per-field preference for
idinfo may hide legitimate IdP / operator misconfiguration. Tracked
as `20260422-1552` (detect claim mismatch between id_token and
/userinfo) — Tier 1 hardcoded strict reject on identity-critical
fields, Tier 2 env-var-controlled reject/warn on display fields.
