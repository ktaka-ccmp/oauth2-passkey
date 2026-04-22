# Issue: Remove `OAUTH2_GOOGLE_USER` Dead Code and `oauth2_account_from_userinfo`

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1521

## Created: 2026-04-20-15-21

## Closed: 2026-04-22

## Status: completed

## Priority: low

## Difficulty: small

## Description

`coordination/oauth2.rs` contains a `match` on a hardcoded `static` constant
that makes two of its three arms unreachable, and a companion function
(`oauth2_account_from_userinfo`) that is never called. This is leftover
scaffolding from when userinfo-vs-idinfo was configurable and should be
removed.

### Current state (`coordination/oauth2.rs:260-267`)

```rust
// Convert IdInfo or UserInfo to OAuth2Account using the active provider name
static OAUTH2_GOOGLE_USER: &str = "idinfo";

let oauth2_account = match OAUTH2_GOOGLE_USER {
    "idinfo" => oauth2_account_from_idinfo(&idinfo, provider_name)?,
    "userinfo" => oauth2_account_from_userinfo(&userinfo, provider_name)?,
    _ => oauth2_account_from_idinfo(&idinfo, provider_name)?, // Default case
};
```

- `OAUTH2_GOOGLE_USER` is a `static &str` hardcoded to `"idinfo"`
- Only the first arm is ever executed
- `oauth2_account_from_userinfo` has no live callers in the binary

### What stays

- `fetch_userinfo` in `oauth2/main/core.rs` stays — the returned `userinfo`
  is used for the `idinfo.sub == userinfo.sub` consistency check, which is
  a useful defense-in-depth signal
- `OidcUserInfo` struct stays for the same reason

### Independence from GitHub (non-OIDC) issue

GitHub (`20260420-1458`) would introduce a separate `OAuth2Only` flow that
does not go through this code path (no id_token at all). So removing this
dead code today does not conflict with the GitHub issue — they are on
independent paths.

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: cleanup surfaced during)
- `20260420-0552` Add Entra Provider (relationship: the OIDC type relaxation work made
  this dead code more visible)
- `20260420-1458` Add GitHub Provider (relationship: independent — non-OIDC uses a different flow)

## Approach

### Step 1: Simplify the call site

`coordination/oauth2.rs:260-267` becomes:

```rust
let oauth2_account = oauth2_account_from_idinfo(&idinfo, provider_name)?;
```

The `userinfo` returned from `get_idinfo_userinfo` is still used by the
`idinfo.sub == userinfo.sub` check inside `get_idinfo_userinfo` itself, so
the return shape of `get_idinfo_userinfo` does not need to change.

### Step 2: Remove the dead function

Delete `oauth2_account_from_userinfo` from `oauth2/types.rs`. Remove any
`pub(crate)` / `use` references.

### Step 3: Trim tests

Remove `oauth2_account_from_userinfo` tests from `oauth2/types/tests.rs`
(the fallback / error-path tests added during the Entra work that exercise
only this function).

The idinfo counterparts already have parallel tests, so coverage of the
fallback logic is preserved.

### Step 4: Verify

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test
```

Regression check: Google / Auth0 / Keycloak / Entra login still work.

## Related Files

- `oauth2_passkey/src/coordination/oauth2.rs` — remove `OAUTH2_GOOGLE_USER` + match
- `oauth2_passkey/src/oauth2/types.rs` — remove `oauth2_account_from_userinfo`
- `oauth2_passkey/src/oauth2/types/tests.rs` — remove related tests
- (no changes) `oauth2_passkey/src/oauth2/main/core.rs` — `get_idinfo_userinfo` keeps fetching userinfo for sub-consistency

## Implementation Tasks

- [x] Simplify the match to a single call in `coordination/oauth2.rs` (done in `db680fe`)
- [x] Delete `oauth2_account_from_userinfo` from `oauth2/types.rs` (done in `3f74d37`)
- [x] Remove the corresponding tests from `oauth2/types/tests.rs` (rewrote as merged-view tests in `3f74d37`)
- [x] Verify `cargo fmt --all` + `cargo clippy --all-targets --all-features` + `cargo test` clean
- [x] Regression: Google / Auth0 / Keycloak / Entra login still work
- [x] Commit (`db680fe` + `3f74d37`)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Keep `fetch_userinfo` and sub-consistency check

- Context: With `oauth2_account_from_userinfo` removed, one could argue that
  fetching userinfo at all is wasted work.
- Decision: Keep `fetch_userinfo` and the `idinfo.sub == userinfo.sub` check.
- Reason: The sub-consistency check is defense-in-depth — it catches id_token
  / userinfo divergence that could signal a compromised provider or a proxy
  attack. Cheap extra HTTPS call, real security value. Removing it is a
  separate decision that would require its own issue.

### 2026-04-21: Partial resolution — dead match removed, but
`oauth2_account_from_userinfo` stays alive

- Context: Zitadel E2E verification under `20260420-1511` revealed that
  some OIDC providers do not assert `email` in the id_token at all,
  only via the UserInfo endpoint. Building the account from `idinfo`
  alone fails for them.
- Decision:
  - **Done now (under `20260420-1511` PR)**: remove the
    `OAUTH2_GOOGLE_USER` constant and the dead `match` in
    `coordination/oauth2.rs`. The call site is now a single call to
    `oauth2_account_from_userinfo`.
  - **Reversed from the original plan**: do **NOT** delete
    `oauth2_account_from_userinfo` from `types.rs`. It is now the live
    path for the main OAuth2 callback.
- Follow-up: `20260421-0105` supersedes this issue for the final
  architecture — a merged `idinfo+userinfo` account builder that
  prefers userinfo and falls back to idinfo. Close this issue once
  that one lands, or mark it completed now that the dead `match` /
  `OAUTH2_GOOGLE_USER` removal is done.

## Resolution

Fully resolved across two PR #316 commits:

- **`db680fe`** (feat: add 8 generic OIDC provider slots): removed
  the `OAUTH2_GOOGLE_USER` constant and the dead three-arm `match`
  in `coordination/oauth2.rs`. The call site became a single call
  to `oauth2_account_from_userinfo` (at that point — subsequently
  replaced; see below).
- **`3f74d37`** (fix: merge idinfo+userinfo when building
  OAuth2Account — issue `20260421-0105`): deleted
  `oauth2_account_from_userinfo` entirely after the callback
  switched to the new merged builder
  `oauth2_account_from_idinfo_and_userinfo`. No remaining callers.

Surviving related code:

- `oauth2_account_from_idinfo` stays — still used by the FedCM
  callback (`coordination/oauth2.rs` post-merged-builder line ~497)
  because FedCM has no `/userinfo` endpoint to fetch from.
- `fetch_userinfo` and `OidcUserInfo` stay per the earlier decision
  log — they power the `idinfo.sub == userinfo.sub` consistency
  check in `get_idinfo_userinfo`.
