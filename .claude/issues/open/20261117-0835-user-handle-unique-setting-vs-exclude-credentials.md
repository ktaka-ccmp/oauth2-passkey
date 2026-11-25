# Issue: PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true No Longer Allows Multiple Credentials per Authenticator

## Metadata

- ID: 20261117-0835
- Created: 2026-11-17-08-35
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260226-2030` AAGUID-Based Credential Deletion Collision (completed; introduced excludeCredentials)

## Problem

The documented purpose of `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true`
is to let a user hold multiple credentials for the site in one
authenticator (password manager). Since v0.4.0 this no longer happens
when a logged-in user adds a passkey.

Based on examination of the code, docs and history on 2026-11-17:

- `start_registration()` (`oauth2_passkey/src/passkey/main/register.rs`)
  puts all of the session user's credential IDs into
  `excludeCredentials` whenever a session user exists, regardless of
  this setting. An authenticator holding one of them refuses to
  create a new credential (browser `InvalidStateError`).
- Introduced by `0edc54e` (2026-03-04, released in v0.4.0) under issue
  `20260226-2030`. That issue treats duplicate credentials on the same
  authenticator as something to prevent, and mentions this setting
  only in connection with the removed AAGUID-based deletion. The
  `true` case was not discussed.
- Behavior by version:

  | Setting | up to v0.3.x | v0.4.0 and later |
  |---------|--------------|------------------|
  | `false` | Registration proceeds; server deleted the old row with the same user_handle + user_id + AAGUID (effectively a replacement) | Blocked by excludeCredentials |
  | `true`  | Registration proceeds; new user_handle each time, nothing deleted, so multiple credentials per authenticator | Blocked by excludeCredentials |

- Docs still describe the pre-v0.4.0 effect:
  - `dot.env.example:326-328`: "When true: Generates unique
    user_handle per credential (allows each user to have multiple
    credentials per site)".
  - `register.rs` doc comment of `get_or_create_user_handle()`:
    "When true: ... allowing a user to have multiple credentials per
    site."
- Credentials on different authenticators were and are possible with
  either setting.

## Timeline

## Latest Plan

Decide the intended behavior first. Options:

1. Skip `excludeCredentials` when the setting is `true` (restores the
   documented effect; accidental duplicates on the same authenticator
   return).
2. Keep current behavior and fix the docs: `true` only makes the user
   handle differ per credential. Re-evaluate whether the setting is
   still useful.
3. Revisit the setting as part of a broader review of passkey
   configuration options.

### Files

- `oauth2_passkey/src/passkey/main/register.rs`
- `oauth2_passkey/src/passkey/config.rs`
- `dot.env.example`
- `docs/src/integration/configuration.md` (check its description)

### Implementation Tasks

- [ ] Decide option
- [ ] Implement code or doc change
- [ ] Tests for the chosen behavior (`test_start_registration_populates_exclude_credentials`)

### Verification

- Behavior with both setting values matches the docs.

## Resolution
