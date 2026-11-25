# Issue: is_discoverable() Uses the Backup Eligibility Flag

## Metadata

- ID: 20261124-2346
- Created: 2026-11-24-23-46
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261124-2136` Stop Returning Credential IDs from Unauthenticated auth/start
  - `20261124-2137` Parse Registration authData into a Typed Structure

## Problem

`AuthenticatorData::is_discoverable()` returns the Backup Eligibility
(BE) flag, which says whether the credential can be backed up (synced),
not whether it is a discoverable credential. The authenticator data
flags have no "discoverable" bit.

Based on examination of the code on 2026-11-24 (origin/dev 13fde6c):

- `oauth2_passkey/src/passkey/main/types.rs:344-347`:
  `(self.flags & auth_data_flags::BE) != 0`, with the doc comment
  "Check if this is a discoverable credential (previously known as
  resident key)".
- The value decides whether a missing `userHandle` is rejected in
  `verify_user_handle` (`oauth2_passkey/src/passkey/main/auth.rs:199-238`,
  called at `:164-168`):
  - `userHandle` present: always compared with the stored handle
    (unchanged by this issue).
  - `userHandle` absent and BE set: rejected.
  - `userHandle` absent and BE not set: accepted.
- It is also used for logging (`auth.rs:153`, `types.rs:394`).

WebAuthn L3 §7.2 step 6 ties the `userHandle` requirement to how the
ceremony started, not to the flags: if the user was not identified
before the ceremony (empty `allowCredentials`), `userHandle` must be
present; if the user was identified, `userHandle`, when present, must
match.

Practical impact is limited (the signature is verified and a present
`userHandle` is always checked), but the rule is based on the wrong
signal: a non-syncable discoverable credential (e.g. a hardware
security key) that omitted `userHandle` in a usernameless login would
be accepted, and a syncable credential would be rejected in the
identified-user case if `userHandle` were omitted.

Found during the 2026-11-24 investigation of adopting `webauthn-rs`.

## Timeline

## Latest Plan

1. Decide the requirement from the ceremony: record in the
   authentication challenge state whether `allowCredentials` was empty,
   and require `userHandle` in that case.
2. Rename or remove `is_discoverable()`; keep `is_backup_eligible()` /
   `is_backed_up()` for logging.
3. If `20261124-2136` lands first (auth/start always returns empty
   `allowCredentials`), `userHandle` can simply always be required.

### Files

- `oauth2_passkey/src/passkey/main/types.rs`
- `oauth2_passkey/src/passkey/main/auth.rs`
- corresponding `tests.rs`

### Implementation Tasks

- [ ] Store whether the ceremony was usernameless in the challenge state
- [ ] Base the `userHandle` requirement on it
- [ ] Fix naming and doc comment of the flag helpers
- [ ] Tests for both cases with BE set and not set

### Verification

- Unit tests cover: usernameless + missing `userHandle` -> rejected
  regardless of BE; identified user + missing `userHandle` -> accepted
  regardless of BE.
- `cargo test`, clippy, fmt.

## Resolution
