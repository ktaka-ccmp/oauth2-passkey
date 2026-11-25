# Issue: Registration Checks rpIdHash, UP and UV Only for the "none" Attestation Format

## Metadata

- ID: 20261125-1002
- Created: 2026-11-25-10-02
- Closed:
- Status: open
- Priority: medium
- Difficulty: small
- Related Issues:
  - `20261124-2137` Parse Registration authData into a Typed Structure
  - `20261124-2346` is_discoverable() Uses the Backup Eligibility Flag
  - `20261125-0003` Registration Offers RS256 but Only ES256 Credential Keys Can Be Stored and Verified
  - `20261125-1003` Review the Default PASSKEY_USER_VERIFICATION=discouraged

## Problem

WebAuthn registration verification (L3 §7.1) requires, for every
attestation format, that the RP verify the rpIdHash in authData, the UP
flag (unless `mediation` is `conditional`) and, if the RP requires user
verification, the UV flag. Each format's own procedure (§8) is run in
addition to these steps. In this library the checks exist only in the
`none` verifier, so registrations with `packed`, `tpm` or `fido-u2f`
attestation skip them.

Found by an external review (Gemini via `agy`, 2026-11-25) and checked
against the code at origin/dev 13fde6c:

- `verify_attestation` dispatches on `fmt`
  (`oauth2_passkey/src/passkey/main/attestation/core.rs:12-63`).
  - `none` -> `verify_none_attestation`, which checks the rpIdHash
    against `PASSKEY_RP_ID`, UP (`0x01`), UV (`0x04`) when
    `PASSKEY_USER_VERIFICATION == "required"`, and AT (`0x40`)
    (`attestation/none.rs:18-47`).
  - `packed`, `tpm`, `fido-u2f` -> `verify_packed_attestation`,
    `verify_tpm_attestation`, `verify_u2f_attestation`. These verify
    the attestation signature and certificates. Apart from the AT flag
    (`packed.rs:219-220`, `tpm.rs:954`) they do not read the flags
    byte or compare the rpIdHash (`u2f.rs:138` copies it into the
    signed data only).
- No other registration step compares the rpIdHash or the flags:
  `validate_registration_challenge` (`register.rs:299-374`) runs
  `verify_client_data` (challenge, origin, type) and
  `extract_credential_public_key` (`register.rs:452-468`, which calls
  `verify_attestation`). The only other rpIdHash check is
  `AuthenticatorData::verify` (`types.rs:365-389`), used for
  authentication.
- The registration options request `attestation: direct` by default,
  so security keys typically return `packed` and Windows Hello `tpm`;
  these paths are used in practice.
- The structure has been like this since the attestation module was
  split by format (`d20c0c4`, 2025-04-10; `d38d4e6`, 2025-04-11).
- `20261124-2137` states "rpIdHash / UP / UV checks stay where they
  are", which assumed the checks were applied to all formats.

Impact (inference, not tested):

- Registration does not enforce UP, or UV under
  `PASSKEY_USER_VERIFICATION=required`, for these formats. A browser
  with a real authenticator already enforces UV when `required` is
  sent, so the gap matters mainly for non-browser or modified clients.
- A credential registered with a wrong rpIdHash cannot be used to sign
  in, because authentication checks the rpIdHash (`types.rs:367`).
- Registration needs a valid challenge and origin, and a client that
  controls its own authenticator can set any flags anyway. So the gap
  mainly affects policy enforcement and spec conformance; no
  cross-account impact was found.

## Timeline

## Latest Plan

1. Move the common authData checks out of `verify_none_attestation`
   into one function run for every format before dispatch (or in
   `validate_registration_challenge`): rpIdHash == SHA-256(RP ID), UP
   set (no conditional create is used: `conditional_ui.js` uses
   conditional mediation only for `get()`), UV set when required, AT
   set. Keep the format-specific checks in each verifier.
2. Consider adding the other §7.1 steps at the same place:
   BE/BS consistency (relates to `20261124-2346`) and checking the
   credential key `alg` against `pubKeyCredParams` (relates to
   `20261125-0003`).
3. Update `20261124-2137` so its plan reflects the new location of the
   checks; doing this issue first makes the typed parsing simpler.

### Files

- `oauth2_passkey/src/passkey/main/attestation/{core,none}.rs`
- `oauth2_passkey/src/passkey/main/register.rs` (if the checks are
  placed there)
- tests under `attestation/*/tests.rs` (fixtures use the RP ID
  `example.com`; check they match the test `PASSKEY_RP_ID`)

### Implementation Tasks

- [ ] Shared authData flag / rpIdHash check for all formats
- [ ] Tests: packed / tpm / fido-u2f with wrong rpIdHash, UP=0, and
      UV=0 under `required` are rejected
- [ ] Update `20261124-2137`

### Verification

- New tests fail before the change and pass after.
- `cargo test`, clippy, fmt; registration with a platform authenticator
  and a security key on the demo.

## Resolution
