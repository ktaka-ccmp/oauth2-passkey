# Issue: Parse Registration authData into a Typed Structure

## Metadata

- ID: 20261124-2137
- Created: 2026-11-24-21-37
- Closed:
- Status: open
- Priority: medium
- Difficulty: medium
- Related Issues:
  - `20261124-2138` Passkey Registration Could Overwrite Another User's Credential (completed)
  - `20261125-1002` Registration Checks rpIdHash, UP and UV Only for the "none" Attestation Format

## Problem

During registration, the attestation verifiers and `register.rs` read
the raw `authData` bytes by index (rpIdHash, flags, AAGUID,
credIdLen, credentialId, public key). There is no single place that
validates the authData structure before the verifiers run.

Based on examination of the code on 2026-11-16 (branch based on
origin/dev 650108f):

- Raw index / length references outside tests: `attestation/none.rs`
  (11), `attestation/packed.rs` (10), `attestation/tpm.rs` (8),
  `register.rs` (8), `attestation/u2f.rs` (6), `attestation/core.rs` (2).
- Some paths check the length first (packed self attestation, u2f,
  tpm, `extract_aaguid`), others do not: `verify_none_attestation`
  (`auth_data[..32]`, `[32]`, `[53]`, `[54]`) and the packed
  attestation-certificate path (`&auth_data[37..53]`).
- Call order in `validate_registration_challenge`: `verify_client_data`
  -> `extract_credential_public_key` -> `parse_attestation_object`
  (no structure check) -> `verify_attestation`.
- Result: an unauthenticated registration request with a `none`
  attestation and a 10-byte authData panics in
  `verify_none_attestation`:
  `range end index 32 out of range for slice of length 10`
  (reproduced by a unit test on 2026-11-16).
- The existing `AuthenticatorData` type (`main/types.rs`) is used
  only by the authentication path (`auth.rs`), not by registration.
- The credential ID length limit in `split_attested_credential_data`
  is `> 1024`; WebAuthn L3 §6.5.1 ("Value MUST be <= 1023") and §7.1
  step 25 ("Verify that the credentialId is <= 1023 bytes") use 1023.
- The AT flag is checked in several places
  (`none.rs`, `extract_public_key_from_auth_data`).

## Timeline

### 2026-11-16T11:39 — Initial validation fix on a separate branch

Branch `fix-auth-data-validation` (stacked on
`fix-passkey-registration-validation`), commit `6897a52`:

- Adds `validate_registration_auth_data()` in `register.rs`, called
  from `parse_attestation_object()`: length >= 37, AT flag set, and
  `split_attested_credential_data()` (header + credential ID present).
- Changes the credential ID limit to `> 1023`.
- Replaces the 8-byte dummy authData (`b"authdata"`) in
  `test_parse_attestation_object_success_none_fmt` with a structurally
  valid one.
- Adds regression tests:
  `test_parse_attestation_object_rejects_short_auth_data`,
  `test_validate_registration_challenge_rejects_short_auth_data`,
  `test_parse_credential_data_rejects_1024_byte_credential_id`.

Kept out of the 0.6.2 security patch to keep that patch limited to the
reported issue. The branch is based on the pre-rebase
`fix-passkey-registration-validation` and needs a rebase onto `dev`
(the fix was merged as #358).

## Latest Plan

Replace raw indexing with a parsed structure, without changing
verification behavior. Note: rpIdHash / UP / UV are currently checked
only for the `none` format; `20261125-1002` moves them to a check
shared by all formats and should be done first.

1. Extend `AuthenticatorData` with
   `attested_credential_data: Option<AttestedCredentialData>`
   (`aaguid`, `credential_id`, `credential_public_key`), keep
   `raw_data` for signature verification.
2. One parse function validates the structure (length, AT flag,
   credential ID length 1..=1023). `validate_registration_auth_data()`
   is folded into it.
3. `AttestationObject.auth_data` becomes the parsed `AuthenticatorData`.
4. Verifiers (`none`, `packed`, `tpm`, `u2f`), `core.rs` and
   `register.rs` read fields instead of indexing.
5. Update tests that construct `AttestationObject` directly (18 sites).

### Files

- `oauth2_passkey/src/passkey/main/types.rs`
- `oauth2_passkey/src/passkey/main/register.rs`
- `oauth2_passkey/src/passkey/main/attestation/{core,none,packed,tpm,u2f}.rs`
- corresponding `tests.rs`

### Implementation Tasks

- [x] Structure validation before attestation verification (`6897a52`)
- [ ] Extend `AuthenticatorData` with attested credential data
- [ ] Switch `AttestationObject` to the parsed type
- [ ] Migrate each verifier and `register.rs`
- [ ] Remove duplicated AT / length checks
- [ ] Decide release version (0.6.3 or 0.7.0)

### Verification

- The three regression tests above keep passing.
- `cargo test --no-fail-fast`, axum tests with `--all-features`,
  clippy, fmt.

## Resolution
