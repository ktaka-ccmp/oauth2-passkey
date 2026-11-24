# Issue: Attestation Object Is Parsed Twice per Registration

## Metadata

- ID: 20261117-0728
- Created: 2026-11-17-07-28
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

`validate_registration_challenge` (`oauth2_passkey/src/passkey/main/register.rs`)
decodes and parses the same attestation object twice.

Based on examination of the code on 2026-11-16:

- `extract_credential_public_key(reg_data)` calls
  `parse_attestation_object()`, then `verify_attestation()` and
  `extract_public_key_from_auth_data()`.
- `validate_registration_challenge` then calls
  `parse_attestation_object()` again to get the credential ID and
  AAGUID.

Behavior is correct, but the duplication makes the flow harder to
follow: the verified object and the one used for the credential ID
are separate values.

## Timeline

## Latest Plan

Parse once in `validate_registration_challenge` and pass the parsed
`AttestationObject` to the verification and extraction steps. Consider
doing this together with other refactoring of the registration flow.

### Files

- `oauth2_passkey/src/passkey/main/register.rs`
- `oauth2_passkey/src/passkey/main/register/tests.rs`

### Implementation Tasks

- [ ] Parse once and pass the object down
- [ ] Adjust `extract_credential_public_key` tests

### Verification

- Full test suite, clippy, fmt.

## Resolution
