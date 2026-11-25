# Issue: Registration Offers RS256 but Only ES256 Credential Keys Can Be Stored and Verified

## Metadata

- ID: 20261125-0003
- Created: 2026-11-25-00-03
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261124-2137` Parse Registration authData into a Typed Structure

## Problem

Registration options advertise RS256, but the credential public key
handling supports only EC P-256 (ES256). An authenticator that chooses
RS256 cannot complete registration.

Based on examination of the code on 2026-11-25 (origin/dev 13fde6c):

- `start_registration` sends `pubKeyCredParams` with `alg: -7` (ES256)
  and `alg: -257` (RS256)
  (`oauth2_passkey/src/passkey/main/register.rs:207-216`).
- `extract_credential_public_key` (`register.rs:452`, `:545-560`) calls
  `extract_key_coordinates` (`register.rs:627-662`), which reads only
  COSE labels `-2` and `-3` (EC2 x and y) and stores
  `0x04 || x || y`. It does not check `kty`, `alg` or `crv`.
- An RSA COSE key uses `-1` (n) and `-2` (e) and has no `-3`, so
  `extract_key_coordinates` returns "Missing or invalid key
  coordinates" and registration fails.
- Authentication verifies only `ECDSA_P256_SHA256_ASN1`
  (`oauth2_passkey/src/passkey/main/auth.rs:321`).
- RS256 is handled only for TPM attestation statement signatures
  (`attestation/tpm.rs:126`), not for the credential key itself.

Impact: most authenticators pick ES256 because it is listed first, so
this is unlikely to be seen in practice. Authenticators that support
only RS256 (e.g. some older Windows Hello / TPM configurations) would
fail to register. Not verified with such an authenticator.

Because `kty` / `crv` are not checked, a non-P-256 EC key would also be
stored in the P-256 format and only fail at authentication; such keys
are not requested by `pubKeyCredParams`, so this is not expected to
occur.

Found on 2026-11-24 while comparing the implementation with
`webauthn-rs`.

## Timeline

## Latest Plan

Choose one:

1. Remove `-257` from `pubKeyCredParams` so the options match what is
   supported (smallest change).
2. Support RS256: store the COSE key (or key type + parameters),
   verify with `RSA_PKCS1_2048_8192_SHA256` at authentication, and
   migrate the stored key format.

In both cases, validate `kty`, `alg` and `crv` when extracting the
credential public key and reject unsupported keys with a clear error.

### Files

- `oauth2_passkey/src/passkey/main/register.rs`
- `oauth2_passkey/src/passkey/main/auth.rs`
- storage schema (option 2 only)
- corresponding `tests.rs`

### Implementation Tasks

- [ ] Decide option 1 or 2
- [ ] Validate `kty` / `alg` / `crv` at registration
- [ ] Tests: RSA COSE key, non-P-256 EC key, valid ES256 key

### Verification

- `cargo test`, clippy, fmt; axum integration tests.

## Resolution
