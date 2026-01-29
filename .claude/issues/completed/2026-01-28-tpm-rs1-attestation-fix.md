# Issue: Fix Windows Hello TPM Attestation (RS1 algorithm support)

## ID: 2026-01-28-03

## Status: completed

## Priority: high

## Description

Windows Hello TPM attestation fails because the server doesn't support COSE algorithm RS1 (`-65535`).

## Related Files

- `oauth2_passkey/src/passkey/main/attestation/utils.rs` - Fixed integer_to_i64()
- `oauth2_passkey/src/passkey/main/attestation/tpm.rs` - Added RS1 support
- `oauth2_passkey/src/passkey/main/attestation/utils/tests.rs` - Updated tests

## Notes

Root cause:
1. `integer_to_i64()` used hardcoded value comparisons, `-65535` not in list
2. `verify_tpm_attestation()` only supported `-257` (RS256) and `-7` (ES256)

Fix:
- Replace hardcoded comparisons with `i128::from(*i)` + `i64::try_from()`
- Add `-65535` (RS1) algorithm handling using `ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY`
- Extract SPKI from AIK cert via x509-parser, verify with `UnparsedPublicKey`

No new dependencies needed (ring and x509-parser already in Cargo.toml).

## Resolution

Completed 2026-01-28. Commit: 91d2fd6.
