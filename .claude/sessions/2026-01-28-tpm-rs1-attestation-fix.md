# Fix Windows Hello TPM Attestation (RS1 algorithm support)

## Current Task

Windows Hello TPM attestation fails because the server doesn't support COSE algorithm RS1 (`-65535`).

## Root Cause

Two bugs identified:

1. **`integer_to_i64()`** in `utils.rs` uses hardcoded value comparisons. `-65535` is not in the list, so it returns `0`.
2. **`verify_tpm_attestation()`** in `tpm.rs` only supports `-257` (RS256) and `-7` (ES256) for signature verification.

## Implementation Plan

### Step 1: Fix `integer_to_i64()` in `utils.rs`
- Replace hardcoded comparisons with `i128::from(*i)` + `i64::try_from()`
- ciborium's `Integer` has `From<Integer> for i128`

### Step 2: Add RS1 support in `tpm.rs`
- Add `-65535` (RS1) algorithm handling
- webpki does NOT support SHA-1 -> use ring directly
- `ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY`
- Extract SPKI from AIK cert via x509-parser, verify with `UnparsedPublicKey`

### Step 3: Update tests
- Fix `test_integer_to_i64_fallback_case` (values should now convert correctly, not return 0)
- Add test for `-65535` conversion
- Add RS1 algorithm matching test

## Files to Change

- `oauth2_passkey/src/passkey/main/attestation/utils.rs`
- `oauth2_passkey/src/passkey/main/attestation/utils/tests.rs`
- `oauth2_passkey/src/passkey/main/attestation/tpm.rs`

## Key Decisions

- No new dependencies needed (ring and x509-parser already in Cargo.toml)
- RS1 is legacy SHA-1 but needed for Windows Hello TPM compatibility
- Use ring's `_FOR_LEGACY_USE_ONLY` API explicitly

## Next Steps

- Implement all changes
- Run `cargo fmt --all && cargo clippy --all-targets --all-features && cargo test`
- Retest with Windows Chrome + Windows Hello
