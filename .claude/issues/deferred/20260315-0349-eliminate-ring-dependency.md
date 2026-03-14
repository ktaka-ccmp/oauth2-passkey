# Issue: Eliminate ring Dependency for Full RustCrypto Migration

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260315-0349

## Created: 2026-03-15-03-49

## Closed:

## Status: deferred

## Priority: low

## Difficulty: large

## Description

The `ring` crate contains vendored C/assembly code from BoringSSL. While it compiles with
`cargo build` alone (no external tools needed), it is not Pure Rust. Eliminating ring
would make the cryptographic layer fully Pure Rust using the RustCrypto ecosystem.

### Current ring usage

| Usage | File | ring API |
|---|---|---|
| ECDSA P-256 signature verification | passkey/main/auth.rs | `ring::signature::ECDSA_P256_SHA256_ASN1` |
| RSA signature verification (TPM) | passkey/main/attestation/tpm.rs | `ring::signature::RSA_PKCS1_*` |
| SHA-256 hashing | passkey/main/auth.rs, attestation/*.rs | `ring::digest::SHA256` |
| CSPRNG | utils.rs | `ring::rand::SystemRandom` |
| Certificate verification | attestation/packed.rs, tpm.rs, u2f.rs | Via `webpki 0.22` (ring-dependent) |
| Test key generation | coordination/passkey/tests.rs | `ring::signature::EcdsaKeyPair` |

### RustCrypto equivalents

| ring usage | RustCrypto alternative | Maturity |
|---|---|---|
| `ring::signature::ECDSA_P256_SHA256_ASN1` | `p256::ecdsa::VerifyingKey` | Stable |
| `ring::signature::RSA_PKCS1_*` | `rsa::pkcs1v15::VerifyingKey` | Stable |
| `ring::digest::SHA256` | `sha2::Sha256` (already in use) | Stable |
| `ring::rand::SystemRandom` | `getrandom` + `rand` | Stable |
| `webpki 0.22` cert verification | Self-implemented with x509-cert + p256/rsa | Risky |

### Why deferred

1. **webpki replacement is the hardest part**: `webpki 0.22` uses ring internally for
   certificate signature verification. The newer `rustls-webpki 0.103` also depends on
   ring or aws-lc-rs. A truly ring-free certificate verification would require self-
   implementing X.509 signature verification using RustCrypto primitives -- this is
   security-critical code.

2. **TLS layer dependency**: Even if all direct ring usage is replaced, rustls itself
   requires ring or aws-lc-rs as a crypto provider. The experimental `rustls-rustcrypto`
   provider exists but is not production-ready.

3. **Low practical benefit**: ring compiles with `cargo build` alone -- no external tools
   needed. The practical benefits of `cargo build` just working are already achieved by
   aws-lc-sys removal (issue `20260315-0348`).

## Related Issues

- `20260315-0348` Eliminate aws-lc-sys Dependency (prerequisite: should be done first)

## Approach

If pursued in the future:

### Phase 1: Replace direct ring usage (medium effort)

1. Replace `ring::digest::SHA256` with `sha2::Sha256` (already used elsewhere)
2. Replace `ring::rand::SystemRandom` with `getrandom`/`rand`
3. Replace `ring::signature::ECDSA_P256*` with `p256::ecdsa`
4. Replace `ring::signature::RSA_PKCS1_*` with `rsa::pkcs1v15`

### Phase 2: Replace webpki certificate verification (high effort, high risk)

1. Replace `webpki::EndEntityCert::verify_signature()` with custom implementation
2. Use `x509-cert` for certificate parsing (or continue using `x509-parser`)
3. Implement signature verification using `p256`/`rsa` directly
4. Extensive security review required

### Phase 3: Replace rustls crypto provider (blocked)

1. Wait for `rustls-rustcrypto` to mature
2. Or accept ring as the TLS crypto provider

## Related Files

- `oauth2_passkey/src/passkey/main/auth.rs` (ECDSA verification)
- `oauth2_passkey/src/passkey/main/attestation/packed.rs` (webpki + ring)
- `oauth2_passkey/src/passkey/main/attestation/tpm.rs` (webpki + ring)
- `oauth2_passkey/src/passkey/main/attestation/u2f.rs` (webpki + ring)
- `oauth2_passkey/src/passkey/main/attestation/core.rs` (ring::digest)
- `oauth2_passkey/src/passkey/main/attestation/none.rs` (ring::digest)
- `oauth2_passkey/src/utils.rs` (ring::rand)
- `oauth2_passkey/src/coordination/passkey/tests.rs` (ring test keys)

## Implementation Tasks

- [ ] Replace ring::digest with sha2 (low effort)
- [ ] Replace ring::rand with getrandom/rand (low effort)
- [ ] Replace ring::signature ECDSA with p256::ecdsa (medium effort)
- [ ] Replace ring::signature RSA with rsa crate (medium effort)
- [ ] Replace webpki certificate verification (high effort, security-critical)
- [ ] Evaluate rustls-rustcrypto provider maturity
- [ ] Full security review of replacement code
- [ ] Performance benchmarking

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-15: Defer ring elimination

- Context: Investigated Pure Rust feasibility for the entire project. ring is used for WebAuthn signature verification and certificate validation (via webpki).
- Decision: Defer ring elimination. Prioritize aws-lc-sys removal first.
- Reason: (1) ring compiles with cargo build alone -- no external tools needed. (2) webpki replacement requires security-critical self-implementation. (3) rustls itself needs ring or aws-lc-rs -- no mature Pure Rust TLS provider exists. (4) The practical benefit of cargo-build-just-works is already achieved by aws-lc-sys removal.

## Resolution
