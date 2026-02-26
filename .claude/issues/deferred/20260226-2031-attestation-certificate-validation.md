# Issue: Attestation Certificate Chain Validation

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2031

## Created: 2026-02-26

## Closed:

## Status: deferred

## Priority: low

## Difficulty: large

## Description

The attestation verification for all formats (fido-u2f, packed, tpm) performs basic signature validation but lacks comprehensive certificate chain verification. This affects the trustworthiness of attestation statements but does not impact authentication security.

### Current State

| Verification | fido-u2f | packed | tpm |
|-------------|----------|--------|-----|
| Signature verification | Done | Done | Done |
| Certificate parsing | Done | Done | Done |
| CA flag check | Done | Done | Done |
| Certificate chain validation | Missing | Missing | Missing |
| Certificate expiration check | Missing | Missing | Missing |
| CRL/OCSP revocation check | Missing | Missing | Missing |
| Key Usage / EKU validation | Partial | Partial | Partial |
| FIDO MDS trust anchor verification | Missing | Missing | Missing |

### Impact

- **Authentication security is NOT affected**: Attestation verifies the authenticator's identity, not the user's. A user can still securely authenticate even without full attestation validation.
- **Affected use case**: Enterprises that require attestation to enforce authenticator policies (e.g., "only allow YubiKey 5 series") cannot fully trust the attestation without chain validation.
- **FIDO U2F specifically**: Legacy security keys use this format. Basic signature verification works, so U2F keys are functional for authentication.

### Background

The FIDO U2F attestation format was originally noted in ToDo.md as "experimentally implemented." Investigation confirmed that the implementation is functional for basic use but shares the same certificate validation gaps as the other attestation formats. This is not a U2F-specific issue but an attestation-wide concern.

## Related Issues

None

## Approach

1. Implement certificate chain validation using existing `webpki` dependency
2. Add FIDO Metadata Service (MDS) integration for trust anchor verification
3. Add certificate expiration and revocation checking
4. Apply consistently across all attestation formats

Deferred because:
- Basic authentication works without full attestation validation
- Enterprise attestation enforcement is a niche use case
- FIDO MDS integration adds significant complexity

## Related Files

- `oauth2_passkey/src/passkey/main/attestation/u2f.rs`
- `oauth2_passkey/src/passkey/main/attestation/packed.rs`
- `oauth2_passkey/src/passkey/main/attestation/tpm.rs`
- `oauth2_passkey/src/passkey/main/attestation/core.rs`

## Implementation Tasks

- [ ] Implement certificate chain validation (shared logic for all formats)
- [ ] Add certificate expiration checking
- [ ] Add CRL/OCSP revocation support
- [ ] Validate Key Usage and Extended Key Usage
- [ ] Integrate FIDO Metadata Service for trust anchors
- [ ] Add comprehensive test suite with valid certificate chains
- [ ] Update documentation

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md; originally tracked as "FIDO U2F attestation (experimental)"
- Decision: Reframed as attestation-wide certificate validation issue and deferred
- Reason: All attestation formats share the same gaps. Basic auth works without it. Enterprise attestation enforcement is niche

## Resolution

