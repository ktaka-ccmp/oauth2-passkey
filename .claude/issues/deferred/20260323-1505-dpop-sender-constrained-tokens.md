# Issue: DPoP (Demonstration of Proof-of-Possession) Support

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260323-1505

## Created: 2026-03-23

## Closed:

## Status: deferred

## Priority: low

## Difficulty: large

## Description

Investigate and plan DPoP (Demonstration of Proof-of-Possession) support for sender-constrained access tokens, as recommended by OAuth 2.1.

### What is DPoP?

Bearer Tokens can be used by anyone who possesses them if leaked. DPoP binds tokens to a specific client by requiring a DPoP Proof JWT signed with the client's private key on every request. This prevents token theft/replay.

Reference: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#name-access-token

### Key Technical Points

**Private key storage:**
- Browser: Web Crypto API (`extractable: false`) -- key cannot be extracted from JS
- Mobile: Secure Enclave / Android Keystore
- Same design philosophy as WebAuthn

**Access token format:**
- Can be JWT or opaque string
- JWT case: embed `cnf` claim with JWK thumbprint of client public key
  - Enables resource server to verify binding without introspection

**DPoP Proof JWT contents:**
- `htu`: Request URL
- `htm`: HTTP method
- `ath`: SHA-256 hash of access token (binds proof to token)
- `iat`: Timestamp
- `jti`: Unique ID (replay prevention)

### Context in oauth2-passkey

**Current state:** Browser-based WebAuthn authentication uses cookie sessions. Cookies have implicit sender constraints (HttpOnly/SameSite/Secure), so DPoP is not needed for the current use case.

**Future need:** If mobile SDKs or cross-service API integration is added, DPoP becomes necessary to secure Bearer tokens. This aligns with the existing Bearer Token issue (`2026-01-23-01`).

### Design Considerations

1. Check whether the current Token endpoint (Authorization Code Flow) can accommodate a DPoP header without breaking changes
2. Assess impact of adding `cnf` claim to JWT Access Tokens
3. Verify the current architecture is "retrofittable" -- DPoP should be addable without structural rewrites

## Related Issues

- `2026-01-23-01` Bearer Token Authentication Support (deferred) -- DPoP builds on top of Bearer token support
- `20260226-2022` OAuth2 Token Storage (deferred) -- token format decisions affect DPoP `cnf` claim design

## Approach

Deferred until Bearer Token support (`2026-01-23-01`) is revisited. DPoP is a layer on top of Bearer tokens, so Bearer support is a prerequisite.

When implementation begins:

1. **Phase 1: DPoP Proof validation** -- Parse and validate DPoP Proof JWT on Token endpoint
2. **Phase 2: Token binding** -- Add `cnf` claim to issued JWT access tokens
3. **Phase 3: Resource server verification** -- Verify DPoP Proof on protected endpoints
4. **Phase 4: Nonce support** -- Server-provided nonce for enhanced replay protection

## Related Files

- `oauth2_passkey/src/session/config.rs` -- SessionAuthMode enum (Bearer support)
- `oauth2_passkey/src/session/main/session.rs` -- Session/token creation
- `oauth2_passkey/src/coordination/oauth2.rs` -- OAuth2 flow coordination

## Implementation Tasks

- [ ] Review Bearer Token issue (`2026-01-23-01`) design decisions
- [ ] Assess current Token endpoint extensibility for DPoP header
- [ ] Design `cnf` claim integration for JWT Access Tokens
- [ ] Implement DPoP Proof JWT parsing and validation
- [ ] Implement token-to-proof binding (`ath` claim verification)
- [ ] Add resource server DPoP verification middleware
- [ ] Add server nonce support (optional, enhanced replay protection)
- [ ] Update documentation

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-23: Issue created from DPoP research notes

- Context: User investigated DPoP as part of OAuth 2.1 compliance planning. Current cookie-based sessions have implicit sender constraints, but future Bearer token use cases (mobile, API) will need DPoP.
- Decision: Create as deferred issue. DPoP depends on Bearer Token support which is itself deferred.
- Reason: No immediate need (cookies are sufficient for browser use case). Capturing technical research now so it is available when Bearer token work begins.

## Resolution