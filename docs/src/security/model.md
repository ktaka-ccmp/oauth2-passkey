# Security Model

## Overview

This chapter provides a comprehensive security analysis of the `oauth2-passkey` library. It defines the threat model, documents verified security claims, and explains the security architecture that protects authentication flows.

Understanding the security model is essential for properly deploying and configuring the library. While the library implements robust security measures, proper deployment configuration (HTTPS, infrastructure security) remains the responsibility of the integrator.

## Threat Model

The library is designed to defend against several categories of attacks that target web authentication systems.

### CSRF Attacks

Cross-Site Request Forgery attacks attempt to trick authenticated users into performing unintended actions. The library defends against CSRF through multiple mechanisms:

**Protection Implementation:**
- CSRF tokens generated using `ring::rand::SystemRandom` (cryptographically secure)
- Token length: 32 bytes of random data
- Constant-time comparison using `subtle::ConstantTimeEq::ct_eq()` prevents timing attacks
- Tokens validated via `X-CSRF-Token` header

**OAuth2 State Parameter:**
The OAuth2 flow uses a multi-component state parameter containing:
- CSRF ID
- Nonce ID
- PKCE ID
- Session reference (misc_id)
- Mode ID

This comprehensive state parameter ensures flow integrity and prevents cross-site request manipulation.

### Session Fixation

Session fixation attacks attempt to hijack a user's session by setting a known session ID before authentication. The library prevents this through complete session renewal.

**Protection Implementation:**
- New session ID generated after OAuth2 authentication completes
- Fresh CSRF token created with each new session
- Session creation uses `create_new_session_with_uid()`
- Old session data is not carried over

This ensures that even if an attacker knows a pre-authentication session ID, they cannot use it to access the authenticated session.

### Replay Attacks

Replay attacks attempt to reuse captured authentication data. The library implements multiple defenses:

**OAuth2 Nonce Validation:**
- Nonce generated using `gen_random_string(32)` with cryptographically secure randomness
- Stored with expiration time
- Validated against ID token claims
- Single-use: removed immediately after successful validation

**WebAuthn Challenge Handling:**
- Challenges generated with 32 bytes of cryptographically secure random data
- Stored with TTL (time-to-live)
- Validated before credential verification
- Removed after successful authentication

These single-use tokens ensure that captured authentication responses cannot be replayed.

### Credential Stuffing

While the library does not implement rate limiting directly (this should be handled at the infrastructure level), it provides security measures that complement rate limiting:

**WebAuthn/Passkey Benefits:**
- Passkeys are phishing-resistant by design
- Credentials are bound to the origin (verified during authentication)
- No passwords to stuff or guess
- Cryptographic authentication eliminates credential reuse attacks

**OAuth2 Benefits:**
- Authentication delegated to identity provider
- PKCE prevents authorization code interception
- No password handling in the application

## Security Architecture

The library implements a layered security architecture across both OAuth2 and WebAuthn authentication flows.

### Cryptographic Foundations

**Random Number Generation:**
- Uses `ring::rand::SystemRandom` for all security-critical random values
- Session IDs, CSRF tokens, challenges, and nonces all use this generator
- Standard length: 32 bytes for most tokens

**Timing Attack Resistance:**
- CSRF token comparison uses constant-time operations
- Implemented via `subtle::ConstantTimeEq::ct_eq()`

**Digital Signature Verification:**
- WebAuthn uses ECDSA P256 SHA256 ASN1 via the `ring` cryptography library
- Signatures verified against stored public keys
- Authenticator data and client data hash form the signed message

### OAuth2 Security Controls

| Security Control | Implementation | Status |
|-----------------|----------------|--------|
| PKCE | S256 with code_challenge/code_verifier | Verified |
| State Parameter | Multi-component (CSRF, nonce, PKCE, session IDs) | Verified |
| Nonce Validation | Generated, stored, validated against ID token | Verified |
| Token Exchange | Secure authorization code exchange with PKCE | Verified |

### WebAuthn Security Controls

| Security Control | Implementation | Status |
|-----------------|----------------|--------|
| Challenge Generation | 32-byte cryptographically secure random | Verified |
| Origin Validation | Client origin verified against configured ORIGIN | Verified |
| Signature Verification | ECDSA P256 SHA256 with public key cryptography | Verified |

### Session Security Controls

| Security Control | Implementation | Status |
|-----------------|----------------|--------|
| Cookie Security | Secure, HttpOnly, SameSite=Lax attributes | Verified |
| Host-locked Cookies | `__Host-SessionId` prefix by default | Verified |
| Session Invalidation | Complete removal from cache on logout | Verified |
| Session Expiration | Automatic cleanup of expired sessions | Verified |
| Session Fixation Protection | Complete session renewal after authentication | Verified |

### Out of Scope

The following security concerns are outside the library's scope and must be addressed at the deployment level:

- **Network Security**: TLS/HTTPS configuration and enforcement
- **Infrastructure Security**: Redis, database, and server hardening
- **Rate Limiting**: Must be implemented at the infrastructure or application level
- **Client-side Security**: JavaScript security and browser protections
- **Framework Vulnerabilities**: Security of the web framework (Axum, etc.)

## Known Limitations

1. **No Memory Zeroization**: Sensitive data is not explicitly cleared from memory using crates like `zeroize`. Consider this for high-security deployments.

2. **Concurrent Sessions Allowed**: Multiple sessions per user are permitted by design. No built-in session limits exist.

3. **No Rate Limiting**: The library does not implement rate limiting. This must be handled externally.

4. **HTTPS Not Enforced**: The library assumes HTTPS but does not enforce it. Deployment must configure HTTPS.

## Security Testing Recommendations

### Static Analysis
- Review all authentication flows for security gaps
- Verify constant-time operations are used appropriately
- Check for credential leakage in logs and error messages
- Validate error handling does not reveal sensitive information

### Dynamic Testing
- Timing attack testing on CSRF validation
- Session fixation testing with pre-authentication session manipulation
- CSRF protection bypass attempts
- OAuth2 flow manipulation (state tampering, callback manipulation)
- WebAuthn challenge replay testing

### Dependency Auditing
- Regular audit of cryptographic dependencies (`ring`, `subtle`)
- Check for known vulnerabilities using `cargo audit`
- Keep dependencies updated

## Summary

The `oauth2-passkey` library implements a robust security model with verified protections against common web authentication attacks. Key security features include:

- Cryptographically secure random generation for all tokens
- Constant-time comparison for CSRF tokens
- Complete session renewal preventing session fixation
- Single-use nonces and challenges preventing replay attacks
- PKCE and comprehensive state parameters for OAuth2 security
- Origin validation and signature verification for WebAuthn

Proper deployment requires attention to infrastructure security, HTTPS configuration, and rate limiting, which fall outside the library's scope.
