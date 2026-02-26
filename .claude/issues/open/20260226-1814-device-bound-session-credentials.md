# Issue: Device Bound Session Credentials (DBSC) Support

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-1814

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: low

## Difficulty: large

## Description

Add optional support for [Device Bound Session Credentials (DBSC)](https://w3c.github.io/webappsec-dbsc/), a W3C standard that binds session cookies to a specific device using TPM-backed cryptographic keys. When DBSC is active, stolen session cookies are useless on any device other than the one where the session was established.

### How DBSC Works

1. **Registration**: After login, server sends `Secure-Session-Registration` header instructing the browser to generate a TPM-bound key pair and POST the public key to a registration endpoint.
2. **Short-lived cookies**: The long-lived session cookie is replaced with a short-lived one (e.g., 10 minutes).
3. **Refresh**: When the short-lived cookie expires, the browser contacts a refresh endpoint, proves possession of the TPM private key via signed JWT challenge-response, and receives a new short-lived cookie.
4. **Protection**: An attacker who exfiltrates the cookie cannot refresh it without the TPM-bound private key.

### Server-Side Requirements

Three new components needed:

1. **Login response**: Add `Secure-Session-Registration` header after authentication
2. **Registration endpoint** (e.g., `POST /o2p/session/dbsc/start`): Receive browser's public key (JWT), store it, return session configuration JSON, replace long-lived cookie with short-lived one
3. **Refresh endpoint** (e.g., `POST /o2p/session/dbsc/refresh`): Challenge-response protocol -- issue challenge via `Secure-Session-Challenge` header, verify signed JWT via `Secure-Session-Response` header, issue new short-lived cookie

### Key HTTP Headers

| Header | Direction | Purpose |
|--------|-----------|---------|
| `Secure-Session-Registration` | Server -> Client | Trigger key generation; specify algorithms and registration path |
| `Sec-Secure-Session-Id` | Client -> Server | Identify the bound session during refresh |
| `Secure-Session-Challenge` | Server -> Client | Fresh challenge for client to sign |
| `Secure-Session-Response` | Client -> Server | JWT proof-of-possession signed with device-bound private key |

Supported algorithms: ES256 (ECDSA P-256), RS256 (RSA PKCS#1 v1.5).

### Standard Status (as of 2026-02)

- **W3C First Public Working Draft** (January 27, 2026), Editor's Draft updated February 17, 2026
- **Chrome**: Origin Trial completed (Chrome 135). Intent to Ship filed for Chrome 145 (desktop)
  - TPM integration is Windows-only initially; other platforms pending OS-specific key storage API integration
  - Chrome 145 ships with DBSC enabled on all desktop platforms (Windows/Mac/Linux), but only Windows devices with TPM 2.0 actually bind sessions to hardware
  - On platforms without TPM integration (Linux, macOS), DBSC silently falls back to standard session behavior -- no errors, no protection
- **Edge**: Origin Trial completed (Windows). No GA announced
- **Firefox**: No signal (concerns about complexity and privacy)
- **Safari**: No signal (concerns about backup/restore workflows)

#### Linux-Specific Notes

- Chrome 145 enables DBSC on Linux, but TPM integration is not yet implemented for Linux
- Linux machines often have TPM 2.0 hardware (especially modern laptops/servers), but Chrome does not use it yet (needs tpm2-tss or equivalent integration)
- Practical result: Linux users get no DBSC protection until Chrome adds Linux TPM support (timeline unknown)
- **Server-side development and testing is platform-independent** -- the server sees the same HTTP headers regardless of client platform. A server implemented on Linux will work correctly when accessed from Windows clients with TPM

### Limitations

- **TPM integration is Windows-only initially** -- other platforms (Linux, macOS) fall back to standard sessions
- **Chrome-only** for the foreseeable future -- no Firefox or Safari support
- Does NOT protect against malware active during session registration
- Does NOT protect against real-time request proxying through compromised device
- Falls back to standard long-lived cookies when no TPM is available
- TPM-bound keys are non-exportable: device backup/restore invalidates all DBSC sessions

### Why Consider This

- Complements existing session management by hardening cookies against exfiltration
- The refresh protocol is conceptually similar to token refresh in OAuth2
- As a library, offering optional DBSC support differentiates oauth2-passkey in the Rust ecosystem
- Chrome 145 shipping would create real-world demand

### Why Not Rush

- Chrome-only, Windows-only at launch -- limited real-world utility
- Spec is still a Working Draft, subject to change
- No other Rust web framework has DBSC support yet (no ecosystem pressure)
- Complexity cost: challenge-response refresh protocol, public key storage, dual cookie lifetime management

## Related Issues

None

## Approach

Implement as an optional feature flag (`dbsc`) that adds:

1. DBSC-aware session management in the coordination layer
2. Registration and refresh endpoints in the Axum integration
3. Public key storage (extend session cache with DBSC key association)
4. Configuration via environment variables (e.g., `O2P_DBSC_MODE=off|optional`, `O2P_DBSC_COOKIE_MAX_AGE=600`)

Wait for Chrome 145 GA and spec stabilization before implementation.

## Related Files

- `oauth2_passkey/src/session/` - Session management (core)
- `oauth2_passkey/src/coordination/` - Authentication flow coordination
- `oauth2_passkey_axum/src/session.rs` - Session handlers (Axum)
- `oauth2_passkey_axum/src/middleware.rs` - Authentication middleware

## Implementation Tasks

- [ ] Monitor Chrome 145 release and DBSC spec status
- [ ] Design public key storage schema (cache store extension)
- [ ] Implement DBSC session registration endpoint
- [ ] Implement DBSC session refresh endpoint (challenge-response)
- [ ] Add `Secure-Session-Registration` header to login responses
- [ ] Implement short-lived cookie rotation logic
- [ ] Add `dbsc` feature flag
- [ ] Add configuration env vars
- [ ] Write integration tests
- [ ] Update documentation

## Decision Log

### 2026-02-26: Initial issue creation

- Context: DBSC is reaching W3C Working Draft status and Chrome is preparing to ship
- Decision: Create tracking issue with low priority; defer implementation until spec stabilizes and browser support expands
- Reason: Chrome-only + Windows-only limits utility; spec may still change. Worth tracking but not worth implementing yet

## Resolution
