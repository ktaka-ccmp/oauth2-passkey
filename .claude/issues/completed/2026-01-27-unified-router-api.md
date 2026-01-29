# Issue: Unified Router API Design

## ID: 2026-01-27-02

## Status: completed

## Priority: medium

## Description

Design and implement a unified router API (`oauth2_passkey_full_router()`) that:
- Nests auth endpoints under `O2P_ROUTE_PREFIX`
- Conditionally includes `/.well-known/webauthn` when `WEBAUTHN_ADDITIONAL_ORIGINS` is set

## Related Files

- `oauth2_passkey_axum/src/lib.rs` - New function
- `oauth2_passkey_axum/src/passkey.rs` - Fixed path to `/.well-known/webauthn`
- `docs/src/integration/multi-origin.md` - New documentation
- `demo-both/src/main.rs` - Updated to use new API

## Notes

Key decisions:
- Fixed `/.well-known/webauthn` path (was `/webauthn`)
- Created multi-origin documentation in Part 2: Basic Integration
- `has_additional_origins()` helper to check configuration
- Maintains backward compatibility with existing APIs

## Resolution

Completed 2026-01-27. Commit: bab689e.
