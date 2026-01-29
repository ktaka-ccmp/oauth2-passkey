# Issue: Bearer Token Authentication Support

## ID: 2026-01-23-01

## Status: open

## Priority: medium

## Description

Add Bearer Token authentication support to enable API/mobile client authentication alongside existing cookie-based browser authentication. Design proposal complete, implementation pending.

## Related Files

- `docs/src/archived/design-proposals/bearer-token-support.md` - Design document
- `oauth2_passkey/src/session/config.rs` - Add SessionAuthMode enum
- `oauth2_passkey/src/session/main/session.rs` - Extract from Authorization header
- `oauth2_passkey_axum/src/session.rs` - Update AuthUser extractor

## Notes

From session 2026-01-23:

**Configuration**: `SESSION_AUTH_MODE` environment variable
- `cookie` (default) - Current behavior
- `bearer` - API/mobile clients only
- `both` - Accept either method

**Implementation Phases**:
1. Add `SessionAuthMode` enum to config
2. Extend `get_session_id_from_headers()` for `Authorization: Bearer` header
3. Modify session creation for JSON response in Bearer mode
4. Update coordination layer for response format switching
5. Update Axum `AuthUser` extractor
6. Add configuration documentation

**CSRF Handling**:
- Cookie mode: CSRF required
- Bearer mode: No CSRF needed (token is proof of possession)
- Both mode: CSRF required only for cookie requests

## Resolution

