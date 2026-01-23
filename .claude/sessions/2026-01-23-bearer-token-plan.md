# Session Snapshot: Bearer Token Support Plan

**Date**: 2026-01-23
**Topic**: Bearer Token authentication support design proposal

## Current Task

Created a design proposal document for adding Bearer Token authentication support to the oauth2-passkey library. This enables API/mobile client authentication alongside the existing cookie-based browser authentication.

## Files Modified

1. **docs/src/archived/design-proposals/bearer-token-support.md** (NEW)
   - Complete implementation plan for Bearer Token support
   - Configuration via `SESSION_AUTH_MODE` environment variable
   - Three modes: `cookie`, `bearer`, `both`
   - Security considerations (CSRF handling per mode)
   - API response formats for Bearer mode

2. **docs/src/SUMMARY.md**
   - Added link to bearer-token-support.md in Design Proposals section

3. **ToDo.md**
   - Added "Bearer Token Support" to Medium Priority section with link to design doc

## Key Decisions

1. **Reuse existing session token** - Same 32-byte random token used for both Cookie and Bearer modes
   - Simplifies implementation significantly
   - No storage layer changes needed
   - Same security strength (cryptographically secure random)

2. **Configuration via environment variable** - `SESSION_AUTH_MODE` with three options:
   - `cookie` (default) - Current behavior, backward compatible
   - `bearer` - API/mobile clients only
   - `both` - Accept either method

3. **CSRF handling differs by mode**:
   - Cookie mode: CSRF protection required (current behavior)
   - Bearer mode: No CSRF needed (token itself is proof of possession)
   - Both mode: CSRF required only for cookie-based requests

## Next Steps

When implementing:

1. **Phase 1**: Add `SessionAuthMode` enum to `oauth2_passkey/src/session/config.rs`
2. **Phase 2**: Extend `get_session_id_from_headers()` to extract from `Authorization: Bearer` header
3. **Phase 3**: Modify session creation to return JSON response in Bearer mode
4. **Phase 4**: Update coordination layer (oauth2.rs, passkey.rs) for response format switching
5. **Phase 5**: Update Axum `AuthUser` extractor for Bearer authentication
6. **Phase 6**: Add configuration documentation to `dot.env.example`

## Context

- Current library uses HTTP-only secure cookies exclusively
- Cookie approach doesn't support mobile apps or REST API clients
- Design keeps implementation minimal by reusing existing token format
- Estimated complexity: Medium (6 files to modify, mostly extension logic)

## Reference Files

Key files to understand before implementation:
- `oauth2_passkey/src/session/main/session.rs` - Session management core
- `oauth2_passkey/src/session/config.rs` - Configuration
- `oauth2_passkey_axum/src/session.rs` - Axum AuthUser extractor
- `oauth2_passkey/src/coordination/oauth2.rs` - OAuth2 flow
- `oauth2_passkey/src/coordination/passkey.rs` - Passkey flow
