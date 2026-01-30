# Issue: Bearer Token Authentication Support

## ID: 2026-01-23-01

## Status: completed

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

**Key Decisions**:
1. Reuse existing 32-byte session token (no storage layer changes)
2. Same security strength (cryptographically secure random)
3. Complexity: Medium (6 files to modify)

**Reference Files**:
- `oauth2_passkey/src/session/main/session.rs` - Session management core
- `oauth2_passkey/src/session/config.rs` - Configuration
- `oauth2_passkey_axum/src/session.rs` - Axum AuthUser extractor
- `oauth2_passkey/src/coordination/oauth2.rs` - OAuth2 flow
- `oauth2_passkey/src/coordination/passkey.rs` - Passkey flow

## Difficulty: large

## Resolution

Implemented Bearer Token authentication support in 6 phases:

**Phase 1: SessionAuthMode enum** (`oauth2_passkey/src/session/config.rs`)
- Added `SessionAuthMode` enum with `Cookie`, `Bearer`, and `Both` variants
- Added `SESSION_AUTH_MODE` static configuration from environment variable

**Phase 2: Session ID extraction** (`oauth2_passkey/src/session/main/session.rs`)
- Added `AuthSource` enum to track cookie vs bearer authentication
- Added `SessionExtraction` struct for extraction results
- Added `get_session_id_from_bearer()` helper function
- Updated `get_session_id_from_headers()` to support mode switching
- Updated `is_authenticated()` to skip CSRF for bearer auth

**Phase 3: Session creation response** (`oauth2_passkey/src/session/main/session.rs`)
- Added `SessionCreationResponse` enum with `NoOp`, `Cookie`, and `Bearer` variants
- Updated `create_new_session_with_uid()` to return `SessionCreationResponse`

**Phase 4: Coordination layer** (`oauth2_passkey/src/coordination/`)
- Updated `oauth2.rs` to handle `SessionCreationResponse`
- Updated `passkey.rs` to handle `SessionCreationResponse`
- Functions now return `(SessionCreationResponse, String)` instead of `(HeaderMap, String)`

**Phase 5: Axum handlers** (`oauth2_passkey_axum/src/`)
- Updated `oauth2.rs` handlers to extract headers from `SessionCreationResponse`
- Updated `passkey.rs` handlers to extract headers from `SessionCreationResponse`

**Phase 6: Documentation** (`dot.env.example`)
- Added `SESSION_AUTH_MODE` configuration documentation

**CSRF Handling Summary:**
| Mode | CSRF Required | Reason |
|------|---------------|--------|
| `cookie` | Yes | Cookies auto-sent; CSRF prevents attacks |
| `bearer` | No | Token explicitly included; proves possession |
| `both` | Depends | Required for cookie, skipped for bearer |

**Backward Compatibility:**
- Default mode is `cookie` - existing apps work unchanged
- No breaking API changes
- New configuration option `SESSION_AUTH_MODE`

