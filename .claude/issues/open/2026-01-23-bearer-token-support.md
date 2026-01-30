# Issue: Bearer Token Authentication Support

## ID: 2026-01-23-01

## Branch: `dev-2026-01-23-01`

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

## Initial Implementation (Completed 2026-01-30)

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

---

## Design Review (2026-01-30)

Re-opened for design review. The initial implementation is complete but the overall design needs clarification.

### Current Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| SessionAuthMode enum | Done | `cookie`, `bearer`, `both` |
| Bearer token extraction | Done | Authorization header parsing |
| Session creation response | Done | `SessionCreationResponse` enum |
| CSRF skip for Bearer | Done | Token is proof of possession |
| demo-api | Done | But design may need revision |

### Open Questions

#### 1. Role of `SESSION_AUTH_MODE`

Current understanding:
- **Authentication**: All modes require browser/platform (OAuth2 needs redirects, Passkey needs `navigator.credentials` or native API)
- **Session maintenance**: Mode determines Cookie or Bearer or both

| Mode | Session Creation | Session Maintenance |
|------|------------------|---------------------|
| `cookie` | Set-Cookie | Cookie only |
| `bearer` | JSON body | Bearer only |
| `both` | Set-Cookie (+ JSON?) | Cookie or Bearer |

**Issue**: In `both` mode, only Cookie is returned during session creation. There's no way to obtain a Bearer token.

#### 2. Support Status by Client Type

| Client | Auth Method | Session Maintenance | Status |
|--------|-------------|---------------------|--------|
| Browser | OAuth2/Passkey (via browser) | Cookie | Done |
| SPA (same origin) | OAuth2/Passkey (via browser) | Cookie | Done |
| SPA (cross origin) | OAuth2/Passkey (via browser) | Bearer (via BFF) | Needs review |
| Native app | Passkey (native API) | Bearer | Partial (demo-api) |
| Native app | OAuth2 (In-App Browser) | Bearer | Not supported |

#### 3. Native App + OAuth2 Challenge

OAuth2 callback is an HTTP redirect (302), so:

| Method | Accessible by Native App | Reason |
|--------|--------------------------|--------|
| 200 + JSON Body | No | In-App Browser cannot read response body |
| 200 + Custom Header | No | In-App Browser cannot read headers |
| 302 -> Custom URL Scheme | Yes | URL change is detectable |
| 200 + JS redirect | Yes | JS navigates to Custom URL Scheme |

**Required additional implementation**:

```text
When SESSION_AUTH_MODE=bearer:
OAuth2 callback redirects to Custom URL Scheme
Example: myapp://callback?token=xxx&expires_in=600

New environment variable: NATIVE_APP_CALLBACK_SCHEME=myapp
```

#### 4. Token Acquisition in `both` Mode

**Option A: Return both during session creation**

```text
Set-Cookie: __Host-SessionId=xxx
Body: { "token": "xxx", "token_type": "Bearer", "expires_in": 600 }
```

**Option B: Token Exchange endpoint**

```text
POST /o2p/api/token
Cookie: __Host-SessionId=xxx
-> { "token": "xxx", "token_type": "Bearer", "expires_in": 600 }
```

**Option C: Return token in response header**

```text
Set-Cookie: __Host-SessionId=xxx
X-Bearer-Token: xxx
```

### Recommended Approach for SPA

| SPA Configuration | SESSION_AUTH_MODE | Reason |
|-------------------|-------------------|--------|
| Same origin | `cookie` | Simple, secure with HttpOnly, protected from XSS |
| Cross origin | `both` + BFF | BFF uses Bearer |

Storing tokens in localStorage is a security risk (XSS vulnerability).
For same-origin SPAs, cookie-based authentication is sufficient.

### Next Steps

1. **Design decision**: Determine token acquisition method for `both` mode
2. **Design decision**: Determine if native app + OAuth2 support is needed
3. **Implementation**: Add features as needed
4. **demo-api**: Rebuild after design is finalized

### Reference: Current demo-api Status

`demo-api` provides API endpoints for Passkey authentication with `SESSION_AUTH_MODE=bearer`:

- `POST /api/passkey/auth/start` - Start authentication
- `POST /api/passkey/auth/finish` - Complete authentication, return Bearer token
- `GET /api/protected` - Protected resource (Bearer required)
- `GET /api/me` - User info (Bearer required)

**Constraint**: WebAuthn requires native API or browser. Complete testing with cURL/Postman is not possible.
