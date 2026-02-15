# Issue: Bearer Token Authentication Support

## Table of Contents

- [Description](#description)
- [Approach](#approach)
- [Impact on Existing Code](#impact-on-existing-code)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-23-01

## Branch: `dev-2026-01-23-01`

## Status: deferred

## Priority: medium

## Difficulty: large

## Description

Add Bearer Token authentication support to enable API/mobile client authentication
alongside existing cookie-based browser authentication. Design proposal complete,
initial implementation done, design review pending.

## Approach

### Configuration

`SESSION_AUTH_MODE` environment variable:
- `cookie` (default) - Current behavior
- `bearer` - API/mobile clients only
- `both` - Accept either method

### CSRF Handling

| Mode | CSRF Required | Reason |
|------|---------------|--------|
| `cookie` | Yes | Cookies auto-sent; CSRF prevents attacks |
| `bearer` | No | Token explicitly included; proves possession |
| `both` | Depends | Required for cookie, skipped for bearer |

### Support Status by Client Type

| Client | Auth Method | Session Maintenance | Status |
|--------|-------------|---------------------|--------|
| Browser | OAuth2/Passkey (via browser) | Cookie | Done |
| SPA (same origin) | OAuth2/Passkey (via browser) | Cookie | Done |
| SPA (cross origin) | OAuth2/Passkey (via browser) | Bearer (via BFF) | Needs review |
| Native app | Passkey (native API) | Bearer | Partial (demo-api) |
| Native app | OAuth2 (In-App Browser) | Bearer | Not supported |

### Open Design Questions

#### 1. Token Acquisition in `both` Mode

Current issue: In `both` mode, only Cookie is returned during session creation.
No way to obtain a Bearer token.

**Option A**: Return both during session creation
```
Set-Cookie: __Host-SessionId=xxx
Body: { "token": "xxx", "token_type": "Bearer", "expires_in": 600 }
```

**Option B**: Token Exchange endpoint
```
POST /o2p/api/token
Cookie: __Host-SessionId=xxx
-> { "token": "xxx", "token_type": "Bearer", "expires_in": 600 }
```

**Option C**: Return token in response header
```
Set-Cookie: __Host-SessionId=xxx
X-Bearer-Token: xxx
```

#### 2. Native App + OAuth2

OAuth2 callback is an HTTP redirect (302):

| Method | Accessible by Native App | Reason |
|--------|--------------------------|--------|
| 200 + JSON Body | No | In-App Browser cannot read response body |
| 200 + Custom Header | No | In-App Browser cannot read headers |
| 302 -> Custom URL Scheme | Yes | URL change is detectable |
| 200 + JS redirect | Yes | JS navigates to Custom URL Scheme |

Would require `NATIVE_APP_CALLBACK_SCHEME=myapp` env var.

#### 3. SPA Recommendation

| SPA Configuration | SESSION_AUTH_MODE | Reason |
|-------------------|-------------------|--------|
| Same origin | `cookie` | Simple, secure with HttpOnly, protected from XSS |
| Cross origin | `both` + BFF | BFF uses Bearer |

Storing tokens in localStorage is a security risk (XSS vulnerability).

### Next Steps

1. Determine token acquisition method for `both` mode
2. Determine if native app + OAuth2 support is needed
3. Implement features as needed
4. Rebuild demo-api after design is finalized

## Impact on Existing Code

### Initial Implementation (Completed 2026-01-30)

Implemented in 6 phases:

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

**Backward Compatibility:**
- Default mode is `cookie` - existing apps work unchanged
- No breaking API changes

## Related Files

- `docs/src/archived/design-proposals/bearer-token-support.md` - Design document
- `oauth2_passkey/src/session/config.rs` - SessionAuthMode enum
- `oauth2_passkey/src/session/main/session.rs` - Session management core
- `oauth2_passkey_axum/src/session.rs` - Axum AuthUser extractor
- `oauth2_passkey/src/coordination/oauth2.rs` - OAuth2 flow
- `oauth2_passkey/src/coordination/passkey.rs` - Passkey flow

### Reference: Current demo-api Status

`demo-api` provides API endpoints for Passkey authentication with `SESSION_AUTH_MODE=bearer`:

- `POST /api/passkey/auth/start` - Start authentication
- `POST /api/passkey/auth/finish` - Complete authentication, return Bearer token
- `GET /api/protected` - Protected resource (Bearer required)
- `GET /api/me` - User info (Bearer required)

**Constraint**: WebAuthn requires native API or browser. Complete testing with cURL/Postman is not possible.

## Implementation Tasks

- [x] Phase 1: SessionAuthMode enum
- [x] Phase 2: Bearer token extraction
- [x] Phase 3: Session creation response
- [x] Phase 4: Coordination layer update
- [x] Phase 5: Axum handler update
- [x] Phase 6: Documentation
- [ ] Design decision: Token acquisition for `both` mode
- [ ] Design decision: Native app + OAuth2 support scope
- [ ] Rebuild demo-api after design finalization

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-23: Initial design

- Context: Need API/mobile client authentication alongside browser cookies
- Decision: Add `SESSION_AUTH_MODE` env var with `cookie`/`bearer`/`both` modes,
  reuse existing 32-byte session token (no storage layer changes)
- Reason: Same security strength, minimal storage layer impact, backward compatible

### 2026-01-30: Initial implementation completed, re-opened for design review

- Context: 6-phase implementation completed, but open questions remain about
  `both` mode token acquisition and native app OAuth2 support
- Decision: Re-open for design review before finalizing
- Reason: In `both` mode, only Cookie is returned during session creation --
  no mechanism to obtain Bearer token. Native app + OAuth2 requires custom URL
  scheme support which is a significant addition

## Resolution

