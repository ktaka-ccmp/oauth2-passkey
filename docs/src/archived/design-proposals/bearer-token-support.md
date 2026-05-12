# Bearer Token Support

This document outlines the implementation plan for adding Bearer Token authentication support to the oauth2-passkey library, enabling API/mobile client authentication alongside the existing cookie-based browser authentication.

## Problem Statement

The current library exclusively uses HTTP-only secure cookies for session management. While this is appropriate for browser-based applications, it does not support:

1. **Mobile applications** that cannot use cookies
2. **REST API clients** using `Authorization: Bearer` headers
3. **Machine-to-machine** authentication scenarios
4. **Multi-client architectures** where token-based auth is preferred

## Proposed Solution

Add a configurable session authentication mode that allows operators to choose between:

- **Cookie-only** (current behavior, default)
- **Bearer Token-only** (API/mobile clients)
- **Both** (flexible hybrid mode)

### Key Design Decision: Reuse Existing Session Token

The existing session ID token will be reused as the Bearer Token. This is secure because:

- **32 bytes of cryptographic randomness** from `ring::rand::SystemRandom`
- **Base64url encoded** (~43 characters)
- **Entropy validated** to prevent degenerate cases
- **Same security strength** as industry-standard Bearer tokens

Benefits of reuse:
- No changes to storage layer
- Existing `StoredSession` structure works as-is
- Session management functions remain unchanged
- Simplified implementation with fewer moving parts

## Configuration

### Environment Variable

```bash
# Session authentication mode
# Options: cookie, bearer, both
# Default: cookie (maintains backward compatibility)
SESSION_AUTH_MODE='cookie'
```

| Mode | Description | Use Case |
|------|-------------|----------|
| `cookie` | Cookie only (current behavior) | Browser applications |
| `bearer` | Bearer Token only | API clients, mobile apps |
| `both` | Cookie or Bearer Token | Hybrid applications |

## Implementation Plan

### Phase 1: Configuration Layer

**File: `oauth2_passkey/src/session/config.rs`**

Add new configuration:

```rust,ignore
/// Session authentication mode determining how sessions are identified
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionAuthMode {
    /// Cookie-based authentication only (default, current behavior)
    #[default]
    Cookie,
    /// Bearer token authentication only
    Bearer,
    /// Accept both cookie and bearer token authentication
    Both,
}

pub static SESSION_AUTH_MODE: LazyLock<SessionAuthMode> = LazyLock::new(|| {
    match std::env::var("SESSION_AUTH_MODE")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "bearer" => SessionAuthMode::Bearer,
        "both" => SessionAuthMode::Both,
        _ => SessionAuthMode::Cookie, // Default
    }
});
```

### Phase 2: Session ID Extraction

**File: `oauth2_passkey/src/session/main/session.rs`**

Modify `get_session_id_from_headers()` to support Bearer token extraction:

```rust,ignore
pub(crate) fn get_session_id_from_headers(
    headers: &HeaderMap,
) -> Result<Option<&str>, SessionError> {
    match *SESSION_AUTH_MODE {
        SessionAuthMode::Cookie => get_session_id_from_cookie(headers),
        SessionAuthMode::Bearer => get_session_id_from_bearer(headers),
        SessionAuthMode::Both => {
            // Try Bearer first (explicit), then Cookie (implicit)
            if let Some(token) = get_session_id_from_bearer(headers)? {
                Ok(Some(token))
            } else {
                get_session_id_from_cookie(headers)
            }
        }
    }
}

fn get_session_id_from_bearer(headers: &HeaderMap) -> Result<Option<&str>, SessionError> {
    if let Some(auth_header) = headers.get(http::header::AUTHORIZATION) {
        let auth_str = auth_header.to_str().map_err(|e| {
            tracing::error!("Invalid Authorization header: {}", e);
            SessionError::HeaderError("Invalid Authorization header".to_string())
        })?;

        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            tracing::debug!("Found Bearer token in Authorization header");
            return Ok(Some(token.trim()));
        }
    }
    Ok(None)
}

// Rename existing logic to:
fn get_session_id_from_cookie(headers: &HeaderMap) -> Result<Option<&str>, SessionError> {
    // ... existing cookie extraction logic ...
}
```

### Phase 3: Session Creation Response

**File: `oauth2_passkey/src/session/main/session.rs`**

Add new function for Bearer mode responses:

```rust,ignore
/// Response type for session creation
pub enum SessionCreationResponse {
    /// Cookie-based: returns HeaderMap with Set-Cookie
    Cookie(HeaderMap),
    /// Bearer-based: returns the token directly
    Bearer(String),
}

pub(super) async fn create_new_session_with_uid(
    user_id: UserId,
) -> Result<SessionCreationResponse, SessionError> {
    // ... existing session creation logic ...

    match *SESSION_AUTH_MODE {
        SessionAuthMode::Cookie | SessionAuthMode::Both => {
            let mut headers = HeaderMap::new();
            header_set_cookie(
                &mut headers,
                SESSION_COOKIE_NAME.to_string(),
                session_id.clone(),
                expires_at,
                *SESSION_COOKIE_MAX_AGE as i64,
            )?;
            Ok(SessionCreationResponse::Cookie(headers))
        }
        SessionAuthMode::Bearer => {
            Ok(SessionCreationResponse::Bearer(session_id))
        }
    }
}
```

### Phase 4: Coordination Layer Updates

**Files:**
- `oauth2_passkey/src/coordination/oauth2.rs`
- `oauth2_passkey/src/coordination/passkey.rs`

Update authentication completion handlers to return appropriate response format:

```rust,ignore
// In OAuth2 callback handler
match session_response {
    SessionCreationResponse::Cookie(headers) => {
        // Return redirect with Set-Cookie header (current behavior)
    }
    SessionCreationResponse::Bearer(token) => {
        // Return JSON response with token
        // { "token": "...", "expires_in": 600 }
    }
}
```

### Phase 5: Axum Integration

**File: `oauth2_passkey_axum/src/session.rs`**

Update `AuthUser` extractor to support Bearer authentication:

```rust,ignore
impl<B> FromRequestParts<B> for AuthUser
where
    B: Send + Sync,
{
    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        let method = parts.method.clone();

        // Try to get session from Bearer token or Cookie based on mode
        let session_id = match get_session_from_request(parts)? {
            Some(id) => id,
            None => return Err(AuthRedirect::new(method.clone())),
        };

        // ... rest of authentication logic ...

        // CSRF handling differs by auth mode
        if is_bearer_auth {
            // Bearer token itself is proof of authentication
            // No CSRF check needed
            auth_user.csrf_via_header_verified = true;
        } else {
            // Existing CSRF validation for cookie-based auth
            // ... current CSRF logic ...
        }

        Ok(auth_user)
    }
}
```

### Phase 6: Documentation Updates

**File: `dot.env.example`**

Add configuration documentation:

```bash
######################################
### Session Authentication Mode ###
######################################

# Session authentication mode
# Options:
#   'cookie' = HTTP-only secure cookies (default, for browser applications)
#   'bearer' = Authorization: Bearer header (for API/mobile clients)
#   'both' = Accept either cookie or bearer token
# Default: 'cookie'
#SESSION_AUTH_MODE='cookie'
```

## Security Considerations

### CSRF Protection

| Mode | CSRF Required | Reason |
|------|---------------|--------|
| `cookie` | Yes | Cookies are automatically sent; CSRF prevents cross-site attacks |
| `bearer` | No | Token must be explicitly included; proves client possession |
| `both` | Depends | Required for cookie requests; skipped for bearer requests |

### Token Security

- Tokens have same entropy and security as session cookies
- HTTPS required for all modes (enforced by existing `Secure` cookie flag logic)
- Token TTL matches `SESSION_COOKIE_MAX_AGE`
- Tokens stored in same cache backend (Redis/Memory)

### Bearer Token Best Practices

When using Bearer mode, clients should:
1. Store tokens securely (secure storage on mobile, memory on web)
2. Never expose tokens in URLs or logs
3. Implement token refresh before expiration
4. Clear tokens on logout

## API Response Format

### Bearer Mode Login Response

```json
{
  "token": "base64url_encoded_session_id",
  "token_type": "Bearer",
  "expires_in": 600
}
```

### Bearer Mode Error Response

```json
{
  "error": "unauthorized",
  "error_description": "Invalid or expired token"
}
```

## Backward Compatibility

- Default mode is `cookie`, preserving current behavior
- No changes required for existing applications
- New mode opt-in via environment variable
- All existing APIs continue to work unchanged

## Files to Modify

| File | Changes | Complexity |
|------|---------|------------|
| `oauth2_passkey/src/session/config.rs` | Add `SessionAuthMode` enum and env var | Low |
| `oauth2_passkey/src/session/main/session.rs` | Extend extraction and creation functions | Medium |
| `oauth2_passkey/src/session/mod.rs` | Export new types if needed | Low |
| `oauth2_passkey/src/coordination/oauth2.rs` | Handle response format by mode | Medium |
| `oauth2_passkey/src/coordination/passkey.rs` | Handle response format by mode | Medium |
| `oauth2_passkey_axum/src/session.rs` | Extend `AuthUser` extractor | Medium |
| `dot.env.example` | Add configuration documentation | Low |

## Testing Strategy

### Unit Tests

1. **Config parsing**: Verify `SESSION_AUTH_MODE` parsing for all values
2. **Header extraction**: Test Bearer token extraction from Authorization header
3. **Mode switching**: Verify correct behavior for each mode

### Integration Tests

1. **Cookie mode**: Verify existing tests pass unchanged
2. **Bearer mode**: Test full auth flow with Bearer tokens
3. **Both mode**: Test fallback from Bearer to Cookie

### Security Tests

1. **CSRF bypass prevention**: Ensure CSRF still required for cookie mode
2. **Token validation**: Verify invalid tokens are rejected
3. **Mode isolation**: Ensure cookie-only mode rejects Bearer tokens

## Future Considerations

### Token Refresh

Future enhancement could add token refresh capability:
- `POST /o2p/token/refresh` endpoint
- Sliding window expiration
- Refresh token rotation

### Token Revocation

Future enhancement for explicit token revocation:
- `POST /o2p/token/revoke` endpoint
- Immediate session invalidation
- Revocation list for distributed deployments

### JWT Support

If stateless tokens are needed in the future:
- JWT generation with configurable claims
- JWT validation without cache lookup
- Separate `SESSION_TOKEN_TYPE` configuration

## Summary

This design adds Bearer Token support with minimal changes to the existing architecture by:

1. Reusing the proven session token format
2. Adding a simple configuration switch
3. Extending header extraction logic
4. Adjusting CSRF requirements based on auth mode
5. Maintaining full backward compatibility

The implementation is straightforward because the core session management remains unchanged - only the transport mechanism (Cookie vs Authorization header) differs.
