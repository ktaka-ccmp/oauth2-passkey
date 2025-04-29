# Session Boundary Solutions

## Problem Statement

The authentication system had session boundary problems:

1. When a user intends to add a new passkey credential or link a new OAuth2 account to an existing user account, the system may incorrectly create a new user if there is no valid session.

2. A specific edge case exists where a user might have multiple accounts and accidentally add credentials to the wrong account due to session desynchronization:
   - User views account #1's page with "add credential" button
   - User gets distracted, logs in as account #2 in another tab
   - User returns to account #1's page, but now has a session for account #2
   - User clicks "add credential" button, believing it will add to account #1, but it actually adds to account #2

## Implemented Solution

We implemented a dual approach to solve these session boundary issues:

### 1. Explicit Registration Modes

We created a clear separation of intent through explicit registration modes:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// Adding a passkey to an existing user (requires authentication)
    AddToUser,
    /// Creating a new user with a passkey (no authentication required)
    CreateUser,
}
```

These modes are used in the client JavaScript and server-side handlers to explicitly indicate the user's intent:

```javascript
// Client-side: Explicit mode when showing registration modal
function showRegistrationModal(mode) { // 'create_user' or 'add_to_user'
    const modal = createRegistrationModal();
    modal.style.display = 'block';
    modal.dataset.mode = mode;
    // ...
}
```

```rust
// Server-side: Mode-specific handling
match body.mode {
    RegistrationMode::AddToUser => {
        // Verify user is authenticated
        // Verify CSRF token matches session
        // Add passkey to existing user
    },
    RegistrationMode::CreateUser => {
        // Create new user with passkey
    },
}
```

### 2. Session/Page Synchronization with Page Context Tokens

We leverage obfuscated CSRF tokens as page context tokens for both CSRF protection and session boundary verification:

#### CSRF Token Implementation

The CSRF token mechanism is integrated with the session management system:

```rust
// When creating a new session, a CSRF token is generated and stored
pub(super) async fn create_new_session_with_uid(user_id: &str) -> Result<HeaderMap, SessionError> {
    let session_id = gen_random_string(32)?;
    let expires_at = Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64);

    let csrf_token = gen_random_string(32)?;

    let stored_session = StoredSession {
        user_id: user_id.to_string(),
        csrf_token: csrf_token.to_string(),
        expires_at,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    // Store the session with the CSRF token
    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(
            "session",
            &session_id,
            stored_session.into(),
            *SESSION_COOKIE_MAX_AGE as usize,
        )
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    // Set the session cookie
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        session_id.clone(),
        expires_at,
        *SESSION_COOKIE_MAX_AGE as i64,
    )?;

    Ok(headers)
}
```

The CSRF token is verified for all state-changing operations:

```rust
// CSRF verification for state-changing methods
if method == Method::POST || method == Method::PUT || method == Method::DELETE {
    let x_csrf_token = headers
        .get("X-Csrf-Token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    if let Some(csrf_token) = x_csrf_token {
        if csrf_token != stored_session.csrf_token {
            return Ok(false);
        }
    } else {
        return Ok(false);
    }
}
```

For session boundary protection, we use an obfuscated version of the CSRF token:

```rust
// Obfuscate the CSRF token for page context
pub fn obfuscate_token(token: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}
```

#### Token Delivery

The CSRF token is delivered through two mechanisms:

1. **HTTP Headers**:
   - The CSRF token is required in the `X-CSRF-Token` header for all state-changing operations
   - This protects against cross-site request forgery attacks

2. **Page Embedding**:
   - The obfuscated CSRF token is embedded in the page as a JavaScript constant: `PAGE_CONTEXT_TOKEN`
   - This is used for session boundary verification
   - Example: `<script>const PAGE_CONTEXT_TOKEN = "{{ page_context_token }}";</script>`

### Page Context Token Verification

The `verify_context_token` function verifies that the page context token matches the obfuscated CSRF token:

```rust
pub async fn verify_context_token(
    headers: &HeaderMap,
    page_context: Option<&String>,
) -> Result<(), SessionError> {
    let session_id: &str = match get_session_id_from_headers(headers) {
        Ok(Some(session_id)) => session_id,
        _ => return Err(SessionError::ContextToken("Session ID missing".to_string())),
    };

    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    if let Some(page_context) = page_context {
        if page_context.as_str() != obfuscate_token(&stored_session.csrf_token) {
            tracing::error!("Page context token does not match session user");
            return Err(SessionError::ContextToken(
                "Page context token does not match session user".to_string(),
            ));
        }
    }

    Ok(())
}
```

## Benefits of the Implemented Approach

1. **Clear Intent Separation**: The `RegistrationMode` enum explicitly declares whether operations create users or modify existing ones
2. **Simplified Security Model**: Using CSRF tokens for both CSRF protection and session boundary verification
3. **Integrated Implementation**: Session management and security are tightly integrated
4. **Performance**: No additional storage or database lookups required
5. **User Experience**: Clear error messages guide users when synchronization fails
6. **Reduced Complexity**: Fewer mechanisms to maintain and understand

## Security Considerations

- CSRF tokens are obfuscated using HMAC-SHA256 to prevent direct exposure
- Token expiration is set to 1 day, balancing security and user experience
- Tokens are signed with HMAC-SHA256 using a configurable server secret
- Cookies are set with HttpOnly and SameSite=Strict to prevent XSS and CSRF attacks
- Error messages are user-friendly but don't expose sensitive information

## Special Considerations for OAuth2 Flows

OAuth2 flows present unique challenges for session boundary protection:

1. **Redirect and Cross-Domain Limitations**:
   - OAuth2 redirects to third-party providers and back
   - Cookies may not be preserved across domains
   - Custom headers like `X-CSRF-Token` cannot be set on redirects

2. **Our Solution**:
   - Use obfuscated CSRF tokens as page context tokens
   - Pass these tokens as query parameters in OAuth2 redirects
   - Verify the tokens when processing OAuth2 callbacks

3. **Security Benefits**:
   - Maintains session boundary protection despite redirect constraints
   - Avoids exposing raw CSRF tokens in URLs
   - Provides a consistent security model across all authentication flows

## Appendix: Alternative Approaches Considered

Several alternative approaches were considered before arriving at the signed composite token solution:

### 1. Using Raw User IDs

**Approach:**

- Embed raw user IDs in pages and/or cookies
- Compare embedded user ID against session user ID

**Advantages:**

- Extremely simple implementation
- No cryptographic operations needed
- Direct comparison logic

**Why Disregarded:**

- Exposes internal identifiers
- No built-in expiration mechanism
- No protection against tampering
- Limited security properties

### 2. Extending SessionInfo with User Token

**Approach:**

```rust
pub struct SessionInfo {
    pub user_id: String,
    pub user_token: String,  // New field 
    pub expires_at: DateTime<Utc>,
}
```

**Advantages:**

- Simplicity of implementation
- Token automatically expires with session
- Directly tied to user's session

**Why Disregarded:**

- Blurs separation of concerns - session management vs. page context
- Mixes authentication logic with UI synchronization concerns
- Session component shouldn't need to know about UI state synchronization

### 3. Page Context Manager with Server-side Storage

**Approach:**

```rust
pub struct PageContextManager {
    storage: Arc<dyn Storage>,
}

impl PageContextManager {
    pub async fn create_context(&self, user_id: &str) -> Result<String, Error> {
        // Generate random token
        // Store in Redis/database with user_id
    }
    
    pub async fn verify_context(&self, token: &str, session_user_id: &str) -> Result<(), Error> {
        // Retrieve from storage
        // Verify user_id matches
    }
}
```

**Advantages:**

- Clean separation of concerns
- Can store additional context beyond user ID
- Tokens can be invalidated immediately
- More flexible for future extensions

**Why Disregarded:**

- Requires additional infrastructure (Redis, database)
- Storage lookups become potential bottleneck
- More complex implementation
- Unnecessary operational complexity for this specific use case
