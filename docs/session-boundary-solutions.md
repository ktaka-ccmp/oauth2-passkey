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
    AddToExistingUser,
    /// Creating a new user with a passkey (no authentication required)
    NewUser,
}
```

These modes are used in the client JavaScript and server-side handlers to explicitly indicate the user's intent:

```javascript
// Client-side: Explicit mode when showing registration modal
function showRegistrationModal(mode) { // 'new_user' or 'add_to_existing_user'
    const modal = createRegistrationModal();
    modal.style.display = 'block';
    modal.dataset.mode = mode;
    // ...
}
```

```rust
// Server-side: Mode-specific handling
match body.mode {
    RegistrationMode::AddToExistingUser => {
        // Verify user is authenticated
        // Verify context token matches session
        // Add passkey to existing user
    },
    RegistrationMode::NewUser => {
        // Create new user with passkey
    },
}
```

### 2. Session/Page Synchronization with Signed Tokens

We implemented a dual verification approach using signed context tokens:

#### Signed Composite Token Implementation

The token generation function creates a signed token containing the user ID, expiration, and signature:

```rust
pub fn generate_user_context_token(user_id: &str) -> String {
    let expires_at = Utc::now() + Duration::days(1);
    let expiry_str = expires_at.timestamp().to_string();

    // Create the data string
    let data = format!("{}{}", user_id, expiry_str);

    // Sign the data with HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(&AUTH_SERVER_SECRET)
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_base64 = URL_SAFE_NO_PAD.encode(signature);

    // Format as data:signature
    format!("{}{}", data, signature_base64)
}
```

The token verification function checks that the token is valid, not expired, and belongs to the correct user:

```rust
pub fn verify_user_context_token(token: &str, session_user_id: &str) -> Result<(), AuthError> {
    // Parse token parts
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return Err(AuthError::Authentication(
            "Invalid token format".to_string(),
        ));
    }

    let token_user_id = parts[0];
    let expiry_str = parts[1];
    let signature_base64 = parts[2];

    // Check expiration
    let expiry = expiry_str
        .parse::<i64>()
        .map_err(|_| AuthError::Authentication("Invalid expiration format in token".to_string()))?;

    let now = Utc::now().timestamp();
    if now > expiry {
        return Err(AuthError::Authentication("Token has expired".to_string()));
    }

    // Verify signature
    let data = format!("{}{}", token_user_id, expiry_str);
    let mut mac = HmacSha256::new_from_slice(&AUTH_SERVER_SECRET)
        .map_err(|_| AuthError::Authentication("Failed to create HMAC".to_string()))?;
    mac.update(data.as_bytes());

    let signature = URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|_| AuthError::Authentication("Invalid signature encoding".to_string()))?;

    mac.verify_slice(&signature)
        .map_err(|_| AuthError::Authentication("Invalid token signature".to_string()))?;

    // Check user ID matches session
    if token_user_id != session_user_id {
        return Err(AuthError::SessionMismatch(
            "Your session has changed since this page was loaded".to_string(),
        ));
    }

    Ok(())
}
```

#### Dual Token Delivery

We implemented both approaches for maximum protection:

1. **HTTP Cookie**:
   - Set a cookie containing the signed token with a 1-day expiration
   - The cookie is HttpOnly and SameSite=Strict for security
   - Example: `auth_context_token=user123:1742511092:0uOGXo_4fc9umHuDzMg_HRjbptC562Slkjw9alOEmWk`

2. **Page Embedding**:
   - Embed the user ID in the page as a JavaScript constant: `PAGE_USER_CONTEXT`
   - Include this context with sensitive operations like adding passkeys or OAuth2 accounts
   - Example: `<script>const PAGE_USER_CONTEXT = "{{ user.id }}";</script>`

### Combined Verification

The `verify_context_token_and_page` function checks both the cookie token and page context:

```rust
pub fn verify_context_token_and_page(
    headers: &HeaderMap,
    page_context: Option<&String>,
    user_id: &str,
) -> Result<(), super::errors::AuthError> {
    // Extract token from cookies
    let context_token = extract_context_token_from_cookies(headers)
        .ok_or_else(|| AuthError::Authentication("Context token missing".to_string()))?;

    // Verify token belongs to user
    verify_user_context_token(&context_token, user_id)?;

    // Verify page context matches user (if provided)
    if let Some(context) = page_context {
        if !context.is_empty() && context != user_id {
            return Err(AuthError::SessionMismatch(
                "Page context does not match session user".to_string(),
            ));
        }
    }

    Ok(())
}
```

## Benefits of the Implemented Approach

1. **Clear Intent Separation**: The `RegistrationMode` enum explicitly declares whether operations create users or modify existing ones
2. **Defense in Depth**: Dual verification with both cookies and page context catches session changes
3. **Stateless Implementation**: No additional server-side storage needed
4. **Performance**: No database lookups required for verification
5. **Separation of Concerns**: Authentication logic remains separate from page synchronization logic
6. **User Experience**: Clear error messages guide users when synchronization fails

## Security Considerations

- Token expiration is set to 1 day, balancing security and user experience
- Tokens are signed with HMAC-SHA256 using a configurable server secret
- Cookies are set with HttpOnly and SameSite=Strict to prevent XSS and CSRF attacks
- Error messages are user-friendly but don't expose sensitive information

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
