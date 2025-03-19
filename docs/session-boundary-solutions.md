# Session Boundary Solutions

## Problem Statement

The authentication system currently has session boundary problems:

1. When a user intends to add a new passkey credential or link a new OAuth2 account to an existing user account, the system may incorrectly create a new user if there is no valid session.

2. A specific edge case exists where a user might have multiple accounts and accidentally add credentials to the wrong account due to session desynchronization:
   - User views account #1's page with "add credential" button
   - User gets distracted, logs in as account #2 in another tab
   - User returns to account #1's page, but now has a session for account #2
   - User clicks "add credential" button, believing it will add to account #1, but it actually adds to account #2

## Proposed Solutions

### 1. Dedicated Functions with Clear Intent

Create dedicated functions that separate user creation from credential addition:

- `add_new_passkey_to_user(auth_user, ...)` - Only adds passkey to existing user, never creates new user
- `add_new_oauth2_account_to_user(auth_user, ...)` - Only links OAuth2 to existing user
- `add_new_user_with_passkey(...)` - Explicitly creates new user with passkey
- `add_new_user_with_oauth2_account(...)` - Explicitly creates new user with OAuth2

These functions would explicitly fail if their preconditions aren't met (e.g., attempting to add a passkey to an existing user without a valid session).

### 2. Session/Page Synchronization with Signed Tokens

To solve the desynchronization problem where a user's session changes but they're viewing a page for a different account, implement a dual verification approach:

#### Signed Composite Token Approach

1. **Generate a signed token** that contains:
   - User ID
   - Expiration timestamp
   - Cryptographic signature

```rust
fn generate_user_context_token(user_id: &str) -> String {
    let expiry = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp();
    let data = format!("{}:{}", user_id, expiry);
    let signature = hmac_sign(data.as_bytes(), &SERVER_SECRET);
    
    format!("{}:{}", data, base64::encode(signature))
}
```

1. **Verify token** before performing sensitive operations:

```rust
fn verify_user_context_token(token: &str, session_user_id: &str) -> Result<(), AuthError> {
    // Parse and verify token components (user_id, expiry, signature)
    // ...
    
    // Verify user ID matches session
    if token_user_id != session_user_id {
        return Err(AuthError::SessionMismatch(
            "Your session has changed since this page was loaded".to_string()
        ));
    }
    
    Ok(())
}
```

#### Dual Token Delivery

For maximum protection, use both approaches simultaneously:

1. **Persistent Cookie**:
   - Set a cookie containing the signed token with longer expiration than session
   - Check this cookie on all sensitive requests

1. **Page Embedding**:
   - Embed the same signed token in forms and page elements
   - Include with specific sensitive form submissions
   - Provides stronger verification for the specific page context

## Benefits of This Approach

1. **Clear Intent Separation**: Functions explicitly declare whether they create users or modify existing ones
2. **Defense in Depth**: Dual verification catches session changes from multiple paths
3. **Stateless Implementation**: No additional server-side storage needed
4. **Performance**: No database lookups required for verification
5. **Separation of Concerns**: Authentication logic remains separate from page synchronization logic

## Implementation Steps

1. Create the dedicated user/credential management functions
1. Implement token generation and verification logic
1. Update login flow to set context token cookie
1. Update templates to embed context token in forms
1. Add verification to sensitive operation handlers
1. Add clear error messages and recovery paths for synchronization failures

## Considerations

- Token expiration should be balanced against user experience
- Error messages should guide users to refresh the page when synchronization fails
- Consider implementing a JavaScript-based polling mechanism to detect stale pages

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
