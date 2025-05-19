# OAuth2 Session Boundary Protection

## The Problem

We encountered a specific security issue in our OAuth2 implementation where users could accidentally add OAuth2 accounts to the wrong user account. This happened in the following scenario:

1. A user views their account page (User A) with an "Add OAuth2 Account" button
2. The user opens another tab and logs in as a different user (User B)
3. The user returns to the first tab (still showing User A's page)
4. The user clicks "Add OAuth2 Account", expecting to add the account to User A
5. The OAuth2 account gets added to User B instead, because that's the active session

This created a serious usability and security problem:

- Users could accidentally link their Google/OAuth2 accounts to the wrong user account
- Users might not notice the mistake until much later
- Recovering from this mistake required manual intervention

## Our Solution

We solved this problem by implementing **Page Session Tokens** specifically for the OAuth2 account addition flow. Here's how we addressed it:

1. When rendering the user account page, we generate a token derived from the user's CSRF token
2. We embed this token in the page as a JavaScript constant: `SESSION_BINDING_TOKEN`
3. When the user clicks "Add OAuth2 Account", this token is included in the OAuth2 authorization request
4. Before redirecting to the OAuth2 provider, we verify that this token matches the current session

This creates a binding between the specific page the user is viewing and their current session, preventing the session boundary confusion.

## How We Implemented It

### 1. Token Generation

We generate the page session token by applying HMAC-SHA256 to the user's CSRF token, creating a secure derivative that can't be reverse-engineered:

```rust
pub fn generate_page_session_token(token: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}
```

### 2. Embedding in the User Interface

When we render the user's account page, we include this token as a JavaScript constant:

```html
<script>
    // Page session token for session boundary protection
    const SESSION_BINDING_TOKEN = "{{ page_session_token }}";
</script>
```

And we use it in the OAuth2 account addition button:

```html
<button onclick="oauth2.openPopup('add_to_user', SESSION_BINDING_TOKEN)" class="action-button">
    Add New OAuth2 Account
</button>
```

### 3. Verification Before OAuth2 Redirect

The critical part is verifying this token before we redirect the user to the OAuth2 provider. This happens in our OAuth2 handler:

```rust
// In oauth2.rs
async fn google_auth(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, (StatusCode, String)> {
    // Extract the page session token from the request
    if let Some(token) = params.get("context") {
        if token.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Missing Session".to_string()));
        }

        // Verify that the token matches the current session
        verify_page_session_token(&headers, Some(token))
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    }

    // If verification passes, proceed with OAuth2 flow
    // ...
}
```

The verification function checks that the token matches what we'd expect for the current session:

```rust
pub async fn verify_page_session_token(
    headers: &HeaderMap,
    page_session_token: Option<&String>,
) -> Result<(), SessionError> {
    // Get the current session
    let session_id = get_session_id_from_headers(headers)?
        .ok_or_else(|| SessionError::PageSessionToken("Session ID missing".to_string()))?;

    let stored_session = get_session_from_store(session_id).await?;

    // Verify the token matches what we'd generate for this session
    match page_session_token {
        Some(token) => {
            let expected_token = generate_page_session_token(&stored_session.csrf_token);
            if token != &expected_token {
                return Err(SessionError::PageSessionToken(
                    "Page session token does not match session user".to_string(),
                ));
            }
        }
        None => {
            return Err(SessionError::PageSessionToken(
                "Page session token missing".to_string(),
            ));
        }
    }

    Ok(())
}
```

## Why This Works

Our solution works because:

1. The page session token is derived from the CSRF token of the user who was logged in when the page was loaded
2. If the user's session changes (by logging out and in as another user), the CSRF token in the new session will be different
3. When we verify the page session token, it won't match what we'd expect for the current session
4. We can reject the OAuth2 flow before it even starts, preventing the wrong account linkage

## Benefits of Our Approach

1. **Prevents Account Confusion**: Users can't accidentally add OAuth2 accounts to the wrong user
2. **Simple Implementation**: Leverages existing CSRF tokens rather than creating a new system
3. **No Additional Storage**: The solution is stateless and requires no extra database entries
4. **Minimal Performance Impact**: Just a single HMAC operation with negligible overhead

## How to Test It

You can verify this protection works by following these steps:

1. Log in as User A and open their account page
2. In another tab, log out and log in as User B
3. Return to User A's account page and click "Add OAuth2 Account"
4. The system should display an error message about session mismatch
5. The OAuth2 flow should not proceed

## Conclusion

By implementing page session tokens in our OAuth2 flow, we've solved a specific security issue where users could accidentally add OAuth2 accounts to the wrong user. This simple but effective solution creates a binding between the page a user is viewing and their current session, preventing confusion and security issues when users have multiple accounts or browser tabs open.

This approach demonstrates how small, targeted security measures can solve specific problems without adding unnecessary complexity to the system.
