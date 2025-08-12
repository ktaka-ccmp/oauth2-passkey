# Session Boundary Protection

## Problem Statement

Modern web applications that support authentication and multi-account workflows are vulnerable to session boundary problems-situations where actions are performed in the wrong user context. These issues can lead to serious security and usability risks, such as accidental credential linking or unauthorized account access.

Two common session boundary problems are:

1. **Page-to-Request Desynchronization**:
   A user loads a page while logged in as Account #1. Later, they log in as Account #2 in another tab or window. If they return to the original page and perform an action (e.g., add credentials), that action may be executed as Account #2, not Account #1-potentially linking credentials to the wrong user.

2. **Process Start-to-Completion Desynchronization**:
   In multi-step processes (such as passkey or OAuth2 registration), a user might start the process with one account but complete it after switching sessions. This can result in credentials being registered to an unintended user or session.

We address these risks by implementing specific protection mechanisms tailored to each phase of potential session desynchronization.

## Protection Mechanisms for Different Desynchronization Phases

We implement different protection mechanisms for different phases of potential session desynchronization:

### Passkey Registration Flow

#### Phase 1: Protection Against Page-to-Request Desynchronization

When a user clicks "Add Passkey" on a user profile page, we use **standard CSRF protection** to detect if the session has changed since the page was loaded:

```rust
// When user clicks "Add Passkey", the CSRF token from the page must match the session
if x_csrf_token != stored_session.csrf_token {
    return Err("CSRF token mismatch");
}
```

This ensures the user who clicks the button is the same one who loaded the page, preventing accidental credential addition to the wrong account.

#### Phase 2: Protection Against Start-to-Completion Desynchronization

During the passkey registration process itself, we verify the user ID at completion time to ensure it matches the ID from when registration started:

```rust
// When completing passkey registration:
if session_user.id != session_info.user.id { // session_info from registration start
    return Err(PasskeyError::Format("User ID mismatch"));
}
```

This catches any session changes that might have occurred during the registration process.

### OAuth2 Account Linking Flow

#### Phase 1: Protection Against Page-to-Request Desynchronization

For OAuth2 account linking, standard CSRF protection isn't sufficient because the flow involves redirects to third-party providers. Instead, we use **page session tokens**:

```rust
// Generate an obfuscated version of the CSRF token for use in redirects
pub fn generate_page_session_token(token: &str) -> String {
    // HMAC-SHA256 of the CSRF token
    // ...
}
```

This token is embedded in the page and included when initiating the OAuth2 flow:

```html
<script>
    const PAGE_SESSION_TOKEN = "{{ page_session_token }}";

    function addOAuth2Account() {
        oauth2.openPopup('add_to_user', PAGE_SESSION_TOKEN);
    }
</script>
```

When the OAuth2 flow begins, we verify the page session token matches the current session:

```rust
async fn google_auth(
    auth_user: Option<AuthUser>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    // Verify that page session token matches current session
    verify_page_session_token(&headers, Some(&context.unwrap()))
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Only after verification passes do we proceed
    // ...
}
```

#### Phase 2: Protection During the OAuth2 Flow

The primary mechanism for maintaining session continuity throughout the OAuth2 flow is the preservation of the original session context:

1. **Session Context Preservation**:
   When starting the OAuth2 flow, we store the current session ID to maintain user context:

   ```rust
   // In prepare_oauth2_auth_request: Store the current session ID in cache
   let misc_id = if let Some(session_id) = get_session_id_from_headers(&headers)? {
       tracing::info!("Session ID found: {}", session_id);
       Some(store_token_in_cache("misc_session", session_id, ttl, expires_at, None).await?)
   } else {
       tracing::debug!("No session ID found");
       None
   };

   // Include the misc_id in the state parameter
   let state_params = StateParams {
       csrf_id,
       nonce_id,
       pkce_id,
       misc_id,  // Reference to stored session ID - critical for session continuity
       mode_id,
   };
   ```

2. **Session Context Retrieval**:
   When completing the OAuth2 flow, we retrieve the original user context regardless of the current session state:

   ```rust
   // Get the original user from the session stored at flow initiation
   pub(crate) async fn get_uid_from_stored_session_by_state_param(
       state_params: &StateParams,
   ) -> Result<Option<SessionUser>, OAuth2Error> {
       // Extract the misc_id from the state parameter
       let Some(misc_id) = &state_params.misc_id else {
           tracing::debug!("No misc_id in state");
           return Ok(None);
       };

       tracing::debug!("misc_id: {:#?}", misc_id);

       // Get the session ID that was stored at the beginning of the flow
       let Ok(token) = get_token_from_store::<StoredToken>("misc_session", misc_id).await else {
           tracing::debug!("Failed to get session from cache");
           return Ok(None);
       };

       tracing::debug!("Token: {:#?}", token);
       // Note: The actual codebase has a commented-out call here:
       // // remove_token_from_store("misc_session", misc_id).await?;

       // Retrieve the user from that original session
       match get_user_from_session(&token.token).await {
           Ok(user) => {
               tracing::debug!("Found user ID: {}", user.id);
               Ok(Some(user))
           },
           Err(e) => {
               tracing::debug!("Failed to get user from session: {}", e);
               Ok(None)
           }
       }
   }
   ```

3. **Session Context Usage**:
   The preserved session context is retrieved and used during OAuth2 account linking, regardless of flow type:

   ```rust
   // During OAuth2 account linking process
   // First decode the state parameter to access misc_id
   let state_in_response = decode_state(&auth_response.state)?;

   // Extract user_id from the stored session if available
   let state_user = get_uid_from_stored_session_by_state_param(&state_in_response).await?;

   // Use this preserved user context for account linking
   if let Some(user) = state_user {
       // Link the OAuth2 account to the original user who initiated the flow
       // regardless of current session state
       // ...
   }
   ```

This approach ensures that:

- The OAuth2 account is always linked to the user who initiated the flow
- Session changes during the OAuth2 process don't affect the final account linking
- We maintain a continuous user context from flow initiation to completion

## Key Security Characteristics

1. **Phase-Specific Protection**: Each mechanism addresses a specific phase where session desynchronization can occur:
   - CSRF protection: Between page load and request submission
   - User ID verification: Between process start and completion
   - Page session tokens: Throughout redirect-based flows

2. **Early Detection**: Problems are caught at the earliest possible point:
   - Page-level desynchronization is caught before the process starts
   - Process-level desynchronization is caught before registration completes

3. **Minimal Implementation**:
   - Leverages existing CSRF token mechanism wherever possible
   - Uses simple verification logic with clear error handling
   - No additional database storage required beyond temporary process state
