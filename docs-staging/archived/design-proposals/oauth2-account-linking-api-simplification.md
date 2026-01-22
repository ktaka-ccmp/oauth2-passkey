# OAuth2 Account Linking API Simplification

## Problem Statement

The current OAuth2 account linking implementation creates a significant barrier to adoption due to its complexity. Users must understand and coordinate multiple concepts and API calls to accomplish what should be a simple operation.

## Current Complexity Issues

- **Multi-step process**: Users must call `/auth/user/csrf_token` endpoint to get CSRF token
- **Security token generation**: Must understand and call `generate_page_session_token(&csrf_token)`
- **URL construction**: Must construct OAuth2 URLs with `mode=add_to_user&context=${page_session_token}`
- **Session management**: Must handle popup window management and session verification
- **Implementation burden**: Requires ~50+ lines of code for what should be a simple operation

## Current Implementation Example

```rust
// Server-side: Multiple endpoints and complex logic
async fn get_csrf_token(auth_user: AuthUser) -> Json<Value> {
    Json(json!({"csrf_token": auth_user.csrf_token}))
}

async fn get_page_session_token_for_oauth2_linking(
    browser: &MockBrowser,
) -> Result<String, Box<dyn std::error::Error>> {
    use oauth2_passkey::generate_page_session_token;

    let csrf_response = browser.get("/auth/user/csrf_token").await?;
    let csrf_data: serde_json::Value = csrf_response.json().await?;

    if let Some(csrf_token) = csrf_data.get("csrf_token").and_then(|v| v.as_str()) {
        let page_session_token = generate_page_session_token(csrf_token);
        return Ok(page_session_token);
    }

    Err("CSRF token not found in response".into())
}
```

```javascript
// Client-side: Complex multi-step coordination
async function linkGoogleAccount() {
    // Step 1: Get CSRF token
    const csrfResponse = await fetch('/auth/user/csrf_token');
    const {csrf_token} = await csrfResponse.json();

    // Step 2: Generate page session token (requires understanding internals)
    const pageSessionToken = await generatePageSessionToken(csrf_token);

    // Step 3: Construct OAuth2 URL with proper parameters
    const oauth2Url = `/auth/oauth2/google/start?mode=add_to_user&context=${pageSessionToken}`;

    // Step 4: Handle popup and session management
    const popup = window.open(oauth2Url, 'oauth2_linking', 'width=500,height=600');

    const checkClosed = setInterval(() => {
        if (popup.closed) {
            clearInterval(checkClosed);
            location.reload();
        }
    }, 1000);
}
```

## Proposed Simplification Approaches

### 1. One-Function Approach ⭐ **(Recommended)**

```rust
// Instead of complex multi-step process:
let link_url = auth_user.create_oauth2_link_url("google").await?;
// Returns secure URL with all complexity handled internally
```

**Benefits:**
- Single function call handles all complexity internally
- No need to understand CSRF tokens or page session tokens
- Maintains all security guarantees transparently

### 2. Builder Pattern with Sensible Defaults

```rust
let link_url = OAuth2AccountLinker::new(&auth_user)
    .provider("google")
    .build_link_url().await?;

// Or with additional options:
let link_url = OAuth2AccountLinker::new(&auth_user)
    .provider("google")
    .redirect_uri("/custom/callback")
    .popup_dimensions(600, 700)
    .build_link_url().await?;
```

**Benefits:**
- Flexible configuration while maintaining simplicity
- Clear, self-documenting API
- Easy to extend with additional options

### 3. Session-Aware Middleware

```rust
// Middleware automatically handles session/CSRF complexity
async fn link_oauth2_handler(
    Extension(oauth2_linker): Extension<OAuth2Linker>,
    auth_user: AuthUser,
    Query(params): Query<LinkParams>,
) -> impl IntoResponse {
    oauth2_linker.start_linking(&auth_user, &params.provider).await
}
```

**Benefits:**
- Zero-configuration for basic use cases
- Framework integration handles complexity
- Consistent behavior across the application

### 4. Trait-Based Approach

```rust
impl OAuth2Linkable for AuthUser {
    async fn link_google_account(&self) -> Result<String, Error>;
    async fn link_github_account(&self) -> Result<String, Error>;
    async fn link_provider_account(&self, provider: &str) -> Result<String, Error>;
}
```

**Benefits:**
- Natural extension of existing AuthUser type
- Type-safe provider methods
- Discoverable through IDE autocomplete

### 5. Embedded JavaScript Helper

```rust
// Server provides JS snippet that handles everything
async fn oauth2_linking_script(auth_user: AuthUser) -> JavaScript {
    generate_oauth2_linking_script(&auth_user).await
}
```

```javascript
// Generated JavaScript handles all complexity
<script src="/auth/oauth2/linking.js"></script>
<script>
    OAuth2Linker.linkGoogle(); // Everything handled internally
</script>
```

**Benefits:**
- Zero JavaScript implementation required
- Server-generated code ensures security
- Framework-agnostic client-side usage

## Final Recommendation: Combine Approaches #1 and #4

The most intuitive solution combines the one-function approach with trait-based extensions:

### Server-Side Implementation

```rust
// Simple, secure API
async fn add_google_account(auth_user: AuthUser) -> impl IntoResponse {
    match auth_user.create_oauth2_link_url("google").await {
        Ok(url) => Json(json!({"link_url": url})),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    }
}

// Or even simpler with trait methods:
async fn add_google_account(auth_user: AuthUser) -> impl IntoResponse {
    match auth_user.link_google_account().await {
        Ok(url) => Json(json!({"link_url": url})),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    }
}
```

### Client-Side Implementation

```javascript
// Simple, clean client code
async function linkGoogleAccount() {
    const response = await fetch('/api/link-google');
    const {link_url} = await response.json();
    window.open(link_url, 'oauth2_link', 'width=500,height=600');
}
```

## Implementation Strategy

### Phase 1: Core Function
- Implement `create_oauth2_link_url()` method that encapsulates all current complexity
- Handle CSRF token retrieval, page session token generation, and URL construction internally
- Maintain backward compatibility with existing implementation

### Phase 2: Trait Extension
- Add `OAuth2Linkable` trait with provider-specific methods
- Implement trait for `AuthUser` type
- Provide convenient methods like `link_google_account()`, `link_github_account()`

### Phase 3: Documentation and Examples
- Update documentation to showcase simplified API
- Provide migration guide from complex implementation
- Add examples for common use cases

## Security Considerations

All simplification approaches must maintain the current security guarantees:

- **CSRF Protection**: Page session tokens still generated and verified internally
- **Session Boundary Protection**: Ensure OAuth2 linking happens for the correct user
- **State Management**: Maintain proper state throughout the OAuth2 flow
- **Token Security**: Secure handling of all authentication tokens

The complexity should be hidden from the user, not eliminated from the implementation.

## Target Goal

**Reduce implementation from 50+ lines to 5-10 lines while maintaining all security guarantees.**

### Before (Current)
```rust
// ~50+ lines of complex coordination
async fn link_oauth2_account() {
    // Multiple API calls, token management, URL construction, etc.
}
```

### After (Proposed)
```rust
// ~5 lines of simple, secure code
async fn link_oauth2_account(auth_user: AuthUser) -> impl IntoResponse {
    match auth_user.create_oauth2_link_url("google").await {
        Ok(url) => Json(json!({"link_url": url})),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    }
}
```

This represents a 90% reduction in implementation complexity while maintaining 100% of the security features.
