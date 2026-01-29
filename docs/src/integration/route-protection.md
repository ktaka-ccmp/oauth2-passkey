# Route Protection

This chapter covers different methods to protect routes in your Axum application.

## Method 1: AuthUser Extractor (Simplest)

Use `AuthUser` as an extractor. Unauthenticated users are redirected to login.

```rust,ignore
use oauth2_passkey_axum::AuthUser;

// Requires authentication - redirects to login if not authenticated
async fn dashboard(user: AuthUser) -> String {
    format!("Welcome, {}! (user_id: {})", user.label, user.user_id)
}

// AuthUser fields:
// - user_id: Unique user identifier
// - label: Display name
// - account: Account identifier
// - csrf_token: CSRF token for forms
// - is_admin: Whether user has admin privileges
```

## Method 2: Option\<AuthUser\> (Optional Authentication)

Allow both authenticated and anonymous users:

```rust,ignore
use oauth2_passkey_axum::AuthUser;

// Works for both authenticated and anonymous users
async fn public_page(user: Option<AuthUser>) -> String {
    match user {
        Some(u) => format!("Hello, {}!", u.label),
        None => "Hello, Anonymous!".to_string(),
    }
}
```

## Method 3: Middleware (Route-Layer Protection)

Apply middleware to protect entire routes or groups:

```rust,ignore
use axum::{Router, Extension, middleware::from_fn, routing::get};
use oauth2_passkey_axum::{
    is_authenticated_redirect,      // Redirects to login
    is_authenticated_user_redirect, // Redirects + provides AuthUser via Extension
    is_authenticated_401,           // Returns 401 (for APIs)
    AuthUser, CsrfToken,
};

let app = Router::new()
    // Method 3a: Middleware only (no user info needed)
    .route("/protected", get(protected_page)
        .route_layer(from_fn(is_authenticated_redirect)))

    // Method 3b: Middleware + user info via Extension
    .route("/dashboard", get(dashboard_with_user)
        .route_layer(from_fn(is_authenticated_user_redirect)))

    // Method 3c: Protect entire nested router
    .nest("/admin", admin_router()
        .route_layer(from_fn(is_authenticated_redirect)));

// With is_authenticated_redirect: no user argument needed
async fn protected_page() -> String {
    "Protected content".to_string()
}

// With is_authenticated_user_redirect: get user via Extension
async fn dashboard_with_user(Extension(user): Extension<AuthUser>) -> String {
    format!("Welcome, {}!", user.label)
}
```

### Middleware Comparison

| Middleware | Unauthenticated | Available in Handler |
|------------|-----------------|----------------------|
| `is_authenticated_redirect` | Redirect to login | `CsrfToken` |
| `is_authenticated_user_redirect` | Redirect to login | `AuthUser` (includes csrf_token) |
| `is_authenticated_401` | Return 401 | `CsrfToken` |
| `is_authenticated_user_401` | Return 401 | `AuthUser` (includes csrf_token) |

> **Note**: The `_user_` variants perform an additional database query to fetch user information. Use the non-user variants when you only need to verify authentication without accessing user details in your handler.

> **Note**: Handlers receive the CSRF token to embed in rendered pages. See [CSRF Token Handling](csrf-handling.md) for details.

## When to Use Each Method

| Method | Use Case |
|--------|----------|
| `AuthUser` extractor | Simple protected routes where you need user info |
| `Option<AuthUser>` | Pages that work for both authenticated and anonymous users |
| `is_authenticated[_user]_redirect` | Protect routes with redirect to login for unauthenticated users |
| `is_authenticated[_user]_401` | API endpoints that should return 401 instead of redirect |
