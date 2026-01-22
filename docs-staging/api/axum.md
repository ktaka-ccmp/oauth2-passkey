# Chapter 21: Axum Integration API (oauth2-passkey-axum)

## Overview

The `oauth2-passkey-axum` crate provides Axum web framework integration for the `oauth2-passkey` authentication library. It offers ready-to-use routers, middleware, and extractors for OAuth2 and WebAuthn/Passkey authentication.

**Full API Documentation**: [https://docs.rs/oauth2-passkey-axum](https://docs.rs/oauth2-passkey-axum)

## Quick Start

```rust
use axum::{Router, response::Html};
use oauth2_passkey_axum::{oauth2_passkey_router, init, O2P_ROUTE_PREFIX};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication
    init().await?;

    // Create application router
    let app: Router = Router::new()
        .route("/", axum::routing::get(|| async { Html("Hello World!") }))
        // Add authentication routes (default: /o2p)
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Routers

### oauth2_passkey_router

The main router that provides all authentication endpoints. Mount this at your desired route prefix.

```rust
use oauth2_passkey_axum::{oauth2_passkey_router, O2P_ROUTE_PREFIX};

let app = Router::new()
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

**Endpoints provided** (relative to mount point):

| Path | Description |
|------|-------------|
| `/oauth2/...` | OAuth2 authentication endpoints |
| `/passkey/...` | WebAuthn/Passkey authentication endpoints |
| `/user/...` | User account management endpoints |
| `/admin/...` | Admin interface endpoints |

### passkey_well_known_router

Router for the WebAuthn well-known endpoint. Should be mounted at the root level.

```rust
use oauth2_passkey_axum::passkey_well_known_router;

let app = Router::new()
    .merge(passkey_well_known_router())
    // Your other routes...
    ;
```

This creates a `/.well-known/webauthn` endpoint for WebAuthn relying party configuration.

## Middleware

Authentication middleware for protecting routes. All middleware functions:
1. Verify valid session cookie
2. For state-changing methods (POST, PUT, DELETE, PATCH), verify CSRF protection
3. Add CSRF token to response headers

### is_authenticated_401

Returns HTTP 401 Unauthorized for unauthenticated requests.

```rust
use axum::{Router, middleware::from_fn};
use oauth2_passkey_axum::is_authenticated_401;

let app: Router = Router::new()
    .route("/api/data", axum::routing::get(handler))
    .layer(from_fn(is_authenticated_401));
```

### is_authenticated_redirect

Redirects unauthenticated GET requests to login page; returns 401 for other methods.

```rust
use axum::{Router, middleware::from_fn};
use oauth2_passkey_axum::is_authenticated_redirect;

let app: Router = Router::new()
    .route("/dashboard", axum::routing::get(handler))
    .layer(from_fn(is_authenticated_redirect));
```

### is_authenticated_user_401

Like `is_authenticated_401`, but also extracts user data into an `Extension<AuthUser>`.

```rust
use axum::{Router, middleware::from_fn, extract::Extension};
use oauth2_passkey_axum::{is_authenticated_user_401, AuthUser};

async fn handler(Extension(user): Extension<AuthUser>) -> String {
    format!("Hello, {}", user.account)
}

let app: Router = Router::new()
    .route("/api/profile", axum::routing::get(handler))
    .layer(from_fn(is_authenticated_user_401));
```

### is_authenticated_user_redirect

Like `is_authenticated_redirect`, but also extracts user data into an `Extension<AuthUser>`.

```rust
use axum::{Router, middleware::from_fn, extract::Extension};
use oauth2_passkey_axum::{is_authenticated_user_redirect, AuthUser};

async fn handler(Extension(user): Extension<AuthUser>) -> String {
    format!("Hello, {}", user.account)
}

let app: Router = Router::new()
    .route("/dashboard", axum::routing::get(handler))
    .layer(from_fn(is_authenticated_user_redirect));
```

## Extractors

### AuthUser

Axum extractor for authenticated user information. Automatically verifies session and CSRF tokens.

```rust
use axum::routing::get;
use oauth2_passkey_axum::AuthUser;

async fn protected_handler(user: AuthUser) -> String {
    format!("Hello, {}!", user.label)
}

let app: Router = Router::new()
    .route("/protected", get(protected_handler));
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Unique user identifier |
| `account` | `String` | User's account name (email or username) |
| `label` | `String` | User's display name |
| `is_admin` | `bool` | Whether user has admin privileges |
| `sequence_number` | `Option<i64>` | Database sequence number |
| `created_at` | `DateTime<Utc>` | Account creation timestamp |
| `updated_at` | `DateTime<Utc>` | Last update timestamp |
| `csrf_token` | `String` | CSRF token for the session |
| `csrf_via_header_verified` | `bool` | Whether CSRF was verified via header |
| `session_id` | `String` | Session ID for secure API calls |

**Methods**:

- `has_admin_privileges()` - Returns `true` if user has admin rights (either `is_admin` flag or is first user)

**Optional Extraction**:

`AuthUser` also implements `OptionalFromRequestParts`, allowing optional user extraction:

```rust
async fn handler(user: Option<AuthUser>) -> String {
    match user {
        Some(u) => format!("Hello, {}!", u.label),
        None => "Hello, guest!".to_string(),
    }
}
```

## URL Constants

| Constant | Description |
|----------|-------------|
| `O2P_ROUTE_PREFIX` | Route prefix for auth endpoints (default: `/o2p`) |
| `O2P_LOGIN_URL` | Login page URL |
| `O2P_ADMIN_URL` | Admin interface URL |
| `O2P_SUMMARY_URL` | User summary page URL |
| `O2P_REDIRECT_ANON` | Redirect URL for anonymous users |

## Re-exports from oauth2-passkey

The following are re-exported from the core library for convenience:

| Item | Description |
|------|-------------|
| `init` | Initialize the authentication system |
| `O2P_ROUTE_PREFIX` | Route prefix constant |
| `CsrfToken` | CSRF token type |
| `CsrfHeaderVerified` | CSRF header verification marker |

## Example: Protected API Routes

```rust
use axum::{Router, routing::{get, post}, middleware::from_fn, Json};
use oauth2_passkey_axum::{
    oauth2_passkey_router, passkey_well_known_router,
    is_authenticated_user_401, AuthUser, init, O2P_ROUTE_PREFIX
};
use serde::Serialize;

#[derive(Serialize)]
struct UserProfile {
    id: String,
    name: String,
    is_admin: bool,
}

async fn get_profile(user: AuthUser) -> Json<UserProfile> {
    Json(UserProfile {
        id: user.id,
        name: user.label,
        is_admin: user.has_admin_privileges(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init().await?;

    // Protected API routes
    let api_routes = Router::new()
        .route("/profile", get(get_profile))
        .layer(from_fn(is_authenticated_user_401));

    let app = Router::new()
        // WebAuthn well-known endpoint (root level)
        .merge(passkey_well_known_router())
        // Authentication routes
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
        // Protected API
        .nest("/api", api_routes);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Example: Protected Web Pages with Redirect

```rust
use axum::{Router, routing::get, middleware::from_fn, response::Html};
use oauth2_passkey_axum::{is_authenticated_user_redirect, AuthUser};

async fn dashboard(user: AuthUser) -> Html<String> {
    Html(format!(
        "<h1>Welcome, {}!</h1><p>Your account: {}</p>",
        user.label,
        user.account
    ))
}

let protected_pages = Router::new()
    .route("/dashboard", get(dashboard))
    .layer(from_fn(is_authenticated_user_redirect));
```
