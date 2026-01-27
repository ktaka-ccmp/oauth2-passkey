# Chapter 21: Axum Integration API (oauth2-passkey-axum)

## Overview

The `oauth2-passkey-axum` crate provides Axum web framework integration for the `oauth2-passkey` authentication library. It offers ready-to-use routers, middleware, and extractors for OAuth2 and WebAuthn/Passkey authentication.

**Full API Documentation**: [https://docs.rs/oauth2-passkey-axum](https://docs.rs/oauth2-passkey-axum)

## Quick Start

```rust
use axum::{Router, response::Html};
use oauth2_passkey_axum::{oauth2_passkey_full_router, init};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication
    init().await?;

    // Create application router
    let app: Router = Router::new()
        .route("/", axum::routing::get(|| async { Html("Hello World!") }))
        // Add all authentication routes with a single call
        .merge(oauth2_passkey_full_router());

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Routers

### oauth2_passkey_full_router (Recommended)

The unified router that provides all authentication endpoints. This is the recommended way to add authentication to your application.

```rust
use oauth2_passkey_axum::oauth2_passkey_full_router;

let app = Router::new()
    .merge(oauth2_passkey_full_router());
```

This router:
- Nests all auth endpoints under `O2P_ROUTE_PREFIX` (default: `/o2p`)
- Automatically includes `/.well-known/webauthn` when `WEBAUTHN_ADDITIONAL_ORIGINS` is configured
- Handles single-origin and multi-origin setups seamlessly

**Endpoints provided**:

| Path | Description |
|------|-------------|
| `{O2P_ROUTE_PREFIX}/oauth2/...` | OAuth2 authentication endpoints |
| `{O2P_ROUTE_PREFIX}/passkey/...` | WebAuthn/Passkey authentication endpoints |
| `{O2P_ROUTE_PREFIX}/user/...` | User account management endpoints |
| `{O2P_ROUTE_PREFIX}/admin/...` | Admin interface endpoints |
| `/.well-known/webauthn` | WebAuthn relying party configuration (only when multi-origin is configured) |

See [Endpoint Reference](#endpoint-reference) for complete details.

### oauth2_passkey_router

The auth-only router without the prefix nesting. Use this for custom setups where you need more control.

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

Router for the WebAuthn well-known endpoint. Only needed if you use `oauth2_passkey_router()` directly with a multi-origin setup.

```rust
use oauth2_passkey_axum::{oauth2_passkey_router, passkey_well_known_router, O2P_ROUTE_PREFIX};

let app = Router::new()
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
    .merge(passkey_well_known_router());
```

This creates a `/.well-known/webauthn` endpoint for WebAuthn relying party configuration. See [Multi-Origin Passkey Setup](../integration/multi-origin.md) for details.

> **Note**: If you use `oauth2_passkey_full_router()`, this endpoint is included automatically when needed.

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
| `O2P_ACCOUNT_URL` | User account management page URL |
| `O2P_DEFAULT_REDIRECT` | Default redirect URL for auth flows |

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
    oauth2_passkey_full_router, is_authenticated_user_401, AuthUser, init
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
        // Authentication routes (includes /.well-known/webauthn when needed)
        .merge(oauth2_passkey_full_router())
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

## Endpoint Reference

Complete list of all endpoints provided by `oauth2_passkey_router()`.

### OAuth2 Endpoints (`/oauth2`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/google` | GET | Start Google OAuth2 authentication flow |
| `/authorized` | GET, POST | OAuth2 callback endpoint (redirect URI) |
| `/popup_close` | GET | Close popup window after OAuth2 flow |
| `/accounts` | GET | List user's linked OAuth2 accounts |
| `/accounts/{provider}/{provider_user_id}` | DELETE | Unlink an OAuth2 account |
| `/oauth2.js` | GET | JavaScript SDK for OAuth2 operations |

### Passkey Endpoints (`/passkey`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register/start` | POST | Start passkey registration ceremony |
| `/register/finish` | POST | Complete passkey registration ceremony |
| `/auth/start` | POST | Start passkey authentication ceremony |
| `/auth/finish` | POST | Complete passkey authentication ceremony |
| `/credentials` | GET | List user's passkey credentials |
| `/credentials/{credential_id}` | DELETE | Delete a passkey credential |
| `/credential/update` | POST | Update passkey credential metadata |
| `/conditional_ui` | GET | Conditional UI page for passkey autofill* |
| `/passkey.js` | GET | JavaScript SDK for passkey operations |
| `/conditional_ui.js` | GET | JavaScript for conditional UI* |

### User Endpoints (`/user`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET | Login page* |
| `/account` | GET | User account management page* |
| `/logout` | GET | End session and redirect |
| `/info` | GET | Get current user info as JSON* |
| `/csrf_token` | GET | Get CSRF token for API calls* |
| `/delete` | DELETE | Delete user account |
| `/update` | PUT | Update user profile (account, label) |
| `/account.js` | GET | JavaScript for account page* |
| `/account.css` | GET | CSS for account page* |
| `/o2p-base.css` | GET | Base CSS styles* |

### Admin Endpoints (`/admin`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/index` | GET | User management list page* |
| `/user/{user_id}` | GET | User detail page* |
| `/delete_user` | DELETE | Delete a user (admin only) |
| `/delete_passkey_credential` | DELETE | Delete user's passkey (admin only) |
| `/delete_oauth2_account` | DELETE | Unlink user's OAuth2 account (admin only) |
| `/update_admin_status` | PUT | Grant/revoke admin privileges |
| `/admin_user.js` | GET | JavaScript for admin pages* |
| `/admin_user.css` | GET | CSS for admin pages* |

### Feature Flags

Endpoints marked with * are controlled by feature flags:

| Feature | Default | Endpoints Affected |
|---------|---------|-------------------|
| `user-ui` | ON | `/user/login`, `/user/account`, `/user/info`, `/user/csrf_token`, static files |
| `admin-ui` | ON | `/admin/index`, `/admin/user/{id}`, admin static files |

API endpoints (authentication, CRUD operations) are always available regardless of feature flags.

```toml
# Disable all built-in UI
oauth2-passkey-axum = { version = "0.2", default-features = false }

# Keep user UI, disable admin UI
oauth2-passkey-axum = { version = "0.2", default-features = false, features = ["user-ui"] }

# Keep admin UI, disable user UI
oauth2-passkey-axum = { version = "0.2", default-features = false, features = ["admin-ui"] }
```

### Additional Router: `passkey_well_known_router()`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/webauthn` | GET | WebAuthn relying party configuration |

This router should be merged at the root level (not nested under `O2P_ROUTE_PREFIX`). Only needed for multi-origin setups. See [Multi-Origin Passkey Setup](../integration/multi-origin.md).
