# oauth2-passkey-axum

[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey-axum.svg)](https://crates.io/crates/oauth2-passkey-axum)
[![Docs.rs](https://docs.rs/oauth2-passkey-axum/badge.svg)](https://docs.rs/oauth2-passkey-axum)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Axum web framework integration for the [`oauth2-passkey`](https://crates.io/crates/oauth2-passkey) authentication library.

This crate provides ready-to-use Axum handlers, middleware, and UI components for OAuth2 and passkey authentication in your Axum web applications.

## Features

- **Drop-in Axum Integration**: Pre-built routers and middleware
- **Admin UI**: Optional admin interface for user management
- **User UI**: Authentication pages and flows
- **Route Protection**: Middleware for protecting routes
- **CSRF Protection**: Built-in CSRF token handling
- **Static Assets**: CSS and JavaScript for authentication UI

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
oauth2-passkey-axum = "0.1"
```

## Basic Usage

```rust
use axum::{Router, response::Html};
use oauth2_passkey_axum::{oauth2_passkey_router, init, O2P_ROUTE_PREFIX};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication (reads configuration from environment variables)
    init().await?;

    // Create your application router
    let app = Router::new()
        .route("/", axum::routing::get(|| async { Html("Hello World!") }))
        // Add authentication routes (default: /o2p, configurable via O2P_ROUTE_PREFIX env var)
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
        .merge(/* other routes */);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Route Protection

Protect your routes with authentication middleware:

```rust
use oauth2_passkey_axum::{is_authenticated_user_redirect, AuthUser};
use axum::{middleware::from_fn, routing::get, Router, response::Html, Extension};

async fn protected_handler(Extension(user): Extension<AuthUser>) -> Html<String> {
    Html(format!("Hello, {}! You are authenticated.", user.account))
}

let app = Router::new()
    .route("/protected", get(protected_handler).route_layer(from_fn(is_authenticated_user_redirect));
```

Alternatively, use the `AuthUser` extractor directly (no middleware needed):

```rust
use oauth2_passkey_axum::AuthUser;
use axum::{routing::get, Router, response::Html};

async fn protected_handler(user: AuthUser) -> Html<String> {
    Html(format!("Hello, {}! You are authenticated.", user.account))
}

let app = Router::new()
    .route("/protected", get(protected_handler));
```

## Feature Flags

- `default = ["admin-ui", "user-ui"]` - Enable all UI components
- `admin-ui` - Include admin interface for user management
- `user-ui` - Include user authentication pages

Disable features you don't need:

```toml
[dependencies]
oauth2-passkey-axum = { version = "0.1", default-features = false, features = ["user-ui"] }
```

## Configuration

Same as the core library. Create a `.env` file:

```env
# Required: Base URL of your application
ORIGIN=https://yourdomain.com

# Database configuration
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL=sqlite:data/auth.db

# Cache configuration  
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL=redis://localhost:6379

# OAuth2 providers
OAUTH2_GOOGLE_CLIENT_ID=your_google_client_id
OAUTH2_GOOGLE_CLIENT_SECRET=your_google_client_secret

# Optional: Server secret (for token signing)
AUTH_SERVER_SECRET=your_32_character_secret_key_here

# Optional: Route configuration
O2P_ROUTE_PREFIX=/o2p
O2P_REDIRECT_ANON=https://yourdomain.com/
```

## Available Routes

When you include the authentication router, these routes are available (default prefix `/o2p`, configurable via `O2P_ROUTE_PREFIX` environment variable):

### OAuth2 Routes (`/o2p/oauth2/`)

- `GET /o2p/oauth2/google` - Start Google OAuth2 authentication
- `GET /o2p/oauth2/authorized` - OAuth2 callback (query mode)
- `POST /o2p/oauth2/authorized` - OAuth2 callback (form_post mode)
- `GET /o2p/oauth2/accounts` - List OAuth2 accounts for user
- `DELETE /o2p/oauth2/accounts/{provider}/{provider_user_id}` - Delete OAuth2 account

### Passkey Routes (`/o2p/passkey/`)

- `POST /o2p/passkey/register/start` - Start passkey registration
- `POST /o2p/passkey/register/finish` - Complete passkey registration
- `POST /o2p/passkey/auth/start` - Start passkey authentication
- `POST /o2p/passkey/auth/finish` - Complete passkey authentication
- `GET /o2p/passkey/credentials` - List passkey credentials for user
- `DELETE /o2p/passkey/credentials/{credential_id}` - Delete passkey credential
- `POST /o2p/passkey/credential/update` - Update passkey credential

### User Routes (`/o2p/user/`)

- `GET /o2p/user/login` - Login page (if `user-ui` feature enabled)
- `GET /o2p/user/summary` - User summary page (if `user-ui` feature enabled)
- `GET /o2p/user/info` - User info JSON (if `user-ui` feature enabled)
- `GET /o2p/user/csrf_token` - Get CSRF token (if `user-ui` feature enabled)
- `GET /o2p/user/logout` - User logout
- `DELETE /o2p/user/delete` - Delete user account
- `PUT /o2p/user/update` - Update user account

### Admin Routes (`/o2p/admin/`)

- `GET /o2p/admin/list_users` - List all users (admin only)
- `GET /o2p/admin/user/{user_id}` - User details page (admin only, if `admin-ui` feature enabled)
- `DELETE /o2p/admin/delete_user` - Delete user account (admin only)
- `DELETE /o2p/admin/delete_passkey_credential/{credential_id}` - Delete passkey credential (admin only)
- `DELETE /o2p/admin/delete_oauth2_account/{provider}/{provider_user_id}` - Delete OAuth2 account (admin only)
- `PUT /o2p/admin/update_admin_status` - Update user admin status (admin only)

### Static Assets

- `GET /o2p/oauth2/oauth2.js` - OAuth2 JavaScript
- `GET /o2p/passkey/passkey.js` - Passkey JavaScript
- `GET /o2p/passkey/conditional_ui.js` - Conditional UI JavaScript
- `GET /o2p/user/summary.js` - User summary JavaScript
- `GET /o2p/user/summary.css` - User summary CSS
- `GET /o2p/admin/admin_user.js` - Admin user JavaScript
- `GET /o2p/admin/admin_user.css` - Admin user CSS

## Middleware Functions

| Middleware | User Data | Error Response | Use Case |
|------------|-----------|----------------|----------|
| `is_authenticated_redirect` | ❌ | Redirect | Browser pages |
| `is_authenticated_401` | ❌ | HTTP 401 | API endpoints |
| `is_authenticated_user_redirect` | ✅ | Redirect | Browser pages with user info |
| `is_authenticated_user_401` | ✅ | HTTP 401 | API endpoints with user info |

**Quick Guide:**

- Need user data in handler? → Use `*_user_*` variants
- Browser app? → Use `*_redirect` | API? → Use `*_401`

## Examples

See the complete working examples in the repository:

- [Basic Integration](https://github.com/ktaka-ccmp/oauth2-passkey/tree/master/demo01)
- [OAuth2 Demo](https://github.com/ktaka-ccmp/oauth2-passkey/tree/master/demo-oauth2)
- [Passkey Demo](https://github.com/ktaka-ccmp/oauth2-passkey/tree/master/demo-passkey)

## Core Library

This crate is built on top of [`oauth2-passkey`](https://crates.io/crates/oauth2-passkey). See that crate's documentation for core authentication concepts and advanced usage.

## License

Licensed under the MIT License. See [LICENSE](https://github.com/ktaka/oauth2-passkey/blob/main/LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](https://github.com/ktaka/oauth2-passkey/blob/main/CONTRIBUTING.md) for guidelines.
