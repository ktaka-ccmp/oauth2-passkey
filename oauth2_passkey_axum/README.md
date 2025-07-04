# oauth2-passkey-axum

[![CI](https://github.com/ktaka-ccmp/oauth2-passkey/workflows/CI/badge.svg)](https://github.com/ktaka-ccmp/oauth2-passkey/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ktaka-ccmp/oauth2-passkey/branch/main/graph/badge.svg)](https://codecov.io/gh/ktaka-ccmp/oauth2-passkey)
[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey-axum.svg)](https://crates.io/crates/oauth2-passkey-axum)
[![Docs.rs](https://docs.rs/oauth2-passkey-axum/badge.svg)](https://docs.rs/oauth2-passkey-axum)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.1-blue)](https://blog.rust-lang.org/2024/11/21/Rust-1.85.0.html)

Axum web framework integration for the [`oauth2-passkey`](../oauth2_passkey) authentication library.

This crate provides ready-to-use Axum handlers, middleware, and UI components for OAuth2 and passkey authentication in your Axum web applications.

## Requirements

- **Minimum Supported Rust Version (MSRV)**: 1.85.1
- **Supported Platforms**: Linux, macOS, Windows (x86_64, ARM64)
- **Dependencies**: Built on stable Rust with minimal dependency tree

## Features

- **Drop-in Axum Integration**: Pre-built routers and middleware
- **Admin UI**: Optional admin interface for user management
- **User UI**: Authentication pages and flows
- **Route Protection**: Middleware for protecting routes
- **CSRF Protection**: Built-in CSRF token handling
- **Static Assets**: CSS and JavaScript for authentication UI

## Getting Started

Try out demo to get familiarize yourself with the usage of the library.

- [Complete Integration](../demo-both)
- [OAuth2 Demo](../demo-oauth2)
- [Passkey Demo](../demo-passkey)

## Basic Usage

### Prepare Cargo.toml

Add to your `Cargo.toml`:

```toml
[dependencies]
oauth2-passkey-axum = "0.1"
```

### Prepare .env

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
```

See [dot.env.example](../dot.env.example) for available options.

### Prepare Endpoints

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

### Route Protection

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

## Available Routes

When you include `oauth2_passkey_router()`, all authentication endpoints are available under `/o2p` by default.
You can change this prefix by setting the `O2P_ROUTE_PREFIX` environment variable.

### Core Authentication

**OAuth2:**
- `GET /o2p/oauth2/google` - Start Google OAuth2 login
- `GET|POST /o2p/oauth2/authorized` - OAuth2 callback handler

**Passkey:**
- `POST /o2p/passkey/register/start` - Begin passkey registration
- `POST /o2p/passkey/register/finish` - Complete registration
- `POST /o2p/passkey/auth/start` - Begin passkey authentication
- `POST /o2p/passkey/auth/finish` - Complete authentication

**Session Management:**
- `GET /o2p/user/info` - Get current user data (JSON)
- `GET /o2p/user/csrf_token` - Get CSRF token
- `GET /o2p/user/logout` - End user session

### UI Components

**User Interface** (requires `user-ui` feature):
- `GET /o2p/ui/login` - Login page
- `GET /o2p/ui/summary` - User dashboard

**Admin Interface** (requires `admin-ui` feature):
- `GET /o2p/admin/list_users` - User management (admin only)
- `GET /o2p/admin/user/{user_id}` - User details (admin only)

### Management Endpoints

**User Account:**
- `PUT /o2p/user/update` - Update user account
- `DELETE /o2p/user/delete` - Delete own account

**Credentials:**
- `GET /o2p/passkey/credentials` - List passkey credentials
- `GET /o2p/oauth2/accounts` - List OAuth2 accounts
- `DELETE /o2p/passkey/credentials/{id}` - Remove passkey
- `DELETE /o2p/oauth2/accounts/{provider}/{id}` - Remove OAuth2 account

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

`*_user_*` variants example:

When you use a `*_user_*` middleware, the authenticated user is injected as an `Extension<AuthUser>`. You can then access user info in your handler like this:

```rust
use axum::{
    Extension,
    response::{Html, IntoResponse},
};
use oauth2_passkey_axum::AuthUser;

async fn protected(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Html(format!("<h1>Hello, {}!</h1>", user.account))
}
```

This pattern is useful when you want both authentication enforcement and access to user data in your handler—such as for rendering templates or personalized responses.

## CSRF Protection

This library includes built-in CSRF protection for all authenticated routes. CSRF tokens are automatically:

- Generated for each user session
- Available via the `AuthUser` extractor (`user.csrf_token`)
- Accessible through the `/o2p/user/csrf_token` endpoint

**Basic Usage:**

```javascript
// Include in headers (automatically verified)
fetch('/api/protected', {
  method: 'POST',
  headers: {'X-CSRF-Token': csrfToken},
  credentials: 'include'
})
````

For detailed implementation guide including form-based CSRF and manual verification, see our [CSRF Protection Guide](../docs/csrf-protection.md).

## Core Library

This crate is built on top of [`oauth2-passkey`](../oauth2_passkey). See that crate's documentation for core authentication concepts and advanced usage.

## License

Licensed under either of

- [Apache License, Version 2.0](../LICENSE-APACHE)
- [MIT License](../LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
