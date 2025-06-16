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
use oauth2_passkey_axum::{oauth2_passkey_router, init, AuthConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication
    let config = AuthConfig::from_env()?;
    let auth_context = init(config).await?;

    // Create your application router
    let app = Router::new()
        .route("/", axum::routing::get(|| async { Html("Hello World!") }))
        // Add authentication routes
        .nest("/auth", oauth2_passkey_router(auth_context))
        .layer(/* your middleware */);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Route Protection

Protect your routes with authentication middleware:

```rust
use oauth2_passkey_axum::{is_authenticated_redirect, AuthUser};
use axum::{routing::get, Router, response::Html};

async fn protected_handler(user: AuthUser) -> Html<String> {
    Html(format!("Hello, {}! You are authenticated.", user.email))
}

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(axum::middleware::from_fn(is_authenticated_redirect));
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
# Database
DATABASE_URL=sqlite:data/auth.db

# Cache
REDIS_URL=redis://localhost:6379

# OAuth2 providers
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Session security
SESSION_SECRET=your_32_character_secret_key_here

# Application URLs
BASE_URL=https://yourdomain.com
REDIRECT_URL_ANON=https://yourdomain.com/
```

## Available Routes

When you include the authentication router, these routes are available:

- `GET /auth/login` - Login page
- `POST /auth/oauth2/{provider}` - OAuth2 authentication
- `GET /auth/oauth2/callback` - OAuth2 callback
- `GET /auth/passkey/register` - Passkey registration
- `POST /auth/passkey/register` - Complete passkey registration
- `GET /auth/passkey/authenticate` - Passkey authentication
- `POST /auth/passkey/authenticate` - Complete passkey authentication
- `POST /auth/logout` - User logout
- `GET /auth/admin` - Admin interface (if `admin-ui` feature enabled)

## Middleware Functions

- `is_authenticated_redirect` - Redirect to login if not authenticated
- `is_authenticated_401` - Return 401 if not authenticated
- `is_authenticated_user_redirect` - Redirect regular users (admin-only routes)
- `is_authenticated_user_401` - Return 401 for regular users

## Examples

See the complete working examples in the repository:

- [Basic Integration](https://github.com/ktaka/oauth2-passkey/tree/main/demo01)
- [OAuth2 Demo](https://github.com/ktaka/oauth2-passkey/tree/main/demo-oauth2)
- [Passkey Demo](https://github.com/ktaka/oauth2-passkey/tree/main/demo-passkey)

## Core Library

This crate is built on top of [`oauth2-passkey`](https://crates.io/crates/oauth2-passkey). See that crate's documentation for core authentication concepts and advanced usage.

## License

Licensed under the MIT License. See [LICENSE](https://github.com/ktaka/oauth2-passkey/blob/main/LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](https://github.com/ktaka/oauth2-passkey/blob/main/CONTRIBUTING.md) for guidelines.
