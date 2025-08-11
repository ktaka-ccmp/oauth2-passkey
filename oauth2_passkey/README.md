# oauth2-passkey

[![CI](https://github.com/ktaka-ccmp/oauth2-passkey/workflows/CI/badge.svg)](https://github.com/ktaka-ccmp/oauth2-passkey/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ktaka-ccmp/oauth2-passkey/branch/master/graph/badge.svg)](https://codecov.io/gh/ktaka-ccmp/oauth2-passkey)
[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey.svg)](https://crates.io/crates/oauth2-passkey)
[![Docs.rs](https://docs.rs/oauth2-passkey/badge.svg)](https://docs.rs/oauth2-passkey)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.1-blue)](https://blog.rust-lang.org/2024/11/21/Rust-1.85.0.html)

A framework-agnostic core library for OAuth2 and WebAuthn/passkey authentication in Rust applications.

This library provides the essential authentication logic and coordination functions that can be integrated into any Rust web framework. It handles complex authentication flows while leaving web framework integration to separate crates.

## Features

- **OAuth2 Support**: Google OAuth2/OIDC authentication with extensible provider system
- **WebAuthn/Passkey**: FIDO2-compliant passwordless authentication
- **Secure Session Management**: Redis and in-memory session storage with secure cookies
- **Flexible Storage**: SQLite and PostgreSQL database support
- **CSRF Protection**: Built-in protection against cross-site request forgery
- **Security-First Design**: Timing-attack resistant with cryptographically secure randomness

## Web Framework Integrations

This core library is designed to be used with framework-specific integration crates:

- **[`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum)** - Axum web framework integration
- **Other frameworks** - Additional integration crates can be built using this core library

**For most users**: Use the framework-specific integration crates rather than this core library directly.

## Core API

The library exposes coordination functions for authentication flows:

```rust
use oauth2_passkey::{
    init,
    handle_start_authentication_core,
    handle_finish_authentication_core,
    handle_start_registration_core,
    handle_finish_registration_core,
    prepare_oauth2_auth_request,
    is_authenticated_basic,
    get_user_from_session,
};

// Initialize the authentication system
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init().await?;

    // Use authentication functions in your web framework handlers
    // See "Building Framework Integrations" section below for examples
    Ok(())
}
```

For a complete list of all public functions, structs, and types, see the [full API documentation on docs.rs](https://docs.rs/oauth2-passkey).

## Configuration

Configure the library via environment variables:

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

# Optional: Server secret for token signing (32+ characters recommended)
AUTH_SERVER_SECRET=your_32_character_secret_key_here

# Optional: Session configuration
SESSION_COOKIE_NAME=__Host-SessionId
SESSION_COOKIE_MAX_AGE=600
```

## Architecture

The library is organized into modular components that work together:

- **`coordination`** - High-level authentication flow coordination functions
- **`oauth2`** - OAuth2 provider interactions and token handling
- **`passkey`** - WebAuthn/FIDO2 passkey operations and verification
- **`session`** - Session management, validation, and security
- **`userdb`** - User account storage and management
- **`storage`** - Database and cache abstractions with multiple backend support

## Building Framework Integrations

To integrate with a web framework, implement HTTP handlers that call the coordination functions:

```rust
use oauth2_passkey::{prepare_oauth2_auth_request, get_user_and_csrf_token_from_session, AuthUser};
use http::{HeaderMap, StatusCode};

// Example: OAuth2 authentication endpoint
async fn handle_oauth2_auth(headers: HeaderMap) -> Result<String, StatusCode> {
    let (auth_url, response_headers) = prepare_oauth2_auth_request(headers, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Framework integration should:
    // 1. Set response_headers on the HTTP response
    // 2. Redirect to auth_url
    Ok(auth_url)
}

// Example: Extract user from session cookie
async fn get_session_user(session_cookie: &str) -> Result<AuthUser, StatusCode> {
    let (session_user, csrf_token) = get_user_and_csrf_token_from_session(session_cookie)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Convert to framework-specific user type
    let mut auth_user = AuthUser::from(session_user);
    auth_user.csrf_token = csrf_token.as_str().to_string();
    Ok(auth_user)
}
```

**Complete Example**: See the [`oauth2-passkey-axum`](../oauth2_passkey_axum) source code for a full framework integration implementation.

## Security Features

- **Secure cookie implementation** with `Secure`, `HttpOnly`, `SameSite=Lax` attributes and `__Host-` prefix
- **Constant-time CSRF comparison** using `subtle::ConstantTimeEq` to prevent timing attacks
- **Cryptographically secure randomness** via `ring::rand::SystemRandom` for session IDs and tokens
- **CSRF protection** with secure token generation and validation
- **Session timeout management** with configurable expiration
- **Host-locked cookies** using `__Host-SessionId` prefix for enhanced security

**Note**: For a comprehensive security analysis and verification status of all claims, see [Security Documentation](../docs/security.md).

## License

Licensed under either of

- [Apache License, Version 2.0](../LICENSE-APACHE)
- [MIT License](../LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
