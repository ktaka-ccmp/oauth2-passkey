# oauth2-passkey

[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey.svg)](https://crates.io/crates/oauth2-passkey)
[![Docs.rs](https://docs.rs/oauth2-passkey/badge.svg)](https://docs.rs/oauth2-passkey)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A minimal-dependency, security-focused core library for OAuth2 and passkey authentication in Rust web applications.

This is the core library that provides the authentication logic and coordination between OAuth2 providers and WebAuthn/passkey authentication. For Axum web framework integration, see [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum).

## Features

- **OAuth2 Authentication**: Support for multiple OAuth2 providers
- **Passkey/WebAuthn**: Modern passwordless authentication
- **Session Management**: Secure session handling with Redis/in-memory cache
- **User Database**: Flexible user storage with SQLite/PostgreSQL support
- **Security-First**: Timing-attack resistant, minimal dependencies
- **Async/Await**: Full async support with tokio

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
oauth2-passkey = "0.1"
```

## Basic Usage

```rust
use oauth2_passkey::{init, AuthConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the authentication system
    let config = AuthConfig::from_env()?;
    let auth_context = init(config).await?;

    // Use auth_context for authentication operations
    Ok(())
}
```

## Configuration

The library uses environment variables for configuration. Create a `.env` file:

```env
# Database
DATABASE_URL=sqlite:data/auth.db
# Or: DATABASE_URL=postgresql://user:pass@localhost/auth_db

# Cache (Redis recommended for production)
REDIS_URL=redis://localhost:6379
# Or use in-memory cache for development

# OAuth2 providers
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Session security
SESSION_SECRET=your_32_character_secret_key_here
```

## Architecture

This library provides the core authentication logic and coordinates between:

- **OAuth2 Module**: Handles OAuth2 provider interactions
- **Passkey Module**: WebAuthn/FIDO2 passkey authentication
- **Session Module**: Secure session management
- **User Database**: User account storage and management
- **Storage Module**: Caching and temporary data storage

## Web Framework Integration

This core library is framework-agnostic. For web framework integration:

- **Axum**: Use [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum)
- **Other frameworks**: Implement handlers using the core authentication functions

## Security Features

- **Constant-time operations** for sensitive comparisons
- **CSRF protection** with secure token generation
- **Session security** with secure random session IDs
- **Timing attack resistance** in authentication flows
- **Memory safety** with secure credential handling

## Examples

See the [demo applications](https://github.com/ktaka/oauth2-passkey/tree/main/demo01) in the repository for complete working examples.

## License

Licensed under the MIT License. See [LICENSE](https://github.com/ktaka/oauth2-passkey/blob/main/LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](https://github.com/ktaka/oauth2-passkey/blob/main/CONTRIBUTING.md) for guidelines.
