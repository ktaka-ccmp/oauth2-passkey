# oauth2-passkey

🔐 **Drop-in authentication for Rust web apps** - Add secure login with Google OAuth2 and/or Passkeys in minutes.

[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey.svg)](https://crates.io/crates/oauth2-passkey)
[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey-axum.svg)](https://crates.io/crates/oauth2-passkey-axum)
[![Docs.rs](https://docs.rs/oauth2-passkey/badge.svg)](https://docs.rs/oauth2-passkey)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## ✨ What You Get

Users authenticate with OAuth2 or Passkey, then receive a secure session cookie to maintain their login status.

- 🌐 **"Sign in with Google"** OAuth2/OIDC authentication that just works
- 🔑 **Passwordless login** WebAuthn/Passkey support for modern devices
- 🔗 **Account linking** Users can add multiple login methods to one account
- 🛡️ **Security built-in** Sessions, CSRF protection, secure cookies
- 📦 **Minimal setup** Works with SQLite out of the box, scales to PostgreSQL + Redis

## 🚀 5-Minute Setup

**1. Add to your `Cargo.toml`:**

```toml
[dependencies]
oauth2-passkey-axum = "0.1"
```

**2. Set your environment variables:**

```bash
ORIGIN='https://your-domain.com'
OAUTH2_GOOGLE_CLIENT_ID='your-google-client-id'
OAUTH2_GOOGLE_CLIENT_SECRET='your-google-secret'
```

**3. Add to your Axum app:**

```rust
use axum::{Router, routing::get, response::IntoResponse};
use oauth2_passkey_axum::{AuthUser, oauth2_passkey_router, O2P_ROUTE_PREFIX};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(home))
        .route("/protected", get(protected))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // Your app is now ready with login/logout at /o2p/*
    Ok(())
}

async fn home() -> &'static str {
    "Welcome! Visit /o2p/user/login to sign in"
}

async fn protected(user: AuthUser) -> impl IntoResponse {
    format!("Hello, {}! 👋", user.account)
}
```

**That's it!** Your users can now sign-in/register with Google or Passkeys.

## 🏗️ How It Works

**Simple Architecture:**

```text
Your Web App
     ↓
oauth2-passkey-axum  ← Handles login/logout routes
     ↓
oauth2-passkey       ← Core session & auth logic
     ↓
Database + Cache     ← SQLite/PostgreSQL + Memory/Redis
```

**User Experience:**

1. **First-time users** can register with Google OAuth2 OR create a Passkey
2. **Existing users** can add additional login methods to their account
3. **Authentication** works with any linked method (OAuth2 or Passkey)
4. **Admin users** (first user auto-promoted) can manage other accounts

## 📱 Try the Demos

See it in action before integrating:

- **[Complete Demo](demo-both/)** - Both OAuth2 and Passkey authentication
- **[OAuth2 Only](demo-oauth2/)** - "Sign in with Google" focus
- **[Passkey Only](demo-passkey/)** - Passwordless authentication focus

```bash
# Copy demo configuration
cp dot.env.simple demo-both/.env

# Run the demo (includes both OAuth2 and Passkeys)
cd demo-both && cargo run

# Open in your browser:
# Visit https://localhost:3443
```

## 📦 Repository Structure

This repository contains:

- **[`oauth2_passkey/`](oauth2_passkey/)** - Core authentication library
- **[`oauth2_passkey_axum/`](oauth2_passkey_axum/)** - Axum web framework integration
- **[`demo-both/`](demo-both/)** - Complete integration example
- **[`demo-oauth2/`](demo-oauth2/)** - OAuth2-focused example
- **[`demo-passkey/`](demo-passkey/)** - Passkey-focused example
- **[`db`](db/)** - Database configuration example

## 🔧 Configuration

**Environment Variables** (create a `.env` file):

```env
ORIGIN='https://your-domain.com'
OAUTH2_GOOGLE_CLIENT_ID='your-google-client-id'
OAUTH2_GOOGLE_CLIENT_SECRET='your-google-secret'

# Database (SQLite by default, PostgreSQL for production)
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:data/auth.db'

# Cache (Memory by default, Redis for production)
GENERIC_CACHE_STORE_TYPE=memory
```

**OAuth2 Setup:** Get credentials from [Google API Console](https://console.cloud.google.com/auth/clients) and add redirect URI: `https://your-domain.com/o2p/oauth2/authorized`

## 🎯 Why Choose This Library?

- ✅ **Beginner-friendly** - Works out of the box with SQLite
- ✅ **Production-ready** - Scales to PostgreSQL + Redis
- ✅ **Modern auth methods** - OAuth2 + Passkeys in one package
- ✅ **Security built-in** - CSRF, secure sessions, minimal dependencies
- ✅ **Flexible** - Users can mix and match auth methods

## 📄 License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
