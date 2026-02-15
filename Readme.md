# <img src="assets/o2p_logo_tight.svg" alt="logo" height="60">oauth2-passkey

🔐 **Passwordless authentication for Rust web apps** - No passwords, no 2FA implementation, better security.

[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey.svg)](https://crates.io/crates/oauth2-passkey)
[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey-axum.svg)](https://crates.io/crates/oauth2-passkey-axum)
[![Docs.rs](https://docs.rs/oauth2-passkey/badge.svg)](https://docs.rs/oauth2-passkey)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Password authentication is fundamentally flawed** - even strong, unique passwords are vulnerable to phishing, brute-force attacks, and server-side breaches. This library provides a better approach: users register with Google OAuth2, then add a Passkey for fast, phishing-resistant daily login. OAuth2 remains as a backup if the device is lost. After authentication, the library issues a secure session cookie to maintain login state.

## 🎮 Live Demo

> **[passkey-demo.ccmp.jp](https://passkey-demo.ccmp.jp)**

No setup required. Google account needed for OAuth2. Data is ephemeral (resets on server restart, sessions expire in 10 min).

## ✨ What You Get

- 🔑 **Passkey** - Phishing-resistant login with biometrics, inherently multi-factor (no 2FA needed)
- 🌐 **Google OAuth2** - One-click registration and backup authentication
- 🔗 **Account linking** - Users can add multiple login methods to one account
- 📦 **Minimal setup** - Works with SQLite out of the box, scales to PostgreSQL + Redis

## 🚀 5-Minute Setup

**1. Add to your `Cargo.toml`:**

```toml
[dependencies]
oauth2-passkey-axum = "0.2"
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
use oauth2_passkey_axum::{AuthUser, oauth2_passkey_full_router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(home))
        .route("/protected", get(protected))
        .merge(oauth2_passkey_full_router());

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

| Demo | Description |
|------|-------------|
| **[demo-both](demo-both/)** | Complete OAuth2 + Passkey authentication |
| **[demo-oauth2](demo-oauth2/)** | OAuth2 only ("Sign in with Google") |
| **[demo-passkey](demo-passkey/)** | Passkey only (passwordless) |
| **[demo-custom-login](demo-custom-login/)** | Custom login page implementation |
| **[demo-profile](demo-profile/)** | User profile extension |
| **[demo-todo](demo-todo/)** | App data linked to users |
| **[demo-cross-origin](demo-cross-origin/)** | Cross-origin authentication setup |

```bash
# Copy demo configuration
cp dot.env.simple demo-both/.env

# Run the demo (includes both OAuth2 and Passkeys)
cd demo-both && cargo run

# Open in your browser:
# Visit http://localhost:3001
```

## 📦 Repository Structure

This repository contains:

- **[`oauth2_passkey/`](oauth2_passkey/)** - Core authentication library
- **[`oauth2_passkey_axum/`](oauth2_passkey_axum/)** - Axum web framework integration
- **[`demo-*/`](.)** - 7 demo applications (see table above)
- **[`docs/`](docs/)** - Documentation (mdBook format) | [Read online](https://ktaka-ccmp.github.io/oauth2-passkey/)
- **[`db/`](db/)** - Database configuration (Docker Compose)

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

## 📄 License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
