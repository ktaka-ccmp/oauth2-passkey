# oauth2-passkey

A minimal-dependency, security-focused authentication library for Rust web applications supporting both OAuth2 and WebAuthn/Passkey authentication.

**Key Features:**

- 🔐 Secure session management with automatic cookie handling
- 🌐 OAuth2 authentication (Google OAuth2/OIDC support)
- 🔑 WebAuthn/Passkey authentication (FIDO2 compliant)
- 🛡️ Built-in CSRF protection and secure session handling
- 📦 Minimal dependencies for reduced attack surface

## 📦 Crates

This repository contains two published crates:

- **[`oauth2-passkey`](https://crates.io/crates/oauth2-passkey)** - Core authentication library
- **[`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum)** - Axum web framework integration

[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey.svg)](https://crates.io/crates/oauth2-passkey)
[![Crates.io](https://img.shields.io/crates/v/oauth2-passkey-axum.svg)](https://crates.io/crates/oauth2-passkey-axum)
[![Docs.rs](https://docs.rs/oauth2-passkey/badge.svg)](https://docs.rs/oauth2-passkey)
[![Docs.rs](https://docs.rs/oauth2-passkey-axum/badge.svg)](https://docs.rs/oauth2-passkey-axum)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

## Table of Contents

- [oauth2-passkey](#oauth2-passkey)
  - [📦 Crates](#-crates)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Basic Usage](#basic-usage)
    - [Prepare database and cache](#prepare-database-and-cache)
      - [Database](#database)
        - [SQLite](#sqlite)
        - [PostgreSQL](#postgresql)
      - [Cache](#cache)
        - [Memory](#memory)
        - [Redis](#redis)
    - [.env file](#env-file)
      - [Important Notes](#important-notes)
    - [Rust Code Example](#rust-code-example)
  - [Route Protection](#route-protection)
    - [Axum Extractor](#axum-extractor)
    - [Middleware](#middleware)
  - [CSRF Protection](#csrf-protection)
    - [Getting CSRF Tokens](#getting-csrf-tokens)
      - [✅ Server-Side Templates (Most Common)](#-server-side-templates-most-common)
      - [🔄 API Endpoint (For SPAs)](#-api-endpoint-for-spas)
      - [⚡ Response Headers (Advanced)](#-response-headers-advanced)
    - [Making Requests with CSRF Tokens](#making-requests-with-csrf-tokens)
      - [✅ Using Headers (Recommended - Automatic Verification)](#-using-headers-recommended---automatic-verification)
      - [⚠️ Using Form Fields (Manual Verification Required)](#️-using-form-fields-manual-verification-required)
    - [Verification](#verification)
      - [✅ Header Tokens: Automatic Verification](#-header-tokens-automatic-verification)
      - [⚠️ Form Tokens: Manual Verification Required](#️-form-tokens-manual-verification-required)
  - [Feature Flags](#feature-flags)
  - [Admin Privileges](#admin-privileges)
  - [License](#license)
    - [Contribution](#contribution)
  - [Contributing](#contributing)

---

## Getting Started

1. **Add to your `Cargo.toml`:**

   ```toml
   oauth2_passkey_axum = "..."
   ```

2. **Prepare your `.env` and database/cache (see below).**
3. **Integrate the router and middleware into your Axum app.**

---

## Basic Usage

### Prepare database and cache

**Supported Storage Options:**

- **Database:** SQLite and PostgreSQL
- **Cache:** In-memory HashMap and Redis

#### Database

##### SQLite

Make sure the database URL you specified is writable.

##### PostgreSQL

```bash
docker compose -f db/postgresql/docker-compose.yaml up -d
```

#### Cache

##### Memory

No preparation needed.

##### Redis

```bash
docker compose -f db/redis/docker-compose.yaml up -d
```

### .env file

```toml
ORIGIN='https://your-domain.example.com'

OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'

GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://localhost:6379'

GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:///tmp/sqlite.db'
```

#### Important Notes

**ORIGIN Configuration:**

- Must not have a trailing slash
- Must use `https://` (OAuth2 and WebAuthn require HTTPS)
- Should be the externally accessible URL (even if using an SSL proxy)

**Google OAuth2 Setup:**

1. Get your client credentials from the [Google API Console](https://console.cloud.google.com/auth/clients)
2. Add the authorized redirect URI: `$ORIGIN/o2p/oauth2/authorized`
   - Example: If `ORIGIN='https://example.com'`, add `https://example.com/o2p/oauth2/authorized`

### Rust Code Example

```rust
use oauth2_passkey_axum::{
    AuthUser, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, O2P_SUMMARY_URL, oauth2_passkey_router,
};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    oauth2_passkey_axum::init().await.expect("init failed");

    let app = Router::new()
        .route("/", get(index))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
        .merge(protected::router());
}
```

The `init()` call initializes database storage and cache connections. The `oauth2_passkey_router()` provides all authentication endpoints for OAuth2/OIDC and WebAuthn/Passkey flows.

---

## Route Protection

Authenticated user pages are protected using either the Axum extractor or middleware approach.

### Axum Extractor

- Protect routes by requiring `AuthUser` as an argument.
- The extractor validates the session.
- The extractor also validates the CSRF token for state-changing requests.

```rust
async fn protected_handler(user: AuthUser) {
    let csrf_token = user.csrf_token;
}
```

### Middleware

- Use `is_authenticated` middleware to protect routes.
- The middleware validates the session.
- The middleware also validates the CSRF token for state-changing requests.

```rust
router.route("/protected", get(protected_handler).layer(is_authenticated()));
```

## CSRF Protection

This crate provides automatic CSRF protection with two usage patterns:

1. **✅ Headers (Recommended)**: Get token → include in `X-CSRF-Token` header → automatic verification
2. **⚠️ Forms**: Get token → include in form field → manual verification required

**Your responsibility:** Get tokens to your frontend and include them in requests.

### Getting CSRF Tokens

Choose the method that best fits your application:

#### ✅ Server-Side Templates (Most Common)

**Best for:** Traditional web apps, server-side rendering

```rust
// Pass token to your template
async fn page_handler(user: AuthUser) -> impl IntoResponse {
    HtmlTemplate::render("page.j2", json!({
        "csrf_token": user.csrf_token,
        // ... other data
    }))
}
```

**In your template:**
```html
<!-- For JavaScript/AJAX -->
<script>window.csrfToken = "{{ csrf_token }}";</script>

<!-- For forms -->
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

#### 🔄 API Endpoint (For SPAs)

**Best for:** Single-page applications, dynamic token refresh

```javascript
// Fetch fresh token when needed
const response = await fetch('/o2p/user/csrf_token', { 
    credentials: 'include' 
});
const { csrf_token } = await response.json();
```

#### ⚡ Response Headers (Advanced)

**Best for:** Existing authenticated requests (token included automatically)

```javascript
// Token available in any authenticated response
const response = await fetch('/api/user-data', { credentials: 'include' });
const csrfToken = response.headers.get('X-CSRF-Token');
// Use token for subsequent requests
```

---

### Making Requests with CSRF Tokens

#### ✅ Using Headers (Recommended - Automatic Verification)

**Best for:** AJAX, fetch requests, SPAs

```javascript
// Get token from any method above, then include in header
fetch('/api/update-profile', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
    },
    credentials: 'include',
    body: JSON.stringify({ name: 'New Name' })
});
```

**✅ Verification is automatic** - no additional code needed in your handlers.

#### ⚠️ Using Form Fields (Manual Verification Required)

**Best for:** Traditional HTML form submissions

```html
<form method="POST" action="/update-profile">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="name" placeholder="Your name">
    <button type="submit">Update Profile</button>
</form>
```

**⚠️ Manual verification required** - see verification code below.

---

### Verification

#### ✅ Header Tokens: Automatic Verification

When using `X-CSRF-Token` header:
- **Works with both** `AuthUser` extractor and `is_authenticated()` middleware
- **Automatic comparison** - token verified against session automatically  
- **Success:** Request proceeds (`AuthUser.csrf_via_header_verified` = `true`)
- **Failure:** Request rejected with 403 FORBIDDEN

**No code needed** - verification happens automatically.

#### ⚠️ Form Tokens: Manual Verification Required

HTML forms cannot include custom headers, so the `X-CSRF-Token` header won't be present. **You must verify the form token manually:**

```rust
// In your handler - check if manual verification is needed
if !auth_user.csrf_via_header_verified {
    // Verify form token manually
    if !form_data.csrf_token.as_bytes().ct_eq(auth_user.csrf_token.as_bytes()).into() {
        return Err((StatusCode::FORBIDDEN, "Invalid CSRF token"));
    }
}
// Token verified - proceed with handler logic
```

---

## Feature Flags

The `oauth2_passkey_axum` crate provides supplemental UI components for both admin and regular users.

- **Default features:**  
  Both admin and user UIs are enabled by default.

- **To disable all UIs:**

```toml
oauth2_passkey_axum = { default-features = false, features = [] }
```

- **To enable only user UI:**

```toml
oauth2_passkey_axum = { default-features = false, features = ["user-ui"] }
```

---

## Admin Privileges

The library includes a built-in admin system for user management and system administration.

**Admin Initialization:**

- The first user to register is automatically granted admin privileges
- This ensures there's always at least one admin to manage the system

**Admin Capabilities:**

- Grant admin privileges to other users
- Access admin-only UI components (when enabled)
- Manage user accounts and permissions

**Admin UI Access:**

Admin users can access additional management interfaces at `/o2p/admin/` when the admin UI feature is enabled.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
