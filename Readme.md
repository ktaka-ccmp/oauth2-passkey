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
    - [Delivering CSRF Token to the Client](#delivering-csrf-token-to-the-client)
      - [Via Extension](#via-extension)
      - [Via Dedicated Endpoint](#via-dedicated-endpoint)
      - [Via Header (automatic)](#via-header-automatic)
    - [Making a Request with CSRF Token](#making-a-request-with-csrf-token)
      - [JavaScript fetch (SPA/AJAX)](#javascript-fetch-spaajax)
      - [Traditional HTML form POST](#traditional-html-form-post)
    - [Verification](#verification)
      - [Automatic Verification via Header](#automatic-verification-via-header)
      - [Manual Verification](#manual-verification)
  - [Feature Flags](#feature-flags)
  - [Admin Privileges](#admin-privileges)

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

To protect against CSRF attacks, all state-changing endpoints must include CSRF token verification. This crate automatically generates CSRF tokens for this purpose.

- All state-changing endpoints must verify the CSRF token.
- The CSRF token is generated per session and must be included in state-changing requests, typically as an `X-CSRF-Token` header.
- Verification of the CSRF token is automatically handled by the extractor and middleware for state-changing requests.

### Delivering CSRF Token to the Client

#### Via Extension

Include the CSRF token in the page using a template engine after extracting it from the `AuthUser`.

```rust
// Handler: extract csrf_token and pass to template context
async fn handler(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    let csrf_token = user.csrf_token.clone();
    HtmlTemplate::render("my_template.j2", json!({
        "csrf_token": csrf_token,
        // ... other context ...
    }))
}
```

```html
<!-- In your template -->
<script>
    // Embed CSRF token as a JS variable
    const csrfToken = "{{ csrf_token }}";
</script>
<!-- Or as a hidden field in a form -->
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

---

#### Via Dedicated Endpoint

We also provide a dedicated endpoint `/o2p/user/csrf_token` that returns the CSRF token as JSON for the authenticated user.

```javascript
// JS: Fetch CSRF token from the dedicated endpoint (make sure to include credentials)
fetch('/o2p/user/csrf_token', { credentials: 'include' })
  .then(response => response.json())
  .then(data => {
    const csrfToken = data.csrf_token;
    // Use csrfToken in subsequent requests
  });
```

---

#### Via Header (automatic)

The middleware automatically adds the CSRF token to the response header as `X-CSRF-Token`.
The client can fetch the CSRF token from the response header by sending a HEAD request to the current URL.

```javascript
fetch(window.location.href, { method: 'HEAD', credentials: 'include' })
    .then(response => {
        const csrfToken = response.headers.get('X-CSRF-Token') || null;
        // Use csrfToken in subsequent requests
    });
```

---

### Making a Request with CSRF Token

All state-changing endpoints must verify the CSRF token.

The CSRF token is generated per session and must be included in state-changing requests, typically as an `X-CSRF-Token` header.

#### JavaScript fetch (SPA/AJAX)

```javascript
fetch('/some_end_point', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': 'your-csrf-token',
        // ...
    },
    // ...
});
```

#### Traditional HTML form POST

```html
<form method="POST" action="/some_end_point">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <!-- other fields -->
    <button type="submit">Submit</button>
</form>
```

---

### Verification

#### Automatic Verification via Header

CSRF token verification for state-changing requests (POST, PUT, DELETE, PATCH) works as follows, whether using the Axum middleware or `AuthUser` extractor directly:

**1. `X-CSRF-Token` Header Present:**

- The header token is compared to the session token.
- **Match:** `AuthUser.csrf_via_header_verified` becomes `true`. Request proceeds.
- **Mismatch:** Request is rejected (FORBIDDEN).

**2. `X-CSRF-Token` Header Absent:**

- `AuthUser.csrf_via_header_verified` is `false`.
- The request's `Content-Type` is then checked:
- **Form submissions** (`application/x-www-form-urlencoded`, `multipart/form-data`):
- The request proceeds to your handler.
- **Handler MUST manually verify** the CSRF token from the form body against `AuthUser.csrf_token`. Reject if mismatched.
- **Other `Content-Type`s** (e.g., `application/json`) or if `Content-Type` is missing:
- Request is rejected (FORBIDDEN). This protects AJAX/API endpoints that submit non-form data without the `X-CSRF-Token` header.

This dual approach ensures header-based CSRF (common for SPAs/AJAX) is handled automatically, while traditional forms require explicit verification in your handler.

#### Manual Verification

For traditional HTML form submissions (where the `X-CSRF-Token` header is typically absent), your request handler **must** manually verify the CSRF token that was submitted in the form body.

```rust
//if csrf verification in header failed
if !auth_user.csrf_via_header_verified {
    // compare csrf token in the form with the one in the session cache
    if !form_data.csrf_token.as_bytes().ct_eq(auth_user.csrf_token.as_bytes()).into() {
        tracing::error!(
            "CSRF token mismatch (form field). Submitted: {}, Expected: {}",
            form_data.csrf_token,
            auth_user.csrf_token
        );
        return Err((StatusCode::FORBIDDEN, "Invalid CSRF token.".to_string()));
    }
    tracing::trace!("CSRF token via form field verified.");
}
```

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

---
