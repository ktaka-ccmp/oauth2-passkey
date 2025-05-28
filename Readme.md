# oauth2_passkey

A minimal-dependency, security-focused library for adding OAuth2 and passkey authentication to Axum-based Rust web apps.

[![Crates.io](https://img.shields.io/crates/v/oauth2_passkey_axum.svg)](https://crates.io/crates/oauth2_passkey_axum)
[![Docs.rs](https://docs.rs/oauth2_passkey_axum/badge.svg)](https://docs.rs/oauth2_passkey_axum)

---

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Usage](#basic-usage)
  - [Prepare Database and Cache](#prepare-database-and-cache)
  - [.env File](#env-file)
  - [Rust Code Example](#rust-code-example)
- [Feature Flags](#feature-flags)
- [Admin Privileges](#admin-privileges)
- [Route Protection & CSRF](#route-protection--csrf)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)
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

## Basic usage

### Prepare database and cache

#### Database

##### sqlite:

Make sure db url you specified is writable.

##### Postgres:

```bash
docker compose -f db/postgresql/docker-compose.yaml up -d
```

#### Cache

##### Memory:

No preparation needed.

##### Redis:

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

Note:
- ORIGIN should not have trailing slash
- ORIGIN should be https, otherwise OAuth2 and Passkey will not work
- You can have a SSL proxy in front of your app, but the ORIGIN should be the one that is accessible from the outside and should have the https:// prefix.

- You can get OAuth2 client ID and secret from [Google API Console](https://console.cloud.google.com/auth/clients).
- You should place `$ORIGIN/o2p/oauth2/authorized` as a Authorized redirect URI in the Google. For example if the ORIGIN is `https://example.com` then place `https://example.com/o2p/oauth2/` there.


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
---

## Feature Flags

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

- The first registered user is always an admin.
- Admins can grant admin privileges to other users.

---

## Route Protection

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

- All state-changing endpoints must verify the CSRF token.
- The CSRF token is generated per session and must be included in state-changing requests, typically as an `X-CSRF-Token` header.
- Verification of the CSRF token is automatically handled by the extractor and middleware for state-changing requests.

### Delivering CSRF Token to the Client

- **Via Extension:**
Include the csrf_token in the page using the template engine etc. after extracting it from the AuthUser.

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

```javascript
// JS fetch example
fetch('/some_end_point', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ /* your data here */ })
});
```

---

- **Via Dedicated Endpoint:**
For single-page applications or API clients, provide a dedicated endpoint (e.g., `/api/csrf-token`) that returns the CSRF token as JSON. 

```rust
// Example Axum handler for /api/csrf-token
use axum::{extract::Extension, Json};
use serde::Serialize;

#[derive(Serialize)]
struct CsrfTokenResponse {
    csrf_token: String,
}

async fn csrf_token_endpoint(Extension(user): Extension<AuthUser>) -> Json<CsrfTokenResponse> {
    Json(CsrfTokenResponse {
        csrf_token: user.csrf_token.clone(),
    })
}

// Route registration:
// router.route("/api/csrf-token", get(csrf_token_endpoint).layer(is_authenticated()));
```

```javascript
// JS: Fetch CSRF token from the dedicated endpoint (make sure to include credentials)
fetch('/api/csrf-token', { credentials: 'include' })
  .then(response => response.json())
  .then(data => {
    const csrfToken = data.csrf_token;
    // Use csrfToken in subsequent requests
  });
```

- **Via Header (automatic):**
  The middleware can automatically add the CSRF token to the response header as `X-CSRF-Token`.
The client can fetch the CSRF token from the response header by sending a HEAD request to the current URL.

```javascript
fetch(window.location.href, { method: 'HEAD', credentials: 'include' })
    .then(response => {
        const csrfToken = response.headers.get('X-CSRF-Token') || null;
        // ...
    });
```

---

## Security Model

- All state-changing endpoints must verify the CSRF token.
- The CSRF token is generated per session and must be included in state-changing requests, typically as an `X-CSRF-Token` header.

**Examples: State-changing requests with CSRF token**

<details>
<summary>JavaScript fetch (SPA/AJAX)</summary>

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
</details>

<details>
<summary>Traditional HTML form POST</summary>

```html
<form method="POST" action="/some_end_point">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <!-- other fields -->
    <button type="submit">Submit</button>
</form>
```
</details>

The validity of the CSRF token is checked automatically by either the Axum extractor or middleware, depending on your route setup.

---
