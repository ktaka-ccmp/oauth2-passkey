# CSRF Token Handling

State-changing requests (POST, PUT, DELETE, PATCH) require a valid CSRF token. This guide explains how to implement CSRF protection for your custom pages.

## Overview

### Token Acquisition

| Client Type | Embedding | Response Header | Endpoint |
|-------------|-----------|-----------------|----------|
| JavaScript  | Optional  | Available       | Available |
| HTML Form   | Required  | Not available   | Not available |

JavaScript clients can use response headers, the endpoint, or embedded values. HTML Forms must embed tokens at render time.

### Token Usage

| Client Type | Token Location | Verification |
|-------------|----------------|--------------|
| JavaScript  | `X-CSRF-Token` header | Automatic (middleware) |
| HTML Form   | Hidden field in body | Manual (your handler) |

Middleware can read headers but not the body, so form tokens require manual verification.

## JavaScript (Automatic Verification)

### 1. Get the Token

**Option A: Embed in template** from `AuthUser.csrf_token`:

```html
<script>
    const csrfToken = '{{ csrf_token }}';
</script>
```

**Option B: Read from response header** of any authenticated request:

```javascript
const csrfToken = response.headers.get('X-CSRF-Token');
```

**Option C: Fetch from endpoint**:

```javascript
const response = await fetch(`${O2P_ROUTE_PREFIX}/user/csrf_token`, {
    credentials: 'include'
});
const { csrf_token: csrfToken } = await response.json();
```

### 2. Include in Requests

Add `X-CSRF-Token` header to all state-changing requests:

```javascript
fetch(`${O2P_ROUTE_PREFIX}/user/update`, {
    method: 'PUT',
    headers: {
        'X-CSRF-Token': csrfToken,
        'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify({ user_id, account, label })
});
```

**That's it!** The middleware verifies the token automatically. No handler code needed.

---

## HTML Form (Manual Verification)

### Step 1: Get Token and Embed in Form

**Handler (GET):**

```rust,ignore
use askama::Template;
use axum::{Extension, response::{Html, IntoResponse}};
use oauth2_passkey_axum::CsrfToken;

#[derive(Template)]
#[template(path = "form.j2")]
struct FormTemplate<'a> {
    csrf_token: &'a str,
}

pub async fn form_page(Extension(csrf_token): Extension<CsrfToken>) -> impl IntoResponse {
    let template = FormTemplate { csrf_token: csrf_token.as_str() };
    Html(template.render().unwrap())
}
```

**Template (form.j2):**

```html
<form method="POST" action="/submit">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="message">
    <button type="submit">Submit</button>
</form>
```

### Step 2: Define Form Data Structure

```rust,ignore
use serde::Deserialize;

#[derive(Deserialize)]
pub struct FormData {
    message: String,
    csrf_token: String,
}
```

### Step 3: Verify Token in Handler

```rust,ignore
use axum::{Extension, extract::Form, response::{Html, IntoResponse}, http::StatusCode};
use oauth2_passkey_axum::{CsrfToken, CsrfHeaderVerified};
use subtle::ConstantTimeEq;

pub async fn form_post(
    Extension(csrf_token): Extension<CsrfToken>,
    Extension(csrf_header_verified): Extension<CsrfHeaderVerified>,
    Form(data): Form<FormData>,
) -> impl IntoResponse {
    // Skip if already verified via header (AJAX request)
    if !csrf_header_verified.0 {
        // Verify form token with constant-time comparison
        if !data.csrf_token.as_bytes().ct_eq(csrf_token.as_str().as_bytes()).into() {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
    }

    Html(format!("Success: {}", data.message)).into_response()
}
```

### Step 4: Register Routes

```rust,ignore
use axum::{Router, routing::get, middleware::from_fn};
use oauth2_passkey_axum::is_authenticated_redirect;

let app = Router::new()
    .route("/form", get(form_page).post(form_post))
    .route_layer(from_fn(is_authenticated_redirect));
```

---

## Key Points

- **JavaScript**: Include `X-CSRF-Token` header → automatic verification
- **HTML Form**: Embed token in hidden field → verify manually with `subtle::ConstantTimeEq`
- Always use constant-time comparison (`ct_eq`) - never `==`
- Add `subtle` to your `Cargo.toml`: `subtle = "2"`

For security best practices and troubleshooting, see [CSRF Protection Guide](../security/csrf.md).
