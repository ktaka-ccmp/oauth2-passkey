# CSRF Protection Guide

This guide covers comprehensive CSRF (Cross-Site Request Forgery) protection implementation in oauth2-passkey applications.

## Overview

This library provides automatic CSRF protection with two usage patterns:

1. **Headers (Recommended)**: Get token → include in `X-CSRF-Token` header → automatic verification ✅
2. **Forms**: Get token → include in form field → manual verification required ⚠️

**Your responsibility:** Get tokens to your frontend and include them in requests.

## Getting CSRF Tokens

Choose the method that best fits your application:

### Server-Side Templates (Most Common)

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

### API Endpoint (For SPAs)

**Best for:** Single-page applications, dynamic token refresh

```javascript
// Fetch fresh token when needed
const response = await fetch('/o2p/user/csrf_token', {
    credentials: 'include'
});
const { csrf_token } = await response.json();
```

### Response Headers (Advanced)

**Best for:** Existing authenticated requests (token included automatically)

```javascript
// Token available in any authenticated response
const response = await fetch('/api/user-data', { credentials: 'include' });
const csrfToken = response.headers.get('X-CSRF-Token');
// Use token for subsequent requests
```

## Making Requests with CSRF Tokens

### Using Headers (Recommended - Automatic Verification)

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

**Verification is automatic** - no additional code needed in your handlers.

### Using Form Fields (Manual Verification Required)

**Best for:** Traditional HTML form submissions

```html
<form method="POST" action="/update-profile">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="name" placeholder="Your name">
    <button type="submit">Update Profile</button>
</form>
```

**Manual verification required** - see verification code below.

## Verification

### Header Tokens: Automatic Verification

When using `X-CSRF-Token` header:

- **Works with both** `AuthUser` extractor and `is_authenticated()` middleware
- **Automatic comparison** - token verified against session automatically
- **Success:** Request proceeds (`AuthUser.csrf_via_header_verified` = `true`)
- **Failure:** Request rejected with 403 FORBIDDEN

**No code needed** - verification happens automatically.

### Form Tokens: Manual Verification Required

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

## Security Best Practices

### Use Constant-Time Comparison

Always use constant-time comparison (`ct_eq`) when manually verifying CSRF tokens to prevent timing attacks:

```rust
use subtle::ConstantTimeEq;

// ✅ Good - constant-time comparison
if !form_data.csrf_token.as_bytes().ct_eq(auth_user.csrf_token.as_bytes()).into() {
    return Err((StatusCode::FORBIDDEN, "Invalid CSRF token"));
}

// ❌ Bad - vulnerable to timing attacks
if form_data.csrf_token != auth_user.csrf_token {
    return Err((StatusCode::FORBIDDEN, "Invalid CSRF token"));
}
```

### Prefer Header-Based CSRF

Header-based CSRF protection is recommended because:

- **Automatic verification** - no manual code required
- **Better security** - headers can't be set by simple forms from malicious sites
- **Cleaner code** - no additional verification logic needed

### Include Credentials in Requests

Always include `credentials: 'include'` in fetch requests to ensure cookies are sent:

```javascript
fetch('/api/protected', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    credentials: 'include',  // ← Required for cookies
    body: JSON.stringify(data)
});
```

## Troubleshooting

### 403 Forbidden Errors

If you're getting 403 errors on protected routes:

1. **Check token inclusion**: Ensure CSRF token is included in request
2. **Verify credentials**: Include `credentials: 'include'` in fetch requests
3. **Check token freshness**: CSRF tokens may expire with sessions
4. **Manual verification**: For forms, ensure manual verification code is present

### Token Not Available

If CSRF tokens are not available in your templates or responses:

1. **Check authentication**: CSRF tokens are only available for authenticated users
2. **Verify extractor**: Ensure you're using `AuthUser` extractor in your handlers
3. **Check initialization**: Ensure `oauth2_passkey_axum::init()` was called

### Performance Considerations

- **Cache tokens**: Don't fetch new tokens for every request
- **Reuse tokens**: CSRF tokens are valid for the entire session
- **Header preference**: Use header-based CSRF for better performance (no manual verification)

## Related Documentation

- [Axum Integration Guide](../oauth2_passkey_axum/README.md) - Basic CSRF usage examples
- [Security Best Practices](security-best-practices.md) - Additional security considerations
- [Demo Applications](../demo-both/README.md) - Complete working examples
