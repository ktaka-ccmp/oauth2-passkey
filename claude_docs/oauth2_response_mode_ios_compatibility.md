# OAuth2 Response Mode and iOS Safari Compatibility

This document explains the OAuth2 response mode configuration, SameSite cookie behavior, and iOS Safari compatibility issues.

## OAuth2 Response Modes

OAuth2 supports two response modes for returning the authorization code:

### `form_post` Mode (Default)

Google creates an HTML form and auto-submits a POST request to your callback URL.

```
User clicks login → Redirect to Google → User authenticates →
Google auto-POSTs to yoursite.com/oauth2/authorized
```

### `query` Mode

Google redirects back via GET with the authorization code in the URL query string.

```
User clicks login → Redirect to Google → User authenticates →
Google redirects (302) to yoursite.com/oauth2/authorized?code=...
```

## SameSite Cookie Behavior

The CSRF cookie's SameSite attribute must match the response mode:

| Response Mode | Callback Method | SameSite Required | Why |
|---------------|-----------------|-------------------|-----|
| `form_post` | Cross-site POST | `None` | Browser must send cookie on cross-origin POST |
| `query` | Top-level GET redirect | `Lax` | Cookies sent on top-level navigation |

### Why `form_post` Requires `SameSite=None`

1. User is on `yoursite.com`, clicks OAuth2 login
2. Your server sets CSRF cookie, redirects to Google
3. User authenticates on `accounts.google.com`
4. Google creates an HTML form that auto-submits POST to `yoursite.com/oauth2/authorized`

Step 4 is a **cross-site POST** from Google's domain to your domain. The browser needs to send your CSRF cookie with this POST request to validate the flow.

**SameSite behavior on cross-site POST:**
- `SameSite=Strict` → Cookie NOT sent
- `SameSite=Lax` → Cookie NOT sent
- `SameSite=None` → Cookie sent ✓

### Why `query` Mode Can Use `SameSite=Lax`

With `query` mode, Google redirects back via GET (302 redirect). This is a **top-level navigation**, not a form POST.

**SameSite behavior on top-level GET navigation:**
- `SameSite=Strict` → Cookie NOT sent
- `SameSite=Lax` → Cookie sent ✓
- `SameSite=None` → Cookie sent ✓

`Lax` is preferred for `query` mode because it provides better security (blocks cookies on cross-site POST/iframe requests) while still working for the redirect flow.

## iOS Safari Compatibility Issue

### The Problem

iOS Safari's Intelligent Tracking Prevention (ITP) blocks or partitions `SameSite=None` cookies on cross-site requests, even with the `Secure` attribute.

**Result**: `form_post` mode fails on iOS Safari because:
1. CSRF cookie is set with `SameSite=None; Secure`
2. User authenticates on Google
3. Google POSTs back to your site
4. iOS Safari blocks the `SameSite=None` cookie due to ITP
5. CSRF validation fails: "No CSRF session cookie found"

### Why Android/Desktop Work But iOS Fails

| Browser | Third-party cookie handling | `form_post` works? |
|---------|----------------------------|-------------------|
| Android Chrome | Allowed by default | Yes ✓ |
| Desktop Chrome | Allowed by default | Yes ✓ |
| Desktop Safari | Some ITP restrictions | Usually ✓ |
| iOS Safari | Strict ITP, blocks cross-site cookies | No ✗ |
| iOS Chrome | Uses WebKit (same as Safari) | No ✗ |

Note: All browsers on iOS use WebKit under the hood (Apple requirement), so iOS Chrome has the same restrictions as iOS Safari.

### The Solution

Use `query` response mode instead of `form_post`:

```bash
# In .env file
OAUTH2_RESPONSE_MODE='query'
```

With `query` mode:
- Google redirects back via GET (not POST)
- Cookie uses `SameSite=Lax` (not `None`)
- Top-level GET navigations work with `Lax` cookies
- iOS Safari's ITP doesn't block `Lax` cookies on top-level navigations

## Additional Fix: Redirect After Authentication

When using full-page redirect on iOS (instead of popup), the `popup_close.j2` template needs to handle the case where there's no popup opener.

**Before** (only worked for popup mode):
```javascript
window.onload = function () {
    if (window.opener) {
        window.opener.postMessage('auth_complete', window.location.origin);
    }
    setTimeout(function () {
        window.close();
    }, 10);
}
```

**After** (works for both popup and redirect modes):
```javascript
window.onload = function () {
    if (window.opener) {
        // Popup mode: notify parent and close
        window.opener.postMessage('auth_complete', window.location.origin);
        setTimeout(function () {
            window.close();
        }, 10);
    } else {
        // Full-page redirect mode (iOS): redirect to summary page
        setTimeout(function () {
            window.location.href = '/o2p/user/summary';
        }, 100);
    }
}
```

## Can `form_post` Work on iOS?

**Short answer**: No, not reliably.

**Possible workarounds (all have issues):**

1. **Storage Access API**
   - Requires explicit user interaction to grant storage access
   - Adds friction to the auth flow
   - Not automatic or seamless

2. **Store CSRF token in URL state instead of cookie**
   - Requires architectural changes to CSRF validation
   - More complex implementation

3. **Wait for Apple to relax ITP**
   - Unlikely to happen
   - Apple has been making ITP stricter over time

**Recommended solution**: Use `query` response mode for iOS compatibility.

## Configuration

### Environment Variable

```bash
# .env file
OAUTH2_RESPONSE_MODE='query'    # Recommended for iOS compatibility
# OAUTH2_RESPONSE_MODE='form_post'  # Default, doesn't work on iOS
```

### Code Reference

The SameSite attribute is set in `oauth2_passkey/src/oauth2/main/core.rs`:

```rust
// Set SameSite attribute based on response mode
// form_post requires SameSite=None because it's a cross-site POST
// query (redirect) can use SameSite=Lax for better security
let samesite = match response_mode.to_lowercase().as_str() {
    "form_post" => "None",
    "query" => "Lax",
    _ => "Lax", // Default to Lax for unknown response modes
};
```

## Summary

| Aspect | `form_post` | `query` |
|--------|-------------|---------|
| Callback method | Cross-site POST | GET redirect |
| SameSite attribute | `None` | `Lax` |
| Security level | Good | Better (Lax is more restrictive) |
| iOS Safari | Broken (ITP blocks cookies) | Works ✓ |
| Android/Desktop | Works | Works |
| Recommendation | Avoid for iOS compatibility | Use this |

## References

- [Full Third-Party Cookie Blocking and More - WebKit](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/)
- [SameSite cookies explained - web.dev](https://web.dev/articles/samesite-cookies-explained)
- [OAuth 2.0 Form Post Response Mode - RFC](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- Internal docs: `docs/oauth2-user-verification.md`, `docs/testing/OAuth2TestCleanupCompletion.md`
