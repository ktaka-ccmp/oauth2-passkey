# Session Cookies and the `__Host-` Prefix

This guide explains how oauth2-passkey uses the `__Host-SessionId` cookie for secure session management, what to expect in different environments, and how to handle common warnings.

Session cookies are a critical part of web authentication, ensuring that users remain securely logged in. The `__Host-` prefix is a modern security feature that helps prevent common vulnerabilities such as session fixation and cross-site attacks by enforcing strict cookie attributes.

---

## Overview

- The `__Host-SessionId` cookie provides enhanced security by enforcing HTTPS, domain locking, and secure attributes.
- Some browsers show warnings or block these cookies on localhost; this is normal and does not affect authentication flow.

---

## Quick Reference

| Environment            | Recommendation                              | Notes                  |
|------------------------|---------------------------------------------|------------------------|
| **Production**         | Use default `__Host-SessionId` + HTTPS      | Required for security  |
| **Local (Firefox)**    | Keep defaults                               | Works perfectly        |
| **Local (Chrome/Safari)** | Accept warnings or use `SessionId-Dev`   | Warnings are harmless  |
| **Tests**              | Keep defaults                               | MockBrowser handles it |

---

## Common Error: "Failed to get session cookie"

This error is expected when users have not logged in yet:

```
ERROR: Failed to get session cookie: "__Host-SessionId" from cookies
```

**When This Error is Normal:**
- **Initial user visits** - Before any authentication has occurred
- **New user registration** - During the account creation process
- **Login page loads** - Before users submit credentials
- **After logout** - When session cookies have been cleared
- **Session expiration** - When existing sessions have timed out

**Why This Happens:**
The library attempts to read session cookies as part of its normal operation. When no session exists yet (new users) or when browsers reject `__Host-` cookies on localhost, this "error" appears but authentication continues normally.

- **No action needed:** Authentication will proceed normally.
- **Occurs in both HTTP and HTTPS environments**
- **Appears in both localhost and production deployments**

---

## Why Use `__Host-` Cookies?

- **HTTPS required:** Cookies with the `__Host-` prefix can only be sent over secure (HTTPS) connections, protecting them from interception.
- **Domain locked:** These cookies cannot be set by subdomains, reducing the risk of attacks from other parts of your domain.
- **Path=/ enforced:** The cookie is sent to all paths in your application, ensuring consistent session management.
- **Secure only:** The cookie is inaccessible to JavaScript (when using `HttpOnly`), further reducing attack surface.

**Benefits:**
Prevents session fixation, subdomain attacks, and ensures secure transmission.

---

## Browser Behavior on localhost

| Browser   | __Host- Cookies on localhost HTTP | Notes                |
|-----------|-----------------------------------|----------------------|
| Firefox   | ✅ Allowed                       | Best for development |
| Chrome    | ❌ Blocked                       | Warnings, auth works |
| Safari    | ❌ Blocked                       | Most restrictive     |
| **MockBrowser (Tests)** | ✅ Allowed           | No browser restrictions |

**Why MockBrowser is Different:**
The oauth2-passkey test suite uses `MockBrowser` (based on `reqwest`), not real browsers. MockBrowser accepts `__Host-` cookies on `http://localhost` without validation, so browser-specific restrictions don't apply in tests. This is why setting `SESSION_COOKIE_NAME='SessionId-Test'` in the test environment is **not necessary**.

**Browser Differences Explained:**
- **Firefox**: Treats `localhost` as a "potentially trustworthy origin" per W3C spec
- **Chrome**: Known inconsistency - allows regular `Secure` cookies but blocks `__Host-` prefixed cookies on localhost (Chromium issues #1056543, #1245434)
- **Safari**: Most restrictive - blocks all `Secure` cookies on `http://localhost`

**Tip:** Use Firefox for smoothest local development.

---

## Configuration

- **Production:** Use defaults and ensure HTTPS
  ```bash
  ORIGIN=https://your-domain.com  # Required
  ```
- **Development:** Defaults are fine; warnings are harmless. Optionally override cookie name:
  ```bash
  SESSION_COOKIE_NAME='SessionId-Dev'
  ```
- **Testing:** Defaults work; MockBrowser bypasses browser restrictions.

**Note:** Overriding the cookie name (e.g., using `SessionId-Dev`) can reduce distracting warnings during development, but it also removes some of the security guarantees provided by the `__Host-` prefix. Always revert to the default in production.

---

## Troubleshooting

### Sessions Not Persisting
**Symptoms:** Users logged out after page refresh, authentication state not maintained

**Solutions:**
- **Ensure HTTPS in production** - `__Host-` cookies require secure origins
- **Verify ORIGIN matches domain exactly** - Check environment variable
- **Check browser developer tools** for cookie rejection errors

### Different Behavior Across Browsers
**Symptoms:** Works in Firefox but not Chrome/Safari locally

**Explanation:** This is expected behavior due to browser differences in localhost handling

**Solutions:**
- **Test with Firefox** for local development (most permissive)
- **Use local HTTPS** with tools like mkcert for production-like testing
- **Accept warnings** in Chrome/Safari (functionality still works)

### "Failed to get session cookie" Error
**When it's normal:** Before login, during registration, after logout, on session expiration

**When to investigate:** If authentication fails completely or sessions don't work after successful login

**Solutions:** Usually no action needed; if persistent issues, check HTTPS configuration

---

## Best Practices

**Do:**
- Use default `__Host-SessionId` in production.
- Always use HTTPS in production.
- Accept localhost warnings in development.
- Prefer Firefox for local development.

**Don't:**
- Disable `__Host-` prefix in production.
- Worry about normal "Failed to get session cookie" errors.

---

## Technical Details

The library handles missing cookies gracefully:

```rust
match get_session_cookie_from_headers(headers) {
    Ok(Some(session_id)) => { /* Cookie found - proceed */ },
    Ok(None) | Err(_) => { /* Normal for new users - continue auth flow */ }
}
```

Browser differences stem from varying RFC interpretations of "potentially trustworthy origins" for localhost.

---

## Summary

- `__Host-` cookies provide robust session security.
- Warnings on localhost are normal; authentication is unaffected.
- Library handles session cookies gracefully across environments.
- HTTPS is required for production.

---

## Related Docs

- [Security Best Practices](security-best-practices.md)
- [Security Analysis](security.md)
- [CSRF Protection](csrf-protection.md)
