# iOS Safari Compatibility Guide

This document covers iOS Safari compatibility issues with OAuth2 authentication and development testing considerations.

## Overview

iOS Safari has one main characteristic that affects OAuth2 authentication:

1. **Intelligent Tracking Prevention (ITP)** - Blocks/partitions third-party cookies

This affects development testing with certain tunneling services (like ngrok) and OAuth2 response modes. Understanding these issues helps with debugging and configuration.

**Note**: OAuth2 popups work correctly on iOS Safari when triggered by user interaction and when using a proper tunneling solution like Cloudflare Tunnel.

## OAuth2 Popup Behavior on iOS

### Summary

**iOS Safari popups work correctly** when:

- The popup is triggered by a direct user action (click event)
- The application is accessed via Cloudflare Tunnel or direct proxy (not ngrok)

The library uses standard `window.open()` popup behavior on all platforms, including iOS Safari. No special fallback is needed.

### Historical Note

Earlier versions included iOS-specific redirect fallback code based on the assumption that iOS WebKit blocks popups aggressively. Testing with Cloudflare Tunnel confirmed that popups work fine on iOS Safari when triggered properly. The fallback code was removed in December 2025 as unnecessary complexity.

## OAuth2 Response Modes and Cookies

### Response Modes

OAuth2 supports two response modes for returning the authorization code:

| Mode | How it works |
|------|--------------|
| `form_post` (default) | Google auto-submits a POST form to your callback URL |
| `query` | Google redirects via GET with code in query string |

### SameSite Cookie Requirements

The CSRF cookie's SameSite attribute must match the response mode:

| Response Mode | Callback Method | SameSite Required | Why |
|---------------|-----------------|-------------------|-----|
| `form_post` | Cross-site POST | `None` | Browser must send cookie on cross-origin POST |
| `query` | Top-level GET redirect | `Lax` | Cookies sent on top-level navigation |

### iOS Safari ITP Issue

iOS Safari's Intelligent Tracking Prevention (ITP) blocks `SameSite=None` cookies on cross-site requests.

**Result**: `form_post` mode fails on iOS Safari:

1. CSRF cookie is set with `SameSite=None; Secure`
2. User authenticates on Google
3. Google POSTs back to your site
4. iOS Safari blocks the cookie due to ITP
5. CSRF validation fails

### Browser Compatibility

| Browser | Third-party cookies | `form_post` works? |
|---------|---------------------|-------------------|
| Android Chrome | Allowed by default | Yes |
| Desktop Chrome | Allowed by default | Yes |
| Desktop Safari | Some ITP restrictions | Usually |
| iOS Safari | Strict ITP | No |
| iOS Chrome | Uses WebKit (same as Safari) | No |

Note: All browsers on iOS use WebKit (Apple requirement), so iOS Chrome has the same restrictions as iOS Safari.

### Configuration

Use `query` response mode for iOS compatibility:

```bash
# .env file
OAUTH2_RESPONSE_MODE='query'
```

With `query` mode:

- Google redirects back via GET (not POST)
- Cookie uses `SameSite=Lax` (not `None`)
- iOS Safari's ITP doesn't block `Lax` cookies on top-level navigations

## Development Testing on iOS

### The ngrok Problem

When testing on iOS devices, developers often use ngrok to expose localhost. However, **ngrok's free tier does not work reliably on iOS**.

**Root Cause**: ngrok shows an interstitial page that requires a cookie to bypass. iOS Safari's ITP blocks this cookie for subresource requests (like JavaScript files).

**What happens**:

1. Main HTML page loads (user clicked through interstitial)
2. Browser requests external JavaScript files
3. ngrok returns HTML interstitial instead of JavaScript (cookie blocked)
4. Scripts fail to load, buttons don't work

**Evidence**:

```text
# Via ngrok on iOS (broken):
fetch oauth2.js content-type=text/html
fetch oauth2.js starts=<!DOCTYPE html>...

# Via nginx (works):
fetch oauth2.js content-type=application/javascript
fetch oauth2.js starts=const oauth2 = (function()...
```

### Why Android Works but iOS Fails

| Browser | Third-party cookies | ngrok works? |
|---------|---------------------|--------------|
| Android Chrome | Allowed by default | Yes |
| Desktop Chrome | Allowed by default | Yes |
| iOS Safari | Blocked by ITP | No |
| iOS Chrome | Blocked by ITP (uses WebKit) | No |

### Recommended Testing Methods

| Method | Use Case | iOS Compatible |
|--------|----------|----------------|
| Cloudflare Tunnel | Remote testing over internet | Yes |
| nginx reverse proxy | Local network testing | Yes |
| localhost | Direct access on same machine | N/A (no mobile) |

**Cloudflare Tunnel** is recommended for iOS testing:

- No interstitial page - Direct tunneling, no cookie dependency
- Works with iOS Safari - No ITP issues
- Free - Quick tunnels require no account

For setup instructions, see [Development Tunneling Guide](../guides/tunneling.md).

### ngrok Workarounds

If you must use ngrok, upgrade to a **paid plan** which removes the interstitial entirely.

## Summary

| Issue | Cause | Solution |
|-------|-------|----------|
| `form_post` fails | iOS ITP blocks `SameSite=None` cookies | Use `OAUTH2_RESPONSE_MODE='query'` |
| ngrok doesn't work on iOS | iOS ITP blocks ngrok's session cookie | Use Cloudflare Tunnel |

**Note**: OAuth2 popups work correctly on iOS Safari when using Cloudflare Tunnel or direct proxy.

## References

- [Full Third-Party Cookie Blocking - WebKit](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/)
- [SameSite cookies explained - web.dev](https://web.dev/articles/samesite-cookies-explained)
- [OAuth 2.0 Form Post Response Mode - RFC](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [Quick Tunnels - Cloudflare Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/)
