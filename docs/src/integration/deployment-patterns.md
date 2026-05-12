# Deployment Patterns

This guide covers different deployment patterns for integrating oauth2-passkey with various client types and architectures.

## Overview

| # | Client | Origin Relationship | Authentication | Session Maintenance | Status |
|---|--------|---------------------|----------------|---------------------|--------|
| 1 | Browser (traditional/SPA) | Same-Origin | Browser | Cookie | Supported |
| 2 | Browser (traditional/SPA) | Cross-Origin, Same-Site | Browser | Cookie + Domain + CORS | Supported |
| 3 | Browser (traditional/SPA) | Cross-Site | - | - | Out of scope |
| 4 | Native App | - | Passkey (Native API) | Bearer | Supported |
| 5 | Native App | - | OAuth2 (In-App Browser) | Bearer | Not yet supported |

## Understanding Origin and Site

Before diving into deployment patterns, it's important to understand the difference between Origin and Site:

- **Same-Origin**: Scheme, host, and port are identical (e.g., `https://example.com:443`)
- **Cross-Origin**: Any difference in scheme, host, or port (e.g., `https://app.example.com` vs `https://api.example.com`)
- **Same-Site**: Same eTLD+1 (e.g., `app.example.com` and `api.example.com` share `example.com`)
- **Cross-Site**: Different eTLD+1 (e.g., `example.com` vs `another.com`)

## Pattern 1: Same-Origin (Recommended)

The simplest and most secure pattern. Your web application and API share the same origin.

### Architecture

```text
https://example.com
├── /              (Web pages)
├── /api/          (API endpoints)
└── /o2p/          (Authentication endpoints)
```

### Configuration

```bash
# .env
ORIGIN='https://example.com'
SESSION_AUTH_MODE=cookie
```

### Characteristics

- HttpOnly cookies automatically sent with every request
- CSRF protection required and handled automatically
- No additional CORS configuration needed
- Works with traditional server-rendered pages and SPAs

## Pattern 2: Cross-Origin, Same-Site

Your frontend and API are on different subdomains of the same domain.

### Architecture

```text
https://app.example.com    (Frontend / SPA)
https://api.example.com    (API server with oauth2-passkey)
```

### Requirements

1. **Cookie Domain attribute**: Set to parent domain
2. **CORS configuration**: On API server
3. **Frontend fetch configuration**: Include credentials

### Cookie Configuration

```bash
# .env for api.example.com
ORIGIN='https://api.example.com'
SESSION_AUTH_MODE=cookie
SESSION_COOKIE_DOMAIN='.example.com'  # Note the leading dot
```

### CORS Configuration (Axum)

```rust,ignore
use tower_http::cors::{CorsLayer, Any};
use http::{Method, header::{CONTENT_TYPE, AUTHORIZATION}};

let cors = CorsLayer::new()
    .allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap())
    .allow_credentials(true)  // Required for cookies
    .allow_methods([Method::GET, Method::POST, Method::DELETE])
    .allow_headers([CONTENT_TYPE, AUTHORIZATION]);

let app = Router::new()
    .merge(oauth2_passkey_full_router())
    .layer(cors);
```

### Frontend Configuration

```javascript
// All API requests must include credentials
fetch('https://api.example.com/o2p/passkey/auth/start', {
    method: 'POST',
    credentials: 'include',  // Required for cross-origin cookies
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({ account: 'user@example.com' }),
});
```

### Important Notes

- `SameSite=Lax` cookies work because both subdomains are Same-Site
- `Access-Control-Allow-Origin` cannot be `*` when using `credentials: include`
- The API server must explicitly list allowed origins

### Demo Application

See [demo-cross-origin](../../../demo-cross-origin/README.md) for a working example that demonstrates:

- Auth Server with OAuth2/Passkey authentication
- Separate API Server validating session cookies
- CORS configuration for cross-origin requests
- Multiple testing methods (localhost, HTTPS proxy, direct HTTPS)

## Pattern 3: Cross-Site (Not Supported)

Cross-site requests (different eTLD+1) face significant restrictions:

- Third-party cookies are being phased out by browsers
- `SameSite=None; Secure` is required but increasingly blocked

**Recommendation**: Use Pattern 2 by hosting your frontend and API on the same site, or use a reverse proxy to make them appear same-origin.

### Alternative: Reverse Proxy

```text
https://example.com
├── /              → Frontend server (proxied)
└── /api/          → API server (proxied)
```

With this setup, the browser sees everything as same-origin.

## Pattern 4: Native App with Passkey

Native mobile apps can use platform Passkey APIs directly.

### Architecture

```text
[Native App (iOS/Android)]
    │
    ├── Platform Passkey API (ASAuthorizationController / CredentialManager)
    │
    └── https://api.example.com (API server)
        └── Bearer token authentication
```

### Configuration

```bash
# .env
ORIGIN='https://api.example.com'
SESSION_AUTH_MODE=bearer
```

### Authentication Flow

1. **Start authentication**
   ```
   POST /api/passkey/auth/start
   Content-Type: application/json

   {"account": "user@example.com"}
   ```

2. **Process with platform API** (iOS example)
   ```swift
   let authController = ASAuthorizationController(authorizationRequests: [request])
   authController.delegate = self
   authController.performRequests()
   ```

3. **Complete authentication**
   ```
   POST /api/passkey/auth/finish
   Content-Type: application/json

   {"id": "...", "rawId": "...", "response": {...}, "type": "public-key"}
   ```

4. **Receive Bearer token**
   ```json
   {
     "token": "session_id_here",
     "token_type": "Bearer",
     "expires_in": 600
   }
   ```

5. **Use token for subsequent requests**
   ```
   GET /api/protected
   Authorization: Bearer session_id_here
   ```

### Security Considerations

- Store tokens securely (iOS Keychain, Android EncryptedSharedPreferences)
- Bearer tokens don't require CSRF protection
- Implement token refresh before expiration

## Pattern 5: Native App with OAuth2 (Not Yet Supported)

OAuth2 authentication from native apps requires special handling due to In-App Browser limitations.

### The Challenge

In-App Browsers (ASWebAuthenticationSession on iOS, Custom Tabs on Android) cannot read HTTP response bodies or headers. They can only detect URL changes.

### OAuth2 Authentication Flow

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Native App │     │ In-App      │     │ API Server  │     │ OAuth2      │
│             │     │ Browser     │     │ (o2p)       │     │ Provider    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
   1.  │ Open In-App Browser                   │                   │
       │──────────────────>│                   │                   │
       │                   │                   │                   │
   2.  │                   │ GET /o2p/oauth2/google/start          │
       │                   │──────────────────>│                   │
       │                   │                   │                   │
   3.  │                   │ 302 Redirect to Google                │
       │                   │<──────────────────│                   │
       │                   │                   │                   │
   4.  │                   │ User authenticates with Google        │
       │                   │──────────────────────────────────────>│
       │                   │                   │                   │
   5.  │                   │ 302 Redirect to /o2p/oauth2/callback?code=xxx
       │                   │<──────────────────────────────────────│
       │                   │                   │                   │
   6.  │                   │ GET /o2p/oauth2/callback?code=xxx     │
       │                   │──────────────────>│                   │
       │                   │                   │                   │
   7.  │                   │                   │ Exchange code for tokens
       │                   │                   │──────────────────>│
       │                   │                   │                   │
   8.  │                   │                   │ Access token + ID token
       │                   │                   │<──────────────────│
       │                   │                   │                   │
   9.  │                   │ 302 Redirect to myapp://callback?code=yyy
       │                   │<──────────────────│                   │
       │                   │                   │                   │
  10.  │ URL Scheme triggers app launch        │                   │
       │<──────────────────│                   │                   │
       │                   │                   │                   │
  11.  │ POST /o2p/api/token/exchange { code: yyy }                │
       │──────────────────────────────────────>│                   │
       │                   │                   │                   │
  12.  │ { token: "xxx", token_type: "Bearer", expires_in: 600 }   │
       │<──────────────────────────────────────│                   │
       │                   │                   │                   │
```

**Key Points:**

- Steps 1-8: Standard OAuth2 flow (same as browser)
- Step 9: Instead of returning session cookie, redirect to Custom URL Scheme with a short-lived code
- Steps 10-12: Native app exchanges code for Bearer token via API call

### Redirect Methods

#### Option A: Custom URL Scheme

```text
myapp://callback?code=xxx
```

- **Pros**: Simple to implement, works on all platforms
- **Cons**: Security risk - any app can register the same scheme

##### Security Risk: URL Scheme Hijacking

```text
1. Legitimate app registers: myapp://
2. Malicious app also registers: myapp://
3. When OAuth2 redirects to myapp://callback?code=xxx
4. OS may open malicious app instead
5. Malicious app steals the authorization code
```

This is why we use a short-lived **code** (not a long-lived token) in the redirect URL. Even if intercepted, the code:

- Expires quickly (typically 30-60 seconds)
- Can only be exchanged once
- Requires the code exchange endpoint

#### Option B: Universal Links / App Links (Recommended)

```text
https://api.example.com/app/callback?code=xxx
```

- **Pros**: Secure - only verified domain owner's app can receive
- **Cons**: Requires server configuration, HTTPS only

##### How Universal Links Work

1. **Server Configuration**: Host `apple-app-site-association` (iOS) or `assetlinks.json` (Android) at `/.well-known/`
2. **App Registration**: App declares which domains it handles in its entitlements
3. **Verification**: OS verifies the association file matches the app's bundle ID / package name
4. **Secure Routing**: Only the verified app can receive links for that domain

##### Example: apple-app-site-association

```json
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.example.myapp",
      "paths": ["/app/callback"]
    }]
  }
}
```

##### Universal Links Flow

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Native App │     │ OS (iOS/    │     │ API Server  │     │ OAuth2      │
│             │     │ Android)    │     │ (o2p)       │     │ Provider    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ (App install)     │                   │                   │
       │                   │                   │                   │
   0.  │                   │ GET /.well-known/apple-app-site-association
       │                   │──────────────────>│                   │
       │                   │                   │                   │
       │                   │ { applinks: { details: [...] } }      │
       │                   │<──────────────────│                   │
       │                   │                   │                   │
       │  (OS caches app-domain association)   │                   │
       │                   │                   │                   │
       │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
       │                   │                   │                   │
       │ (OAuth2 authentication - same as Custom URL Scheme)       │
       │                   │                   │                   │
   9.  │                   │ 302 Redirect to   │                   │
       │                   │ https://api.example.com/app/callback?code=yyy
       │                   │<──────────────────│                   │
       │                   │                   │                   │
  10.  │                   │ (OS intercepts    │                   │
       │                   │  HTTPS URL)       │                   │
       │                   │                   │                   │
  11.  │                   │ (Verify: Is this  │                   │
       │                   │  domain registered│                   │
       │                   │  for this app?)   │                   │
       │                   │                   │                   │
  12.  │ Launch app with URL                   │                   │
       │<──────────────────│                   │                   │
       │                   │                   │                   │
  13.  │ POST /o2p/api/token/exchange { code: yyy }                │
       │──────────────────────────────────────>│                   │
       │                   │                   │                   │
  14.  │ { token: "xxx", token_type: "Bearer", expires_in: 600 }   │
       │<──────────────────────────────────────│                   │
       │                   │                   │                   │
```

**Key Differences from Custom URL Scheme:**

- Step 0: OS fetches and caches `apple-app-site-association` at app install time
- Steps 10-11: OS verifies the domain is registered for this specific app
- No hijacking possible: Only the verified app can receive URLs for this domain

### Configuration (Planned)

```bash
# .env
ORIGIN='https://api.example.com'
SESSION_AUTH_MODE=bearer

# For Custom URL Scheme (Option A)
NATIVE_APP_CALLBACK_URL='myapp://callback'

# For Universal Links (Option B - Recommended)
NATIVE_APP_CALLBACK_URL='https://api.example.com/app/callback'
```

### Security Comparison

| Method | URL Scheme Hijacking | Requires HTTPS | Setup Complexity |
|--------|---------------------|----------------|------------------|
| Custom URL Scheme | Vulnerable | No | Low |
| Universal Links | Protected | Yes | Medium |

> **Recommendation**: Use Universal Links / App Links for production applications. Custom URL Scheme may be acceptable for development or low-security applications.

### Implementation Status

This pattern requires additional implementation:

1. **Code Exchange Endpoint**: `POST /o2p/api/token/exchange`
2. **OAuth2 Callback Modification**: Redirect to configured callback URL with code
3. **Code Generation**: Short-lived, one-time-use codes
4. **Configuration**: `NATIVE_APP_CALLBACK_URL` environment variable

Currently not supported. See [issue #2026-01-23-01](https://github.com/ktaka-ccmp/oauth2-passkey/issues) for tracking.

## Infrastructure Considerations

### Session Storage

| Deployment | Recommended Storage |
|------------|---------------------|
| Single server | Memory (default) |
| Multiple servers (Load Balanced) | Redis |

For multi-server deployments, all servers must share the same session store:

```bash
# .env
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://redis-server:6379'
```

### Database

Similarly, all servers must share the same database:

```bash
# .env
GENERIC_DATA_STORE_TYPE=postgres
GENERIC_DATA_STORE_URL='postgres://user:pass@db-server/oauth2_passkey'
```

## Choosing the Right Pattern

| Use Case | Recommended Pattern |
|----------|---------------------|
| Traditional web app | Pattern 1 (Same-Origin) |
| SPA on same domain | Pattern 1 (Same-Origin) |
| SPA on subdomain | Pattern 2 (Cross-Origin, Same-Site) |
| SPA on different domain | Use reverse proxy → Pattern 1 |
| iOS/Android with Passkey | Pattern 4 (Native Passkey) |
| iOS/Android with OAuth2 | Pattern 5 (not yet supported) |

## Summary

- **For browsers**: Use Cookie-based authentication (Pattern 1 or 2)
- **For native apps with Passkey**: Use Bearer token authentication (Pattern 4)
- **Avoid Cross-Site**: Third-party cookies are unreliable
- **Multi-server**: Always use shared Redis and database
