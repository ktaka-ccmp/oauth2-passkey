# Issue: Create Cross-Origin Same-Site Demo (Pattern 2)

## ID: 2026-01-30-09

## Status: completed

## Priority: medium

## Description

Create a demo application that demonstrates Pattern 2: Cross-Origin Same-Site cookie-based authentication. This will show how to configure cookie authentication when the frontend and API are on different subdomains of the same site.

## Background

From [deployment-patterns.md](docs/src/integration/deployment-patterns.md):

| # | Client | Origin Relationship | Authentication | Session Maintenance | Status |
|---|--------|---------------------|----------------|---------------------|--------|
| 2 | Browser (traditional/SPA) | Cross-Origin, Same-Site | Browser | Cookie + Domain + CORS | Supported |

This pattern is common for:
- SPAs hosted on `app.example.com` calling APIs on `api.example.com`
- Microservices architecture with shared authentication
- CDN-hosted frontends with separate API servers

## Architecture

```text
https://app.example.com    (Frontend / SPA)
    │
    │ fetch with credentials: 'include'
    ▼
https://api.example.com    (API server with oauth2-passkey)
    │
    ├── Set-Cookie: Domain=.example.com
    └── CORS: Access-Control-Allow-Origin: https://app.example.com
```

## Requirements

### Server-Side (API)

1. **Cookie Configuration**
   ```bash
   ORIGIN='https://api.example.com'
   SESSION_AUTH_MODE=cookie
   SESSION_COOKIE_DOMAIN='.example.com'
   ```

2. **CORS Configuration**
   ```rust
   let cors = CorsLayer::new()
       .allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap())
       .allow_credentials(true)
       .allow_methods([Method::GET, Method::POST, Method::DELETE])
       .allow_headers([CONTENT_TYPE, AUTHORIZATION]);
   ```

### Client-Side (SPA)

1. **Fetch Configuration**
   ```javascript
   fetch('https://api.example.com/o2p/passkey/auth/start', {
       method: 'POST',
       credentials: 'include',  // Required for cross-origin cookies
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({ account: 'user@example.com' }),
   });
   ```

## Demo Structure

```text
demo-cross-origin/
├── Cargo.toml
├── README.md
├── .env.example
└── src/
    ├── main.rs           # API server (api.example.com)
    └── frontend/
        └── index.html    # SPA (app.example.com)
```

## Testing Approach

### Option A: /etc/hosts + Local Ports

```bash
# /etc/hosts
127.0.0.1 app.example.local
127.0.0.1 api.example.local
```

Run:
- Frontend: `http://app.example.local:3000`
- API: `http://api.example.local:3001`

**Note**: Cookies with `SameSite=Lax` work for Same-Site even with different ports.

### Option B: Real Subdomains (Recommended for full testing)

Use actual subdomains with HTTPS for production-like testing:
- `https://app.yourdomain.com`
- `https://api.yourdomain.com`

## Key Points to Demonstrate

1. **Cookie Domain attribute**: How `.example.com` enables cross-subdomain sharing
2. **CORS configuration**: Proper headers for cross-origin requests
3. **credentials: 'include'**: Required for cross-origin cookie sending
4. **CSRF protection**: Still required for cookie-based auth
5. **SameSite=Lax behavior**: Works because both subdomains are Same-Site

## Acceptance Criteria

- [x] API server with CORS configuration
- [x] SPA frontend with proper fetch configuration
- [x] Cookie Domain configuration working
- [x] CSRF protection working across origins
- [x] README with setup instructions
- [x] Documentation of /etc/hosts testing approach
- [x] All code passes `cargo fmt`, `cargo clippy`, `cargo test`

## Related Files

- `docs/src/integration/deployment-patterns.md` - Pattern 2 documentation
- `demo-passkey/` - Reference for passkey-only demo (Pattern 1)

## Related Issues

- `2026-01-23-01` - Bearer Token Support (Pattern 4)

## Notes

This demo differs from existing demos (demo-both, demo-passkey, etc.) which all use Pattern 1 (Same-Origin). This will be the first demo showing cross-origin cookie configuration.

## Resolution

Implemented Pattern 2 (Cross-Origin Same-Site) support with the following changes:

### Library Changes

1. **SESSION_COOKIE_DOMAIN** (`oauth2_passkey/src/session/config.rs`)
   - Added new environment variable for cookie domain configuration
   - Enables cross-subdomain cookie sharing

2. **header_set_cookie()** (`oauth2_passkey/src/utils.rs`)
   - Added optional `domain` parameter for Domain attribute in cookies
   - Updated all call sites to pass domain parameter

3. **CORS Support** (`oauth2_passkey_axum/src/cors.rs`)
   - New module with configurable CORS layer
   - Environment variables: `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_CREDENTIALS`
   - Available via `cors` feature flag

### Demo Application

Created `demo-cross-origin/` demonstrating:
- API server with CORS and cookie domain configuration
- SPA frontend with `credentials: 'include'` fetch calls
- WebAuthn passkey authentication across origins
- Complete setup instructions with /etc/hosts approach

### Key Configuration

```bash
# Cookie domain for cross-subdomain sharing
SESSION_COOKIE_DOMAIN='.example.local'
SESSION_COOKIE_NAME='SessionId'  # No __Host- prefix!

# CORS for cross-origin requests
CORS_ALLOWED_ORIGINS='http://app.example.local:3000'
CORS_ALLOW_CREDENTIALS=true
```

### Files Modified/Created

- `oauth2_passkey/src/session/config.rs` - Added SESSION_COOKIE_DOMAIN
- `oauth2_passkey/src/utils.rs` - Added domain parameter to header_set_cookie
- `oauth2_passkey/src/session/main/session.rs` - Updated cookie creation
- `oauth2_passkey/src/coordination/oauth2.rs` - Updated CSRF cookie creation
- `oauth2_passkey/src/utils/tests.rs` - Added test for domain parameter
- `oauth2_passkey_axum/src/cors.rs` - New CORS configuration module
- `oauth2_passkey_axum/src/lib.rs` - Export cors module
- `oauth2_passkey_axum/Cargo.toml` - Added cors feature with tower-http
- `Cargo.toml` - Added demo-cross-origin to workspace, tower-http dependency
- `dot.env.example` - Documented new configuration options
- `demo-cross-origin/` - Complete demo application
