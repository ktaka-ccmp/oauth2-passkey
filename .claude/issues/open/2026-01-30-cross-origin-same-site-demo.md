# Issue: Create Cross-Origin Same-Site Demo (Pattern 2)

**Created**: 2026-01-30
**Status**: open
**Priority**: medium
**Type**: feature

## Summary

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

- [ ] API server with CORS configuration
- [ ] SPA frontend with proper fetch configuration
- [ ] Cookie Domain configuration working
- [ ] CSRF protection working across origins
- [ ] README with setup instructions
- [ ] Documentation of /etc/hosts testing approach
- [ ] All code passes `cargo fmt`, `cargo clippy`, `cargo test`

## Related

- [deployment-patterns.md](docs/src/integration/deployment-patterns.md) - Pattern 2 documentation
- [demo-passkey/](demo-passkey/) - Reference for passkey-only demo (Pattern 1)
- Issue 2026-01-23-01 - Bearer Token Support (Pattern 4)

## Notes

This demo differs from existing demos (demo-both, demo-passkey, etc.) which all use Pattern 1 (Same-Origin). This will be the first demo showing cross-origin cookie configuration.
