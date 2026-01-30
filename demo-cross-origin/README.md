# Cross-Origin Same-Site Demo (Pattern 2)

This demo demonstrates **Pattern 2: Cross-Origin Same-Site** cookie-based authentication, where the frontend and API are hosted on different subdomains of the same site.

## Architecture

```
http://app.example.local:3000    (Frontend / SPA)
    |
    | fetch with credentials: 'include'
    v
http://api.example.local:3001    (API server with oauth2-passkey)
    |
    +-- Set-Cookie: Domain=.example.local
    +-- CORS: Access-Control-Allow-Origin: http://app.example.local:3000
```

## Key Configuration

### 1. Cookie Domain

The session cookie uses a domain attribute to enable cross-subdomain sharing:

```bash
SESSION_COOKIE_DOMAIN='.example.local'
```

**Important**: When using a domain attribute, the cookie name should NOT use the `__Host-` prefix:

```bash
SESSION_COOKIE_NAME='SessionId'  # No __Host- prefix!
```

This is because `__Host-` cookies enforce:
- No Domain attribute
- Path must be `/`
- Secure flag required

### 2. CORS Configuration

Cross-origin requests require proper CORS headers:

```bash
CORS_ALLOWED_ORIGINS='http://app.example.local:3000'
CORS_ALLOW_CREDENTIALS=true
```

### 3. Client-Side Fetch

The frontend must include credentials in all requests:

```javascript
fetch('http://api.example.local:3001/api/protected', {
    method: 'GET',
    credentials: 'include',  // Required for cross-origin cookies
});
```

## Setup

### 1. Add hosts entries

Add the following to `/etc/hosts`:

```
127.0.0.1 app.example.local
127.0.0.1 api.example.local
```

### 2. Copy environment file

```bash
cp .env.example .env
```

### 3. Start the API server

```bash
cargo run
```

The API server will start on `http://api.example.local:3001`.

### 4. Start the frontend server

In a separate terminal:

```bash
cd frontend
python -m http.server 3000 --bind 127.0.0.1
```

Or use any other static file server.

### 5. Open the demo

Navigate to `http://app.example.local:3000` in your browser.

## How It Works

1. **User visits frontend** at `http://app.example.local:3000`
2. **Frontend fetches API** at `http://api.example.local:3001` with `credentials: 'include'`
3. **Browser sends cookies** because both origins are Same-Site (`.example.local`)
4. **API validates session** using the cookie
5. **CORS headers** allow the cross-origin request

## Same-Site vs Same-Origin

| Concept | Example |
|---------|---------|
| Same-Origin | `http://app.example.local:3000` = `http://app.example.local:3000` (exact match) |
| Same-Site | `http://app.example.local:3000` ~ `http://api.example.local:3001` (same registrable domain) |

Cookies with `SameSite=Lax` are sent for Same-Site requests, which is why this pattern works.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/info` | Returns API info and authentication status |
| `GET /api/protected` | Protected resource (requires authentication) |
| `GET /api/health` | Health check |
| `GET /o2p/passkey/csrf_token` | Get CSRF token |
| `POST /o2p/passkey/auth/start` | Start passkey authentication |
| `POST /o2p/passkey/auth/finish` | Complete passkey authentication |
| `POST /o2p/passkey/logout` | Logout |

## Troubleshooting

### Cookies not being sent

1. Verify hosts entries are correct
2. Check browser developer tools > Network > Request headers for `Cookie`
3. Ensure `credentials: 'include'` is set in fetch
4. Verify CORS configuration is correct

### CORS errors

1. Check that `CORS_ALLOWED_ORIGINS` matches the frontend origin exactly
2. Ensure `CORS_ALLOW_CREDENTIALS=true`
3. Check browser console for specific CORS error messages

### Cookie not set

1. Verify `SESSION_COOKIE_DOMAIN='.example.local'`
2. Ensure cookie name doesn't use `__Host-` prefix
3. Check Set-Cookie header in response

## Related Documentation

- [Deployment Patterns](../docs/src/integration/deployment-patterns.md)
- [Bearer Token Support](../.claude/issues/open/2026-01-23-bearer-token-support.md) (Pattern 4)
