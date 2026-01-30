# Cross-Origin Same-Site Demo (Pattern 2)

This demo demonstrates **Pattern 2: Cross-Origin Same-Site** cookie-based authentication with a **separate Resource API** that validates sessions issued by the Auth Server.

## Architecture

```
cargo run
  |
  +-- Auth Server (auth.example.local:3000)
  |     |
  |     +-- Frontend (static files)
  |     +-- oauth2_passkey (authentication endpoints)
  |     +-- Issues Cookie: Domain=.example.local
  |
  +-- Resource API (api.example.local:3001)
        |
        +-- Protected endpoints (/api/*)
        +-- Validates same Cookie (Cross-Origin)
        +-- CORS: Allow auth.example.local:3000
```

## Why This Architecture?

This demo shows the **real value of Pattern 2**: a session cookie issued by one server can be validated by a completely **separate server** on a different subdomain.

| Server               | Role                     | CORS Needed                      |
|----------------------|--------------------------|----------------------------------|
| Auth Server (3000)   | Issues session cookie    | No (Same-Origin with frontend)   |
| Resource API (3001)  | Validates session cookie | Yes (Cross-Origin from frontend) |

This pattern is useful for:

- **Microservices**: Multiple APIs sharing authentication
- **Separation of concerns**: Auth service separate from business logic
- **Scalability**: Auth and API servers can scale independently

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

The Resource API needs CORS to accept requests from the frontend (served by Auth Server):

```bash
CORS_ALLOWED_ORIGINS='http://auth.example.local:3000'
CORS_ALLOW_CREDENTIALS=true
```

### 3. Client-Side Fetch

The frontend uses different fetch patterns for each server:

```javascript
// Auth Server (Same-Origin) - no special options needed
fetch('/o2p/passkey/auth/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
});

// Resource API (Cross-Origin) - requires credentials
fetch('http://api.example.local:3001/api/protected', {
    method: 'GET',
    credentials: 'include',  // Required for cross-origin cookies!
});
```

## Setup

### 1. Add hosts entries

Add the following to `/etc/hosts`:

```
127.0.0.1 auth.example.local
127.0.0.1 api.example.local
```

### 2. Copy environment file

```bash
cp .env.example .env
```

### 3. Start both servers

```bash
cargo run
```

This starts both servers:

- Auth Server: `http://auth.example.local:3000`
- Resource API: `http://api.example.local:3001`

### 4. Open the demo

Navigate to `http://auth.example.local:3000` in your browser.

## How It Works

1. **User visits Auth Server** at `http://auth.example.local:3000` (frontend is served here)
2. **User authenticates** via passkey (Same-Origin, no CORS)
3. **Auth Server sets cookie** with `Domain=.example.local`
4. **Frontend calls Resource API** at `http://api.example.local:3001` with `credentials: 'include'`
5. **Browser sends the same cookie** because both origins are Same-Site
6. **Resource API validates session** using the shared cookie
7. **CORS headers** allow the cross-origin response

## Same-Site vs Same-Origin

| Concept     | Example                                                                                      |
|-------------|----------------------------------------------------------------------------------------------|
| Same-Origin | `http://auth.example.local:3000` = `http://auth.example.local:3000` (exact match)            |
| Same-Site   | `http://auth.example.local:3000` ~ `http://api.example.local:3001` (same registrable domain) |

Cookies with `SameSite=Lax` are sent for Same-Site requests, which is why this pattern works.

## API Endpoints

### Auth Server (auth.example.local:3000)

| Endpoint | Description |
|----------|-------------|
| `GET /` | Frontend (static files) |
| `GET /o2p/info` | oauth2_passkey info |
| `GET /o2p/passkey/csrf_token` | Get CSRF token |
| `POST /o2p/passkey/auth/start` | Start passkey authentication |
| `POST /o2p/passkey/auth/finish` | Complete passkey authentication |
| `POST /o2p/passkey/logout` | Logout |

### Resource API (api.example.local:3001)

| Endpoint | Description |
|----------|-------------|
| `GET /api/info` | Shows auth status (demonstrates cookie sharing) |
| `GET /api/protected` | Protected resource (requires authentication) |
| `GET /api/health` | Health check |

## Troubleshooting

### Cookies not being sent to Resource API

1. Verify hosts entries are correct for both `auth` and `api`
2. Check browser developer tools > Network > Request headers for `Cookie`
3. Ensure `credentials: 'include'` is set in fetch to Resource API
4. Verify CORS configuration is correct

### CORS errors

1. Check that `CORS_ALLOWED_ORIGINS` matches the Auth Server origin exactly
2. Ensure `CORS_ALLOW_CREDENTIALS=true`
3. Check browser console for specific CORS error messages

### Cookie not set

1. Verify `SESSION_COOKIE_DOMAIN='.example.local'`
2. Ensure cookie name doesn't use `__Host-` prefix
3. Check Set-Cookie header in response

### Authentication works but Resource API says not authenticated

1. Verify both servers share the same session storage configuration
2. Check that the cookie is being sent (look for `Cookie` header in Network tab)
3. Ensure `ORIGIN` is set to the Auth Server origin in `.env`

## Related Documentation

- [Deployment Patterns](../docs/src/integration/deployment-patterns.md)
- [Bearer Token Support](../.claude/issues/open/2026-01-23-bearer-token-support.md) (Pattern 4)
