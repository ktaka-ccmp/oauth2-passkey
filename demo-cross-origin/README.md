# Cross-Origin Same-Site Demo (Pattern 2)

This demo demonstrates **Pattern 2: Cross-Origin Same-Site** authentication.
A separate **Resource API** validates session cookies issued by the **Auth Server**.

## Architecture

```text
cargo run
  │
  ├── Auth Server (auth.example.local:3000)
  │     ├── Frontend (Askama template)
  │     ├── OAuth2 + Passkey authentication (oauth2_passkey_full_router)
  │     └── Issues Cookie: Domain=.example.local
  │
  └── Resource API (api.example.local:3001)
        ├── /api/info (public endpoint)
        ├── /api/protected (requires auth)
        └── Validates same Cookie via CORS
```

## Why This Architecture?

**Pattern 2's value**: A session cookie issued by one server can be validated by
a completely **separate server** on a different subdomain.

| Server               | Role                     | CORS Needed |
|----------------------|--------------------------|-------------|
| Auth Server (3000)   | Issues session cookie    | No          |
| Resource API (3001)  | Validates session cookie | Yes         |

Use cases:

- **Microservices**: Multiple APIs sharing authentication
- **Separation of concerns**: Auth service separate from business logic
- **Scalability**: Auth and API servers can scale independently

## Quick Start

### 1. Add hosts entries

```bash
sudo sh -c 'echo "127.0.0.1 auth.example.local api.example.local" >> /etc/hosts'
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env to add your Google OAuth2 credentials
```

### 3. Start the servers

```bash
cargo run
```

### 4. Open in browser

Navigate to <http://auth.example.local:3000>

## Configuration

### Required Environment Variables

| Variable                      | Description                     | Example                          |
|-------------------------------|---------------------------------|----------------------------------|
| `ORIGIN`                      | Auth server URL                 | `http://auth.example.local:3000` |
| `RESOURCE_API_ORIGIN`         | Resource API URL (for frontend) | `http://api.example.local:3001`  |
| `SESSION_COOKIE_DOMAIN`       | Cookie domain for sharing       | `.example.local`                 |
| `CORS_ALLOWED_ORIGINS`        | Origins allowed for CORS        | `http://auth.example.local:3000` |
| `OAUTH2_GOOGLE_CLIENT_ID`     | Google OAuth2 client ID         | `xxx.apps.googleusercontent.com` |
| `OAUTH2_GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret     | (from Google Cloud Console)      |

### Optional Environment Variables

| Variable       | Default | Description             |
|----------------|---------|-------------------------|
| `AUTH_PORT`    | 3000    | Auth server port        |
| `API_PORT`     | 3001    | Resource API port       |

## How It Works

1. **User visits Auth Server** at `http://auth.example.local:3000`
2. **User logs in** via OAuth2 (Google) or Passkey
3. **Auth Server sets cookie** with `Domain=.example.local`
4. **User clicks "Test Resource API"** buttons on the page
5. **Browser sends cookie** to `api.example.local` (same domain)
6. **Resource API validates session** using the shared cookie
7. **CORS headers** allow the cross-origin response

## Key Technical Points

### Cookie Domain

```bash
SESSION_COOKIE_DOMAIN='.example.local'
```

The leading dot allows the cookie to be shared across all subdomains:

- `auth.example.local` (Auth Server) - issues the cookie
- `api.example.local` (Resource API) - receives and validates the cookie

### Cookie Name

```bash
SESSION_COOKIE_NAME='SessionId'
```

**Important**: Do NOT use `__Host-` prefix with Domain attribute.
`__Host-` cookies enforce: no Domain, Path=/, Secure.

### CORS Configuration

```bash
CORS_ALLOWED_ORIGINS='http://auth.example.local:3000'
CORS_ALLOW_CREDENTIALS=true
```

Only the Resource API needs CORS. The Auth Server serves the frontend
(Same-Origin), so no CORS is needed there.

## Production Deployment

For production with HTTP proxy (nginx, Caddy, etc.):

```bash
# Example: proxy passes to localhost:3000 and localhost:3001
ORIGIN='https://auth.example.com'
RESOURCE_API_ORIGIN='https://api.example.com'
SESSION_COOKIE_DOMAIN='.example.com'
CORS_ALLOWED_ORIGINS='https://auth.example.com'

# Ports for local binding (proxy forwards to these)
AUTH_PORT=3000
API_PORT=3001
```

## Troubleshooting

### "Not authenticated" on Resource API

1. Check that both servers use the same session storage:
   - `GENERIC_DATA_STORE_URL` must be shared (use PostgreSQL/Redis for separate processes)
   - In-memory storage only works within a single process

2. Check the cookie is being sent:
   - Open browser DevTools > Network > check for `Cookie` header

3. Verify cookie domain:
   - `SESSION_COOKIE_DOMAIN` must match both subdomains

### CORS errors

1. Check `CORS_ALLOWED_ORIGINS` matches the Auth Server origin exactly
2. Ensure `CORS_ALLOW_CREDENTIALS=true`
3. Check browser console for specific error messages

### OAuth2 login fails

1. Verify Google OAuth2 credentials in `.env`
2. Add redirect URI to Google Cloud Console:
   `http://auth.example.local:3000/o2p/oauth2/authorized`

## Related

- [Deployment Patterns](../docs/src/integration/deployment-patterns.md)
- [demo-both](../demo-both/) - Pattern 1 (Same-Origin) reference
