# Cross-Origin Same-Site Demo (Pattern 2)

This demo demonstrates **Pattern 2: Cross-Origin Same-Site** authentication.
A separate **API server** validates session cookies issued by the **Auth Server**.

## Table of Contents

- [Architecture](#architecture)
- [Why This Architecture?](#why-this-architecture)
- [Testing Methods](#testing-methods)
  - [localhost (Easiest)](#localhost-easiest)
  - [HTTPS Proxy](#https-proxy)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [Key Technical Points](#key-technical-points)
- [Troubleshooting](#troubleshooting)
- [Related](#related)

## Architecture

```text
cargo run
  │
  ├── Auth Server (localhost:3001)
  │     ├── Frontend (Askama template)
  │     ├── OAuth2 + Passkey authentication (oauth2_passkey_full_router)
  │     └── Issues Cookie
  │
  └── API Server (localhost:3002)
        ├── /api/info (public endpoint)
        ├── /api/protected (requires auth)
        └── Validates same Cookie via CORS
```

## Why This Architecture?

**Pattern 2's value**: A session cookie issued by one server can be validated by
a completely **separate server** on a different subdomain (or port).

| Server      | Role                     | CORS Needed |
|-------------|--------------------------|-------------|
| Auth Server | Issues session cookie    | No          |
| API Server  | Validates session cookie | Yes         |

Use cases:

- **Microservices**: Multiple APIs sharing authentication
- **Separation of concerns**: Auth service separate from business logic
- **Scalability**: Auth and API servers can scale independently

## Testing Methods

### localhost (Easiest)

The simplest way to try this demo. No `/etc/hosts`, HTTPS, or proxy required.

| Requirement  | Status     |
|--------------|------------|
| /etc/hosts   | Not needed |
| HTTPS        | Not needed |
| Proxy        | Not needed |
| Passkey      | Works      |
| OAuth2       | Works      |

#### 1. Create `.env`

```bash
cat > .env << 'EOF'
ORIGIN='http://localhost:3001'
API_ORIGIN='http://localhost:3002'
CORS_ALLOWED_ORIGINS='http://localhost:3001'
CORS_ALLOW_CREDENTIALS=true

AUTH_PORT=3001
API_PORT=3002

# Google OAuth2 (get from https://console.cloud.google.com/apis/credentials)
OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
OAUTH2_GOOGLE_CLIENT_SECRET='your-secret'

# Storage (in-memory for demo)
GENERIC_CACHE_STORE_TYPE=memory
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite::memory:'
EOF
```

#### 2. Configure Google OAuth2

Add this redirect URI in Google Cloud Console:

```text
http://localhost:3001/o2p/oauth2/authorized
```

#### 3. Start the servers

```bash
cargo run
```

#### 4. Open in browser

Navigate to <http://localhost:3001>

**Why localhost works:**

- `localhost` is a secure context (Passkey works over HTTP)
- Google allows `http://localhost:*` for OAuth2 redirect URIs
- `localhost:3001` and `localhost:3002` are Cross-Origin but Same-Site

### HTTPS Proxy

Use nginx or Caddy to terminate HTTPS and proxy to the Rust app on HTTP.
This is the recommended approach for production.

| Requirement       | Status        |
|-------------------|---------------|
| /etc/hosts or DNS | Required      |
| HTTPS             | Proxy handles |
| Valid certificate | Required      |
| Passkey           | Works         |
| OAuth2            | Works         |

```text
Browser
  │
  ├─→ https://auth.foobar.com ──→ nginx/Caddy ──→ localhost:3001 (Auth Server)
  │
  └─→ https://api.foobar.com  ──→ nginx/Caddy ──→ localhost:3002 (API Server)
```

#### 1. Nginx configuration

```nginx
# /etc/nginx/sites-available/cross-origin-demo

# Auth Server
server {
    listen 443 ssl;
    server_name auth.foobar.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# API Server
server {
    listen 443 ssl;
    server_name api.foobar.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://localhost:3002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 2. Caddy configuration (alternative)

Copy the example configuration:

```bash
cp Caddyfile.example Caddyfile
# Edit paths to your certificate files
```

```caddyfile
# Auth Server
auth.foobar.com {
    tls /path/to/fullchain.pem /path/to/privkey.pem
    reverse_proxy localhost:3001
}

# API Server
api.foobar.com {
    tls /path/to/fullchain.pem /path/to/privkey.pem
    reverse_proxy localhost:3002
}
```

Validate and run:

```bash
caddy validate --config Caddyfile
caddy run --config Caddyfile
```

**Note**: You can use a wildcard certificate (`*.foobar.com`) or individual certificates.
For automatic Let's Encrypt, remove the `tls` directive and Caddy will obtain certificates automatically.

#### 3. Create `.env`

```bash
cat > .env << 'EOF'
# ORIGIN must match the external HTTPS URL
ORIGIN='https://auth.foobar.com'
API_ORIGIN='https://api.foobar.com'
SESSION_COOKIE_DOMAIN='.foobar.com'
CORS_ALLOWED_ORIGINS='https://auth.foobar.com'
CORS_ALLOW_CREDENTIALS=true

# Internal HTTP ports (proxy forwards to these)
AUTH_PORT=3001
API_PORT=3002

# Google OAuth2
OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
OAUTH2_GOOGLE_CLIENT_SECRET='your-secret'

# Storage
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://localhost:6379'
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:data.db'
EOF
```

#### 4. Configure Google OAuth2

Add this redirect URI in Google Cloud Console:

```text
https://auth.foobar.com/o2p/oauth2/authorized
```

#### 5. Start the servers

```bash
# Start nginx/Caddy first, then:
cargo run
```

#### 6. Open in browser

Navigate to <https://auth.foobar.com>

**Benefits:**

- No TLS configuration in Rust code
- Easy certificate management (especially with Caddy)
- Production-like architecture
- Can add rate limiting, logging, etc. at proxy level

## Configuration

### Required Environment Variables

| Variable                      | Description                     | Example                          |
|-------------------------------|---------------------------------|----------------------------------|
| `ORIGIN`                      | Auth server URL                 | `http://localhost:3001`          |
| `API_ORIGIN`                  | API server URL (for frontend)   | `http://localhost:3002`          |
| `CORS_ALLOWED_ORIGINS`        | Origins allowed for CORS        | `http://localhost:3001`          |
| `OAUTH2_GOOGLE_CLIENT_ID`     | Google OAuth2 client ID         | `xxx.apps.googleusercontent.com` |
| `OAUTH2_GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret     | (from Google Cloud Console)      |

### Optional Environment Variables

| Variable                | Default | Description                         |
|-------------------------|---------|-------------------------------------|
| `AUTH_PORT`             | 3000    | Auth server port                    |
| `API_PORT`              | 3001    | API server port                     |
| `SESSION_COOKIE_DOMAIN` | -       | Cookie domain (e.g., `.foobar.com`) |

## How It Works

1. **User visits Auth Server** (e.g., `http://localhost:3001`)
2. **User logs in** via OAuth2 (Google) or Passkey
3. **Auth Server sets cookie** (with optional `Domain` for subdomains)
4. **User clicks "Test API"** buttons on the page
5. **Browser sends cookie** to API server (Cross-Origin, Same-Site)
6. **API server validates session** using the shared cookie
7. **CORS headers** allow the cross-origin response

## Key Technical Points

### Cookie Domain

For subdomain sharing (not needed for localhost):

```bash
SESSION_COOKIE_DOMAIN='.foobar.com'
```

The leading dot allows the cookie to be shared across all subdomains:

- `auth.foobar.com` (Auth Server) - issues the cookie
- `api.foobar.com` (API Server) - receives and validates the cookie

### Cookie Name

```bash
SESSION_COOKIE_NAME='SessionId'
```

**Important**: Do NOT use `__Host-` prefix with Domain attribute.
`__Host-` cookies enforce: no Domain, Path=/, Secure.

### CORS Configuration

```bash
CORS_ALLOWED_ORIGINS='http://localhost:3001'
CORS_ALLOW_CREDENTIALS=true
```

Only the API server needs CORS. The Auth Server serves the frontend
(Same-Origin), so no CORS is needed there.

## Troubleshooting

### "Not authenticated" on API server

1. Check that both servers use the same session storage:
   - `GENERIC_DATA_STORE_URL` must be shared (use PostgreSQL/Redis for separate processes)
   - In-memory storage only works within a single process

2. Check the cookie is being sent:
   - Open browser DevTools > Network > check for `Cookie` header

3. Verify cookie domain (if using subdomains):
   - `SESSION_COOKIE_DOMAIN` must match both subdomains

### CORS errors

1. Check `CORS_ALLOWED_ORIGINS` matches the Auth Server origin exactly
2. Ensure `CORS_ALLOW_CREDENTIALS=true`
3. Check browser console for specific error messages

### OAuth2 login fails

1. Verify Google OAuth2 credentials in `.env`
2. Add redirect URI to Google Cloud Console matching your `ORIGIN`

### Passkey doesn't work

1. `localhost` works over HTTP (secure context)
2. Custom domains require HTTPS
3. Check browser console for WebAuthn errors

## Related

- [Deployment Patterns](../docs/src/integration/deployment-patterns.md)
- [demo-both](../demo-both/) - Pattern 1 (Same-Origin) reference
