# Chapter 2: Quick Start

This guide walks you through running the demo applications to quickly experience OAuth2 and WebAuthn/Passkey authentication.

## Prerequisites

- **Rust toolchain**: Latest stable version
- **Docker** (optional): For PostgreSQL and Redis in production setups
- **Google OAuth2 credentials**: Required for OAuth2 demos (demo-both, demo-oauth2)
- **Modern web browser**: Chrome, Firefox, Safari, or Edge with WebAuthn support
- **HTTPS**: Required for WebAuthn/Passkey functionality

## Installation

Add the library as a dependency in your `Cargo.toml`:

```toml
[dependencies]
oauth2-passkey = "0.2"
oauth2-passkey-axum = "0.2"
```

For building with all features (required for Axum integration):

```bash
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --all-features
```

## Running Demo Applications

The repository includes three demo applications to showcase different authentication scenarios.

### demo-both (OAuth2 + Passkey)

A complete authentication example showcasing both Google OAuth2 and WebAuthn/Passkey authentication in a single integrated application.

**Features:**
- Dual authentication methods (Google OAuth2 and WebAuthn/Passkey)
- Session management with CSRF protection
- User management and registration
- Admin interface for user administration

#### Setup

1. **Environment Setup**

   ```bash
   cd demo-both
   cp ../dot.env.simple .env
   ```

   Edit `.env` with your configuration:

   ```bash
   # Required: Base URL of your application
   ORIGIN='https://localhost:3443'

   # Required: Google OAuth2 credentials
   OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
   OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'

   # Database (SQLite for easy setup)
   GENERIC_DATA_STORE_TYPE=sqlite
   GENERIC_DATA_STORE_URL='sqlite:/tmp/auth.db'

   # Cache (in-memory for demo)
   GENERIC_CACHE_STORE_TYPE=memory
   GENERIC_CACHE_STORE_URL='memory'
   ```

2. **Get Google OAuth2 Credentials**

   1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   2. Create OAuth2 credentials (Web application)
   3. Add `https://localhost:3443/o2p/oauth2/authorized` to "Authorized redirect URIs"

3. **Run the Demo**

   ```bash
   cargo run
   ```

   The application starts on:
   - **HTTPS**: Port 3443 (access as `https://localhost:3443`)
   - **HTTP**: Port 3001 (for use behind HTTPS proxies)

4. **Try the Demo**

   1. Visit `https://localhost:3443`
   2. Create a user with Google OAuth2 or Passkey
   3. Navigate to the user summary page: `https://localhost:3443/o2p/user/summary`
   4. Add new Passkey or OAuth2 account
   5. Log out and sign in with a different method
   6. Explore credential linking and protected pages (p1-p6)
   7. Admin features: The first user gets admin privileges at `https://localhost:3443/o2p/admin/list_users`

### demo-oauth2 (OAuth2 Only)

A focused example demonstrating Google OAuth2 authentication.

**Features:**
- Google OAuth2/OIDC authentication flow
- Session management with logout
- Protected routes requiring authentication

#### Setup

1. **Environment Setup**

   ```bash
   cd demo-oauth2
   cp ../dot.env.example .env
   ```

   Edit `.env` with your Google OAuth2 credentials:

   ```bash
   # Required: Base URL of your application
   ORIGIN='https://localhost:3443'

   # Required: Google OAuth2 credentials
   OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
   OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'

   # Database (SQLite for easy setup)
   GENERIC_DATA_STORE_TYPE=sqlite
   GENERIC_DATA_STORE_URL='sqlite:./auth.db'

   # Cache (in-memory for demo)
   GENERIC_CACHE_STORE_TYPE=memory
   GENERIC_CACHE_STORE_URL='memory://demo'
   ```

2. **Get Google OAuth2 Credentials**

   1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   2. Create OAuth2 credentials (Web application)
   3. Add `https://localhost:3443/o2p/oauth2/authorized` to "Authorized redirect URIs"

3. **Run the Demo**

   ```bash
   cargo run
   ```

   The application starts on `https://localhost:3443`

4. **Try the Demo**

   1. Visit `https://localhost:3443`
   2. Click "Sign in with Google"
   3. Navigate to protected pages and view your profile

### demo-passkey (Passkey Only)

A focused example demonstrating WebAuthn/Passkey (FIDO2) passwordless authentication.

**Features:**
- WebAuthn/Passkey registration and credential creation
- Passwordless authentication using biometrics, security keys, or device authentication
- Credential management (list, view, delete)

#### Setup

1. **Environment Setup**

   ```bash
   cd demo-passkey
   cp ../dot.env.example .env
   ```

   Edit `.env` with your configuration:

   ```bash
   # Required: Base URL of your application (MUST be HTTPS)
   ORIGIN='https://localhost:3443'

   # Database (SQLite for easy setup)
   GENERIC_DATA_STORE_TYPE=sqlite
   GENERIC_DATA_STORE_URL='sqlite:./auth.db'

   # Cache (in-memory for demo)
   GENERIC_CACHE_STORE_TYPE=memory
   GENERIC_CACHE_STORE_URL='memory://demo'

   # Optional: OAuth2 credentials (not used in this demo)
   # OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
   # OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'
   ```

2. **Run the Demo**

   ```bash
   cargo run
   ```

   The application starts on `https://localhost:3443`

3. **Try the Demo**

   1. Visit `https://localhost:3443`
   2. Click "Register with Passkey"
      - Enter a username
      - Follow browser prompts to create a passkey
   3. Click "Sign in with Passkey"
      - Authenticate using your chosen method
   4. Navigate protected pages and manage credentials

## Basic Configuration

### Common Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ORIGIN` | Yes | Base URL of your application (e.g., `https://localhost:3443`) |
| `OAUTH2_GOOGLE_CLIENT_ID` | For OAuth2 | Google OAuth2 client ID |
| `OAUTH2_GOOGLE_CLIENT_SECRET` | For OAuth2 | Google OAuth2 client secret |
| `GENERIC_DATA_STORE_TYPE` | Yes | Database type: `sqlite` or `postgresql` |
| `GENERIC_DATA_STORE_URL` | Yes | Database connection URL |
| `GENERIC_CACHE_STORE_TYPE` | Yes | Cache type: `memory` or `redis` |
| `GENERIC_CACHE_STORE_URL` | Yes | Cache connection URL |

### Development vs Production

**Development (SQLite + Memory)**
```bash
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:./auth.db'
GENERIC_CACHE_STORE_TYPE=memory
GENERIC_CACHE_STORE_URL='memory://demo'
```

**Production (PostgreSQL + Redis)**
```bash
GENERIC_DATA_STORE_TYPE=postgresql
GENERIC_DATA_STORE_URL='postgresql://user:pass@localhost/dbname'
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://localhost:6379'
```

To start PostgreSQL and Redis with Docker:
```bash
cd db && docker compose up -d
```

### Using Cloudflared Tunnel

For public HTTPS access without self-signed certificates:

1. Set up a cloudflared tunnel pointing to `https://localhost:3443`
2. Update `.env`:
   ```bash
   ORIGIN='https://your-tunnel-domain.example.com'
   ```
3. Update Google OAuth2 redirect URI to `https://your-tunnel-domain.example.com/o2p/oauth2/authorized`

## Troubleshooting

### Common Issues

1. **"Invalid origin" error**
   - Ensure `ORIGIN` in `.env` matches the URL you're visiting exactly
   - Use `https://localhost:3443` (not `127.0.0.1` or `http://`)

2. **Google OAuth2 not working**
   - Check your Google OAuth2 credentials in `.env`
   - Verify authorized origins and redirect URIs in Google Cloud Console

3. **WebAuthn/Passkey not working**
   - Ensure you're using HTTPS (required for WebAuthn)
   - Try a different browser (Chrome has the best WebAuthn support)
   - Clear browser data for localhost if needed

4. **"Authenticator not found" error**
   - Ensure your device has biometric capabilities enabled
   - Try using a security key if available

5. **Database errors**
   - SQLite database is created automatically
   - Delete the database file to reset: `rm auth.db`
   - Ensure the path in `GENERIC_DATA_STORE_URL` is writable

6. **SSL/HTTPS issues**
   - Browser will show security warning for self-signed certificates
   - Click "Advanced" -> "Proceed" to continue

### Development Tips

- **Logs**: Check console output for detailed error messages
- **Self-signed certificates**: Browser will show security warning; proceed anyway
- **Reset database**: Delete `auth.db` to clear all sessions and credentials
