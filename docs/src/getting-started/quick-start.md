# Chapter 2: Quick Start

This guide walks you through running the demo applications to quickly experience OAuth2 and WebAuthn/Passkey authentication.

## Prerequisites

- **Rust toolchain**: Latest stable version
- **Web browser**: Chrome (recommended, fewest issues), Android Chrome, or iOS Safari

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

1. **Choose Your ORIGIN**

   Decide how you'll access the application:
   - **localhost** (default): `http://localhost:3001` - for local desktop testing (localhost is a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts))
   - **tunnel** (mobile testing): Use [Cloudflare Tunnel](../guides/tunneling.md) to get a public URL like `https://random-name.trycloudflare.com`

   > **Note**: If using a tunnel, set it up first to get your URL before proceeding.

2. **Get Google OAuth2 Credentials**

   1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   2. Create OAuth2 credentials (Web application)
   3. Add `{YOUR_ORIGIN}/o2p/oauth2/authorized` to "Authorized redirect URIs"
      - For localhost: `http://localhost:3001/o2p/oauth2/authorized`
      - For tunnel: `https://random-name.trycloudflare.com/o2p/oauth2/authorized`
   4. Copy the Client ID and Client Secret

3. **Environment Setup**

   ```bash
   cd demo-both
   cp ../dot.env.simple .env
   ```

   Edit `.env` with your configuration:

   ```bash
   # Required: Base URL of your application (must match step 1)
   ORIGIN='http://localhost:3001'

   # Required: Google OAuth2 credentials (from step 2)
   OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
   OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'

   # Database (SQLite for easy setup)
   GENERIC_DATA_STORE_TYPE=sqlite
   GENERIC_DATA_STORE_URL='sqlite:/tmp/auth.db'

   # Cache (in-memory for demo)
   GENERIC_CACHE_STORE_TYPE=memory
   GENERIC_CACHE_STORE_URL='memory'
   ```

4. **Run the Demo**

   ```bash
   cargo run
   ```

   The application starts on:
   - **HTTP**: Port 3001 (access as `http://localhost:3001`)

   > **Note**: localhost is a secure context, so WebAuthn/Passkey works over HTTP. For production, use a reverse proxy (nginx/Caddy) to provide HTTPS.

5. **Try the Demo**

   1. Visit your ORIGIN URL (e.g., `http://localhost:3001` or your tunnel URL)
   2. Create a user with Google OAuth2 or Passkey
   3. Navigate to the user account page: `{YOUR_ORIGIN}/o2p/user/account`
   4. Add new Passkey or OAuth2 account
   5. Log out and sign in with a different method
   6. Explore credential linking and protected pages (p1-p6)
   7. Admin features: The first user gets admin privileges at `{YOUR_ORIGIN}/o2p/admin/index`

### Other Demo Applications

| Demo | Description | Notes |
|------|-------------|-------|
| **demo-oauth2** | OAuth2-only authentication | Simpler setup, no passkey |
| **demo-passkey** | Passkey-only authentication | No Google credentials needed |
| **demo-custom-login** | Custom login/summary pages | See [Custom Pages](../integration/custom-pages.md) |
| **demo-cross-origin** | Cross-Origin Same-Site (Pattern 2) | Auth + API servers, see [Deployment Patterns](../integration/deployment-patterns.md) |

Setup is similar to demo-both: copy `.env` from `dot.env.simple`, adjust for each demo's needs.

## Basic Configuration

### Common Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ORIGIN` | Yes | Base URL of your application (e.g., `http://localhost:3001`) |
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

## Troubleshooting

### Common Issues

1. **"Invalid origin" error**
   - Ensure `ORIGIN` in `.env` matches the URL you're visiting exactly
   - Use `http://localhost:3001` (not `127.0.0.1`)

2. **Google OAuth2 not working**
   - Check your Google OAuth2 credentials in `.env`
   - Verify authorized origins and redirect URIs in Google Cloud Console

3. **WebAuthn/Passkey not working**
   - WebAuthn requires a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (localhost or HTTPS)
   - Try a different browser (Chrome has the best WebAuthn support)
   - Clear browser data for localhost if needed

4. **"Authenticator not found" error**
   - Ensure your device has biometric capabilities enabled
   - Try using a security key if available

5. **Database errors**
   - SQLite database is created automatically
   - Delete the database file to reset: `rm auth.db`
   - Ensure the path in `GENERIC_DATA_STORE_URL` is writable

### Development Tips

- **Logs**: Check console output for detailed error messages
- **Reset database**: Delete `auth.db` to clear all sessions and credentials
