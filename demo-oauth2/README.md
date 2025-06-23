# Demo-OAuth2: Google OAuth2 Authentication Example

This demo application showcases Google OAuth2 authentication using [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum).

## Features

- **Google OAuth2 Integration**: Complete OAuth2/OIDC authentication flow
- **Session Management**: Secure session handling with logout
- **Protected Routes**: Pages requiring authentication

## Quick Start

### Prerequisites

- Rust (latest stable version)
- Google OAuth2 credentials

### 1. Environment Setup

Copy the environment template and configure:

```bash
cp ../dot.env.example .env
```

Edit `.env` with your Google OAuth2 credentials:

```bash
# Required: Base URL of your application
ORIGIN='https://localhost:3000'

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

### 2. Get Google OAuth2 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth2 credentials (Web application)
3. Add `https://localhost:3443/o2p/oauth2/authorized` to "Authorized redirect URIs"

### 3. Run the Demo

```bash
cargo run
```

The application will start on <https://localhost:3443>

### 4. Try the Demo

1. **Visit**: <https://localhost:3443>
2. **Sign In**: Click "Sign in with Google"
3. **Explore**: Navigate to protected pages and view your profile

## Application Structure

```text
demo-oauth2/
├── src/
│   ├── main.rs          # Application entry point
│   ├── handlers.rs      # Route handlers for authentication flows
│   └── server.rs        # Server configuration and routes
├── templates/           # HTML templates
│   ├── index_anon.j2   # Landing page for anonymous users
│   ├── index_user.j2   # Landing page for authenticated users
│   └── protected.j2    # Protected page template
├── self_signed_certs/   # HTTPS certificates for development
│   ├── cert.pem
│   ├── key.pem
│   └── gen_certs.sh    # Certificate generation script
├── Cargo.toml          # Dependencies
└── README.md           # This file
```

## Troubleshooting

### Common Issues

1. **"Invalid origin" error**
   - Ensure `ORIGIN` in `.env` matches the URL you're visiting
   - Use `https://localhost:3443` (not `127.0.0.1` or `http://`)

2. **Google OAuth2 not working**
   - Check your Google OAuth2 credentials in `.env`
   - Verify authorized origins and redirect URIs in Google Cloud Console

3. **SSL/HTTPS issues**
   - Browser will show security warning for self-signed certificates
   - Click "Advanced" → "Proceed" to continue

### Development Tips

- **Logs**: Check console output for detailed error messages
- **Database**: SQLite file `auth.db` stores user sessions
- **Reset**: Delete `auth.db` and restart to clear all sessions

