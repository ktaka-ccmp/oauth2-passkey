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
ORIGIN='http://localhost:3001'

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
3. Add `http://localhost:3001/o2p/oauth2/authorized` to "Authorized redirect URIs"

### 3. Run the Demo

```bash
cargo run
```

The application will start on:

- **HTTP**: Port 3001 (access as <http://localhost:3001>)

**For mobile testing**, see the [Development Tunneling Guide](../docs/src/guides/tunneling.md).

### 4. Try the Demo

1. **Visit**: <http://localhost:3001>
2. **Sign In**: Click "Sign in with Google"
3. **Explore**: Navigate to protected pages and view your profile

## HTTPS for Production

For production or non-localhost environments, use an HTTPS proxy (nginx/Caddy) to terminate TLS:

```text
Browser -> HTTPS (nginx/Caddy) -> HTTP (localhost:3001)
```

Example Caddy configuration:

```caddyfile
your-domain.com {
    reverse_proxy localhost:3001
}
```

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
├── Cargo.toml          # Dependencies
└── README.md           # This file
```

## Troubleshooting

### Common Issues

1. **"Invalid origin" error**
   - Ensure `ORIGIN` in `.env` matches the URL you're visiting
   - Use `http://localhost:3001` for local development

2. **Google OAuth2 not working**
   - Check your Google OAuth2 credentials in `.env`
   - Verify authorized origins and redirect URIs in Google Cloud Console

### Development Tips

- **Logs**: Check console output for detailed error messages
- **Database**: SQLite file `auth.db` stores user sessions
- **Reset**: Delete `auth.db` and restart to clear all sessions
