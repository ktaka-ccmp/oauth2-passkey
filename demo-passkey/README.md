# Demo-Passkey: WebAuthn/Passkey Authentication Example

This demo application showcases WebAuthn/Passkey (FIDO2) passwordless authentication using [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum).

## Features

- **WebAuthn/Passkey Registration**: Create new passkey credentials
- **Passwordless Authentication**: Sign in using biometrics, security keys, or device authentication
- **Credential Management**: List, view, and delete passkey credentials

## Quick Start

### Prerequisites

- Rust (latest stable version)
- Modern web browser with WebAuthn support (Chrome, Firefox, Safari, Edge)

### 1. Environment Setup

Copy the environment template and configure:

```bash
cp ../dot.env.example .env
```

Edit `.env` with your configuration:

```bash
# Required: Base URL of your application
ORIGIN='http://localhost:3001'

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

### 2. Run the Demo

```bash
cargo run
```

The application will start on:

- **HTTP**: Port 3001 (access as <http://localhost:3001>)

**Note**: `localhost` is a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts), so WebAuthn/Passkey works over HTTP on localhost.

**For mobile testing**, see the [Development Tunneling Guide](../docs/src/guides/tunneling.md).

### 3. Try the Demo

1. **Visit**: <http://localhost:3001>
2. **Register**: Click "Register with Passkey"
   - Enter a username
   - Follow browser prompts to create a passkey
3. **Sign In**: Click "Sign in with Passkey"
   - Authenticate using your chosen method
4. **Explore**: Navigate protected pages and manage credentials

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

**Important**: WebAuthn requires HTTPS for non-localhost origins.

## Application Structure

```text
demo-passkey/
├── src/
│   ├── main.rs          # Application entry point
│   └── server.rs        # Server configuration and routes
├── templates/           # HTML templates
│   ├── index_anon.j2   # Landing page for anonymous users
│   └── index_user.j2   # Landing page for authenticated users
├── Cargo.toml          # Dependencies
└── README.md           # This file
```

## Troubleshooting

### Common Issues

1. **"WebAuthn not supported" error**
   - Ensure you're using a modern browser
   - Update browser to latest version

2. **WebAuthn/Passkey not working**
   - `localhost` is a secure context - WebAuthn works over HTTP
   - For non-localhost, HTTPS is required (use an HTTPS proxy)
   - Ensure your device has biometric capabilities enabled
   - Try using a security key if available

3. **"Origin mismatch" error**
   - Ensure `ORIGIN` in `.env` matches the URL exactly
   - Use `http://localhost:3001` for local development

### Development Tips

- **localhost**: WebAuthn works over HTTP on localhost (secure context)
- **Production**: Use HTTPS proxy for non-localhost origins
- **Database**: SQLite file `auth.db` stores user credentials
- **Reset**: Delete `auth.db` to clear all registered credentials
