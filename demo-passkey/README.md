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
- HTTPS connection (required for WebAuthn)

### 1. Environment Setup

Copy the environment template and configure:

```bash
cp ../dot.env.example .env
```

Edit `.env` with your configuration:

```bash
# Required: Base URL of your application (MUST be HTTPS)
ORIGIN='https://localhost:3000'

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

The application will start on <https://localhost:3443>

### 3. Try the Demo

1. **Visit**: <https://localhost:3000>
2. **Register**: Click "Register with Passkey"
   - Enter a username
   - Follow browser prompts to create a passkey
3. **Sign In**: Click "Sign in with Passkey"
   - Authenticate using your chosen method
4. **Explore**: Navigate protected pages and manage credentials

## Application Structure

```text
demo-passkey/
├── src/
│   ├── main.rs          # Application entry point
│   └── server.rs        # Server configuration and routes
├── templates/           # HTML templates
│   ├── index_anon.j2   # Landing page for anonymous users
│   └── index_user.j2   # Landing page for authenticated users
├── self_signed_certs/   # HTTPS certificates for development
│   ├── cert.pem
│   ├── key.pem
│   └── gen_certs.sh    # Certificate generation script
├── Cargo.toml          # Dependencies
└── README.md           # This file
```

## Troubleshooting

### Common Issues

1. **"WebAuthn not supported" error**
   - Ensure you're using a modern browser
   - Update browser to latest version

2. **"HTTPS required" error**
   - WebAuthn requires HTTPS
   - Use <https://localhost:3443> (not HTTP)
   - Accept self-signed certificate warning

3. **"Authenticator not found" error**
   - Ensure your device has biometric capabilities enabled
   - Try using a security key if available

4. **"Origin mismatch" error**
   - Ensure `ORIGIN` in `.env` matches the URL exactly
   - Use `https://localhost:3000` (not `127.0.0.1`)

### Development Tips

- **HTTPS Required**: WebAuthn only works with HTTPS (except localhost)
- **Self-signed Certificates**: Browser will show security warning, proceed anyway
- **Database**: SQLite file `auth.db` stores user credentials
- **Reset**: Delete `auth.db` to clear all registered credentials
