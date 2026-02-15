# Demo-Both: Complete Authentication Example

This demo application showcases both OAuth2 (Google) and WebAuthn/Passkey authentication in a single integrated application using [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum).

## Features

- **Dual Authentication Methods**: Users can choose between Google OAuth2 or WebAuthn/Passkey
- **Session Management**: Secure session handling with CSRF protection
- **User Management**: Registration, login, and profile management
- **Admin Interface**: User administration features

## Quick Start

### Prerequisites

- Rust (latest stable version)
- Google OAuth2 credentials (for OAuth2 authentication)
- Modern web browser (for WebAuthn/Passkey support)

### 1. Environment Setup

Copy the environment template and configure:

```bash
cp ../dot.env.simple .env
```

Edit `.env` with your configuration:

```bash
# Required: Base URL of your application
ORIGIN='http://localhost:3001'

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

**Note**: `localhost` is a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts), so WebAuthn/Passkey works over HTTP on localhost.

**For mobile testing**, see the [Development Tunneling Guide](../docs/src/guides/tunneling.md).

### 4. Try the Demo

1. **Visit**: <http://localhost:3001>
2. **Create User** with Google OAuth2 or Passkey
3. **Navigate to** the user account page: <http://localhost:3001/o2p/user/account>
4. **Add New Passkey** or **Add New OAuth2 Account**
5. **Logout**
6. **Sign in** with Google OAuth2 or Passkey
7. **Explore**
   1. Try Credential linking
   2. Try accessing protected pages p1-p6
8. **Admin** The first user is given admin privilege
   1. Create multiple users
   2. Try accessing the admin interface at <http://localhost:3001/o2p/admin/index>
   3. Manipulate other users

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

See [demo-cross-origin](../demo-cross-origin/) for a complete HTTPS proxy setup example.

## Application Structure

```text
demo-both/
├── src/
│   ├── main.rs          # Application entry point
│   ├── server.rs        # Server configuration and routes
│   └── protected.rs     # Protected route handlers
├── templates/           # HTML templates
│   ├── index.j2        # Landing page
│   ├── p3.j2           # Protected page examples
│   ├── p4.j2
│   ├── p5.j2
│   └── p6.j2
├── Cargo.toml          # Dependencies
├── dot.env.simple      # Environment template
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

3. **WebAuthn/Passkey not working**
   - `localhost` is a secure context - WebAuthn works over HTTP
   - For non-localhost, HTTPS is required (use an HTTPS proxy)
   - Try a different browser if having issues (Chrome has the best support)
   - Clear browser data for localhost if needed

4. **Database errors**
   - The SQLite database will be created automatically
   - Delete the database file to reset it (path depends on your configuration)
   - Use `touch` to recreate the database file if needed
   - Make sure the path specified by `GENERIC_DATA_STORE_URL` in your `.env` is writable (e.g., the directory for your SQLite file)

### Development Tips

- **Logs**: Check console output for detailed error messages

## Configuration Options

This demo supports all the same configuration options as the main library:

- **Database**: SQLite, PostgreSQL
- **Cache**: In-memory, Redis
- **Route prefix**: Customize authentication routes
- **UI features**: Enable/disable admin and user interfaces

See the dot.env.example in the main repository documentation for complete configuration details.
