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

### 2. Get Google OAuth2 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth2 credentials (Web application)
3. Add `https://localhost:3443/o2p/oauth2/authorized` to "Authorized redirect URIs"

### 3. Run the Demo

```bash
cargo run
```

The application will start on:

- **HTTPS**: 3443 (access as <https://localhost:3443> for testing with self-signed certs)
- **HTTP**: 3001 (for use behind HTTPS proxies like ngrok)

Successful startup looks like:

```text
$ cargo run 
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.19s
     Running `/home/ktaka/GitHub/oauth2-passkey/target/debug/demo-both`
2025-06-23T03:11:56.158375Z  INFO demo_both::server: Debug mode enabled - showing detailed logs by default
2025-06-23T03:11:56.158413Z  INFO demo_both::server: You can increase verbosity by setting the RUST_LOG environment variable.
2025-06-23T03:11:56.158420Z  INFO demo_both::server: Log levels from least to most verbose: error < warn < info < debug < trace
2025-06-23T03:11:56.158425Z  INFO demo_both::server: Example: RUST_LOG=debug ./demo-xxxxx
2025-06-23T03:11:56.158431Z  INFO demo_both::server: Current log level: DEBUG build with detailed logging
2025-06-23T03:11:56.158656Z  INFO oauth2_passkey::storage::data_store::config: Initializing data store with type: sqlite, url: sqlite:/tmp/auth.db
2025-06-23T03:11:56.158839Z  INFO oauth2_passkey::storage::data_store::config: Connected to database: type=sqlite, url=sqlite:/tmp/auth.db
2025-06-23T03:11:56.175587Z  INFO oauth2_passkey::storage::cache_store::config: Initializing cache store with type: memory, url: memory
2025-06-23T03:11:56.175612Z  INFO oauth2_passkey::storage::cache_store::memory: Creating new in-memory generic cache store
2025-06-23T03:11:56.175627Z  INFO oauth2_passkey::storage::cache_store::config: Connected to cache store: type=memory, url=memory
2025-06-23T03:11:56.203120Z  INFO oauth2_passkey::passkey::main::aaguid: Loading AAGUID mappings from JSON
2025-06-23T03:11:56.207605Z  INFO oauth2_passkey::passkey::main::aaguid: Successfully loaded 31 AAGUID mappings into cache
2025-06-23T03:11:56.715727Z  INFO oauth2_passkey::passkey::main::aaguid: Successfully loaded 272 AAGUID mappings into cache
2025-06-23T03:11:56.782317Z  INFO demo_both::server: HTTP server listening on 0.0.0.0:3001
2025-06-23T03:11:56.784802Z  INFO demo_both::server: HTTPS server listening on 0.0.0.0:3443
```

### 4. Try the Demo

1. **Visit**: <https://localhost:3443>
2. **Create User** with Google OAuth2 or Passkey
3. **Navigate to** [User](https://localhost:3443/o2p/user/summary)
4. **Add New Passkey** or **Add New OAuth2 Account**
5. **Logout**
6. **Sign in** with Google OAuth2 or Passkey
7. **Explore**
   1. Try Credential linking
   2. Try accessing protected pages p1-p6
8. **Admin** The first user is given admin privilege
   1. Create multiple users
   2. Try accessing the admin interface at <https://localhost:3443/o2p/admin/list_users>
   3. Manipulate other users

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
├── self_signed_certs/   # HTTPS certificates for development
│   ├── cert.pem
│   └── key.pem
├── Cargo.toml          # Dependencies
├── dot.env.simple      # Environment template
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

3. **WebAuthn/Passkey not working**
   - Ensure you're using HTTPS (required for WebAuthn)
   - Try a different browser if having issues (Chrome has the best chance of working at the time of writing)
   - Clear browser data for localhost if needed

4. **Database errors**
   - The SQLite database will be created automatically  
   - Delete the database file to reset it (path depends on your configuration)
   - Use `touch` to recreate the database file if needed
   - Make sure to use the path from your `.env` file

### Development Tips

- **Logs**: Check console output for detailed error messages
- **Database**: SQLite file will be created automatically if it does not exist. Make sure the path is writable.
- **Self-signed certificates**: Browser will show security warning, click "Advanced" → "Proceed"
- **Reset state**: Delete the database file (check your `.env` for the correct path) and restart to reset all users and sessions

## Configuration Options

This demo supports all the same configuration options as the main library:

- **Database**: SQLite, PostgreSQL
- **Cache**: In-memory, Redis
- **Route prefix**: Customize authentication routes
- **UI features**: Enable/disable admin and user interfaces

See the dot.env.example in the main repository documentation for complete configuration details.
