# Demo Applications

This document provides an overview of the demo applications available in the repository that showcase the usage of `oauth2-passkey` and `oauth2-passkey-axum`.

## Quick Access

Each demo application includes a comprehensive README.md with detailed setup instructions:

- **[demo-both](../demo-both/README.md)** - Complete integration with both authentication methods
- **[demo-oauth2](../demo-oauth2/README.md)** - Google OAuth2/OIDC authentication
- **[demo-passkey](../demo-passkey/README.md)** - WebAuthn/Passkey authentication

## Available Demos

### 1. OAuth2 Demo

**Location:** [`/demo-oauth2`](../demo-oauth2/)  
**Documentation:** [README.md](../demo-oauth2/README.md)

The OAuth2 Demo showcases Google OAuth2 authentication integration with the following features:

* Google Sign-In button and flow
* Protected pages requiring authentication
* User profile display after successful authentication
* Session management with logout capability

**Key files:**

* `src/main.rs` - Server setup and initialization
* `src/handlers.rs` - Route handlers for authentication flows
* `src/server.rs` - Server configuration and route setup
* `templates/` - HTML templates for the UI

**Running the demo:**

```bash
cd demo-oauth2
# Set up environment variables (see .env.example)
cargo run
# Visit http://localhost:3000 in your browser
```

### 2. Passkey Demo

**Location:** [`/demo-passkey`](../demo-passkey/)  
**Documentation:** [README.md](../demo-passkey/README.md)

The Passkey Demo demonstrates WebAuthn/Passkey authentication with the following features:

* Passkey registration and authentication flows
* Cross-device credential management
* Credential listing and deletion
* User profile management

**Key files:**

* `src/main.rs` - Server setup and Passkey initialization
* `src/server.rs` - Server configuration and route setup
* `templates/` - HTML templates with WebAuthn JavaScript

**Running the demo:**

```bash
cd demo-passkey
# Set up environment variables (see .env.example)
cargo run
# Visit http://localhost:3000 in your browser
```

### 3. Combined Authentication Demo

**Location:** [`/demo-both`](../demo-both/)  
**Documentation:** [README.md](../demo-both/README.md)

The Combined Demo showcases both OAuth2 and Passkey authentication in a single application:

* User choice between OAuth2 and Passkey authentication
* Protected routes with different authentication requirements
* Complete user registration and authentication flows
* Session management and CSRF protection

**Key files:**

* `src/main.rs` - Combined authentication setup
* `src/protected.rs` - Protected route implementations
* `src/server.rs` - Server configuration with all routes
* `templates/` - Templates for both authentication methods

**Running the demo:**

```bash
cd demo-both
# Set up environment variables (see .env.example)
cargo run
# Visit http://localhost:3000 in your browser
```

## Setting Up the Demos

All demos require:

1. Environment variables configuration (copy `.env.example` to `.env` and customize)
2. Database setup (SQLite by default, no additional setup required)
3. Google OAuth2 credentials (for OAuth2 demos)
4. HTTPS for local testing (self-signed certificates provided)

### Environment Variables

Each demo requires at minimum:

```bash
ORIGIN=https://localhost:3000
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL=sqlite:auth.db
GENERIC_CACHE_STORE_TYPE=memory
GENERIC_CACHE_STORE_URL=memory://test
OAUTH2_GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
OAUTH2_GOOGLE_CLIENT_SECRET=your_client_secret
```

## Demo Application Architecture

The demos follow a consistent architecture:

1. **Server setup** - Initializes the server with Axum and authentication
2. **Routes** - Defines public and protected routes
3. **Handlers** - Implements route handlers that use the authentication APIs
4. **Templates** - HTML templates with authentication UI components

Each demo is designed to showcase specific aspects of the authentication library while following best practices for security and user experience.
