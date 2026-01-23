# demo-custom-login

This demo demonstrates how to create a **fully custom login page** with your own design while using the `oauth2-passkey` library for authentication.

## Key Concept

By default, unauthenticated users are redirected to the built-in login page at `/o2p/user/login`. This demo shows how to use the `O2P_LOGIN_URL` environment variable to redirect users to your own custom login page instead.

## Setup

1. Copy the environment file and configure it:

```bash
cp ../dot.env.example .env
# Edit .env with your Google OAuth2 credentials
```

2. **Important**: Add this line to your `.env` file:

```bash
O2P_LOGIN_URL='/login'
```

This tells the `AuthUser` extractor to redirect unauthenticated users to `/login` instead of the default `/o2p/user/login`.

> **Note**: This environment variable is **required** for custom login pages to work. Although it doesn't appear in your application code, the library reads it internally to determine where to redirect unauthenticated users.

3. Start the database and cache:

```bash
cd ../db && docker compose up -d
```

4. Run the demo:

```bash
cargo run
```

5. Open https://localhost:3443 in your browser.

## How It Works

### Custom Login Page (`/login`)

The login page is completely custom-designed:
- Uses the JavaScript APIs from `oauth2-passkey-axum`
- Full control over HTML, CSS, and layout
- Integrates with OAuth2 and Passkey authentication

### Route Protection

- **Index page (`/`)**: Uses `Option<AuthUser>` to show different content for authenticated vs anonymous users
- **Protected page (`/protected`)**: Uses `AuthUser` extractor which automatically redirects to `/login` if not authenticated

### JavaScript APIs

The custom login page uses these JavaScript functions:

| Function | Description |
|----------|-------------|
| `oauth2.openPopup('login')` | Sign in with OAuth2 |
| `oauth2.openPopup('create_user')` | Create account with OAuth2 |
| `startAuthentication()` | Sign in with Passkey |
| `showRegistrationModal('create_user')` | Create account with Passkey |

## File Structure

```
demo-custom-login/
├── src/
│   ├── main.rs          # Routes and handlers
│   └── server.rs        # HTTP/HTTPS server setup
├── templates/
│   ├── login.j2         # Custom login page
│   ├── index_anon.j2    # Index for anonymous users
│   ├── index_user.j2    # Index for authenticated users
│   └── protected.j2     # Protected page
├── self_signed_certs/   # TLS certificates
├── Cargo.toml
└── README.md
```

## Learn More

See the [Custom Login Page Guide](../docs/src/integration/custom-pages.md) for detailed documentation.
