# Basic Setup

This chapter explains how to integrate oauth2-passkey into your Axum application.

## Axum Integration

### Basic Setup

```rust,ignore
use axum::{Router, routing::get};
use oauth2_passkey_axum::{init, oauth2_passkey_router, O2P_ROUTE_PREFIX, AuthUser}; // [1]

async fn protected(user: AuthUser) -> String { // [2]
    format!("Hello, {}!", user.label)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init().await?; // [3]

    let app = Router::new()
        .route("/", get(|| async { "Public page" }))
        .route("/protected", get(protected))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router()); // [4]

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

### Key Components

| | Component | Description |
|-----|-----------|-------------|
|[1]| `use` statement | Imports the necessary components from `oauth2_passkey_axum`. |
|[2]| `AuthUser` | Axum extractor for authenticated user information. |
|[3]| `init()` | Initializes database and cache connections. Must be called before serving requests. |
|[4]| `O2P_ROUTE_PREFIX`, `oauth2_passkey_router()` | Mount auth routes at prefix (default: `/o2p`). |

### Protected Routes

Use `AuthUser` as an extractor to require authentication:

```rust,ignore
use oauth2_passkey_axum::AuthUser;

// Requires authentication - redirects to login if not authenticated
async fn dashboard(user: AuthUser) -> String {
    format!("Welcome, {}! (user_id: {})", user.label, user.user_id)
}

// AuthUser fields:
// - user_id: Unique user identifier
// - label: Display name
// - account: Account identifier
// - csrf_token: CSRF token for forms
// - is_admin: Whether user has admin privileges
```

For more protection methods (optional authentication, middleware-based protection), see [Route Protection](route-protection.md).

### Available Endpoints

The `oauth2_passkey_router()` provides these endpoints under `O2P_ROUTE_PREFIX`:

| Endpoint | Description |
|----------|-------------|
| `/oauth2/login` | Start Google OAuth2 login |
| `/oauth2/authorized` | OAuth2 callback (redirect URI) |
| `/passkey/register/start` | Start passkey registration |
| `/passkey/register/finish` | Complete passkey registration |
| `/passkey/auth/start` | Start passkey authentication |
| `/passkey/auth/finish` | Complete passkey authentication |
| `/user/summary` | User profile and credential management |
| `/admin/list_users` | Admin user list (requires admin) |
| `/logout` | End session |
