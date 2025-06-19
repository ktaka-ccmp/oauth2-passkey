# Framework Integrations for oauth2-passkey

This document provides information on available framework integrations for the `oauth2-passkey` core library and guidance for creating new integrations.

## Available Framework Integrations

### Axum Integration: oauth2-passkey-axum

The [oauth2-passkey-axum](https://crates.io/crates/oauth2-passkey-axum) crate provides ready-to-use Axum handlers, middleware, and components that integrate with the core library.

**Key features:**

* Drop-in Axum router with all authentication routes
* Route protection middleware
* CSRF token handling
* Admin and user interfaces
* Static assets for authentication pages

**Usage:**

```rust
use axum::{Router, routing::get};
use oauth2_passkey_axum::{init, oauth2_passkey_router, O2P_ROUTE_PREFIX, AuthUser};

// Authenticated route example
async fn protected(user: AuthUser) -> String {
    format!("Hello, {}!", user.label)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication
    init().await?;

    // Create application router with auth routes
    let app = Router::new()
        .route("/", get(|| async { "Public page" }))
        .route("/protected", get(protected))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
        
    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

For complete examples, see:
- [OAuth2 Demo](../demo-oauth2/)
- [Passkey Demo](../demo-passkey/)
- [Combined Demo](../demo01/)

## Relationship Between Core and Framework Integration

The relationship between `oauth2-passkey` (core) and `oauth2-passkey-axum` (integration) follows a clear separation of concerns:

| `oauth2-passkey` (Core) | `oauth2-passkey-axum` (Integration) |
|------------------------|-----------------------------------|
| Framework-agnostic authentication logic | Axum-specific handlers and middleware |
| Database/cache operations | Route configuration and HTTP interface |
| Security implementation | User interface components |
| User identity management | Error handling and HTTP responses |

This architecture allows the core authentication logic to remain decoupled from any specific web framework while providing convenient integration points.

## Creating New Framework Integrations

To create integrations for other web frameworks (Rocket, Actix, etc.), follow these guidelines:

1. Use the core coordination functions from `oauth2-passkey`
2. Create framework-specific handlers that call these functions
3. Implement middleware for authentication and CSRF protection
4. Add user interface components appropriate for the framework
5. Provide clear examples and documentation

For a complete example of creating a framework integration, see the [oauth2-passkey-axum source code](https://github.com/ktaka-ccmp/oauth2-passkey/tree/main/oauth2_passkey_axum).
