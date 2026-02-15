# Server Setup

This guide covers server setup patterns for running OAuth2/Passkey authentication, based on the demo applications.

## Overview

Demo applications run HTTP servers on port 3001. For production deployments requiring HTTPS:

- **localhost development**: WebAuthn works over HTTP (localhost is a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts))
- **Production**: Use a reverse proxy (nginx/Caddy) to handle TLS termination

## Tracing Initialization

Initialize tracing before other setup to capture all logs:

```rust,ignore
pub(crate) fn init_tracing(app_name: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            #[cfg(debug_assertions)]
            {
                format!(
                    "oauth2_passkey_axum=trace,oauth2_passkey=trace,{app_name}=trace,info"
                ).into()
            }

            #[cfg(not(debug_assertions))]
            {
                "info".into()
            }
        });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
```

### Default Log Levels

| Build   | Command                 | Default Level                                |
|---------|-------------------------|----------------------------------------------|
| Debug   | `cargo run`             | oauth2_passkey=trace, app=trace, others=info |
| Release | `cargo build --release` | info                                         |

Override with `RUST_LOG`:

```bash
RUST_LOG=debug cargo run
```

## HTTP Server

Spawn HTTP server using `tokio::net::TcpListener`:

```rust,ignore
use axum::Router;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

pub(crate) fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("HTTP server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    })
}
```

## Production HTTPS Setup

For production, use a reverse proxy to handle TLS termination:

### Caddy Example

```caddyfile
example.com {
    reverse_proxy localhost:3001
}
```

### nginx Example

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

When using a reverse proxy:
- Set `ORIGIN` to your HTTPS URL (e.g., `https://example.com`)
- The proxy forwards to your HTTP server on port 3001

## Development Tunnels

For remote testing, use tunnel services like ngrok or cloudflared:

- Tunnel URL: `https://myapp.trycloudflare.com`
- Set `ORIGIN='https://myapp.trycloudflare.com'`
- Tunnel forwards to `http://localhost:3001`

## Complete main.rs Example

```rust,ignore
use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum::response::Html;
use askama::Template;
use dotenvy::dotenv;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oauth2_passkey_axum::{AuthUser, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, oauth2_passkey_full_router};

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate<'a> {
    message: &'a str,
    prefix: &'a str,
}

async fn index(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => {
            let template = IndexTemplate {
                message: "Welcome! You are authenticated.",
                prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            match template.render() {
                Ok(html) => Ok(Html(html).into_response()),
                Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            }
        }
        None => Ok(Redirect::to(O2P_LOGIN_URL.as_str()).into_response()),
    }
}

fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("HTTP server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    })
}

fn init_tracing(app_name: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            #[cfg(debug_assertions)]
            {
                format!(
                    "oauth2_passkey_axum=trace,oauth2_passkey=trace,{app_name}=trace,info"
                ).into()
            }
            #[cfg(not(debug_assertions))]
            {
                "info".into()
            }
        });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_tracing("my-app");

    // Load environment variables
    dotenv().ok();

    // Initialize oauth2-passkey library
    oauth2_passkey_axum::init().await?;

    // Build application router
    let app = Router::new()
        .route("/", get(index))
        .merge(oauth2_passkey_full_router());

    // Start server
    spawn_http_server(3001, app).await?;
    Ok(())
}
```

## TLS Certificates (bundled-tls)

The library makes HTTPS requests to OAuth2/OIDC providers (e.g., Google) for token exchange and JWKS fetching. By default, it uses the system's CA certificates for TLS verification.

For minimal container deployments (scratch or alpine Docker images) where system certificates are not available, enable the `bundled-tls` feature to bundle Mozilla root certificates:

```toml
[dependencies]
oauth2-passkey-axum = { version = "0.2", features = ["bundled-tls"] }
```

This bundles certificates from the `webpki-roots` crate and configures ALPN protocol negotiation for proper TLS handshakes.

**When to use `bundled-tls`**:
- Scratch Docker images (no filesystem, no `/etc/ssl/certs/`)
- Alpine Linux containers without `ca-certificates` package
- Any environment where system CA certificates are missing

**When NOT needed**:
- Standard Linux distributions with `ca-certificates` installed
- Docker images based on Debian, Ubuntu, or similar

Example minimal Dockerfile:

```dockerfile
FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --features bundled-tls

FROM scratch
COPY --from=builder /app/target/release/myapp /
ENTRYPOINT ["/myapp"]
```

## Required Dependencies

Add these to your `Cargo.toml`:

```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy = "0.15"
askama = "0.12"
oauth2-passkey-axum = "0.2"
```

## Startup Sequence

1. Initialize tracing
2. Load environment variables with `dotenv()`
3. Call `oauth2_passkey_axum::init().await`
4. Build router with `oauth2_passkey_full_router()`
5. Start HTTP server
