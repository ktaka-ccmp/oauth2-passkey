# Server Setup

This guide covers server setup patterns for running OAuth2/Passkey authentication, based on the `demo-both` application.

## Overview

A typical setup runs both HTTP and HTTPS servers:
- **HTTPS (port 3443)**: Primary server with TLS for production and local development
- **HTTP (port 3001)**: Secondary server for tunnels and reverse proxies

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

## Self-Signed Certificate Setup

Each demo includes a `gen_certs.sh` script that generates certificates with proper SANs:

```bash
cd self_signed_certs
./gen_certs.sh
```

This creates `cert.pem` and `key.pem` valid for 10 years with localhost and 127.0.0.1 as SANs.

Load certificates with `RustlsConfig`:

```rust,ignore
use axum_server::tls_rustls::RustlsConfig;

let config = RustlsConfig::from_pem_file(
    format!("{}/self_signed_certs/cert.pem", env!("CARGO_MANIFEST_DIR")),
    format!("{}/self_signed_certs/key.pem", env!("CARGO_MANIFEST_DIR")),
)
.await
.expect("Failed to load TLS certificates");
```

## HTTP and HTTPS Servers

### HTTP Server

Spawn HTTP server for tunnel/proxy access:

```rust,ignore
use axum::Router;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

pub(crate) fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("HTTP server listening on {}", addr);
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}
```

### HTTPS Server

Spawn HTTPS server with TLS:

```rust,ignore
pub(crate) async fn spawn_https_server(port: u16, app: Router) -> JoinHandle<()> {
    let config = RustlsConfig::from_pem_file(
        format!("{}/self_signed_certs/cert.pem", env!("CARGO_MANIFEST_DIR")),
        format!("{}/self_signed_certs/key.pem", env!("CARGO_MANIFEST_DIR")),
    )
    .await
    .expect("Failed to load TLS certificates");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("HTTPS server listening on {}", addr);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}
```

## Why HTTP Port is Needed

The HTTP server enables:

1. **Development tunnels**: Services like ngrok or cloudflared terminate TLS and forward HTTP to your app
2. **Reverse proxies**: Nginx/Caddy handle TLS termination, proxying HTTP internally
3. **Load balancers**: Cloud load balancers often communicate with backends over HTTP
4. **Container deployments**: Kubernetes ingress controllers manage TLS externally

When using tunnels, set `ORIGIN` to the tunnel's HTTPS URL while the tunnel connects to your HTTP port.

Example with cloudflared:

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
use axum_server::tls_rustls::RustlsConfig;
use askama::Template;
use dotenvy::dotenv;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oauth2_passkey_axum::{AuthUser, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, oauth2_passkey_router};

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
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

async fn spawn_https_server(port: u16, app: Router) -> JoinHandle<()> {
    let config = RustlsConfig::from_pem_file(
        format!("{}/self_signed_certs/cert.pem", env!("CARGO_MANIFEST_DIR")),
        format!("{}/self_signed_certs/key.pem", env!("CARGO_MANIFEST_DIR")),
    )
    .await
    .expect("Failed to load TLS certificates");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("HTTPS server listening on {}", addr);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
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
    // Install rustls crypto provider (required for TLS)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    // Initialize logging
    init_tracing("my-app");

    // Load environment variables
    dotenv().ok();

    // Initialize oauth2-passkey library
    oauth2_passkey_axum::init().await?;

    // Build application router
    let app = Router::new()
        .route("/", get(index))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // Start both servers
    let http_server = spawn_http_server(3001, app.clone());
    let https_server = spawn_https_server(3443, app).await;

    // Wait for both servers
    tokio::try_join!(http_server, https_server)?;
    Ok(())
}
```

## Required Dependencies

Add these to your `Cargo.toml`:

```toml
[dependencies]
axum = "0.8"
axum-server = { version = "0.7", features = ["tls-rustls"] }
rustls = "0.23"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy = "0.15"
askama = "0.12"
oauth2_passkey_axum = { version = "0.1", features = ["oauth2", "passkey"] }
```

## Startup Sequence

1. Install rustls crypto provider
2. Initialize tracing
3. Load environment variables with `dotenv()`
4. Call `oauth2_passkey_axum::init().await`
5. Build router with `oauth2_passkey_router()`
6. Start HTTP and HTTPS servers
