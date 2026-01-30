//! Demo application for Cross-Origin Same-Site cookie authentication (Pattern 2).
//!
//! This demo demonstrates how to configure oauth2-passkey for cross-origin deployments
//! where the frontend and API are on different subdomains of the same site.
//!
//! # Architecture
//!
//! ```text
//! http://app.example.local:3000    (Frontend / SPA)
//!     |
//!     | fetch with credentials: 'include'
//!     v
//! http://api.example.local:3001    (API server with oauth2-passkey)
//!     |
//!     +-- Set-Cookie: Domain=.example.local
//!     +-- CORS: Access-Control-Allow-Origin: http://app.example.local:3000
//! ```
//!
//! # Setup
//!
//! 1. Add to /etc/hosts:
//!    ```
//!    127.0.0.1 app.example.local
//!    127.0.0.1 api.example.local
//!    ```
//!
//! 2. Start the API server:
//!    ```bash
//!    cd demo-cross-origin && cargo run
//!    ```
//!
//! 3. Serve the frontend (in another terminal):
//!    ```bash
//!    cd demo-cross-origin/frontend
//!    python -m http.server 3000 --bind 127.0.0.1
//!    ```
//!
//! 4. Open http://app.example.local:3000 in your browser

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use axum_core::response::Response;
use dotenvy::dotenv;
use serde::Serialize;
use std::sync::Arc;
use tower_http::services::ServeDir;

use oauth2_passkey_axum::{AuthUser, cors_layer, oauth2_passkey_full_router};

mod server;
use crate::server::{init_tracing, spawn_http_server};

/// Application state
#[derive(Clone)]
struct AppState {
    api_origin: String,
}

/// Response for the info endpoint
#[derive(Serialize)]
struct InfoResponse {
    message: String,
    api_origin: String,
    authenticated: bool,
    user: Option<UserInfo>,
}

#[derive(Serialize)]
struct UserInfo {
    account: String,
    label: String,
}

/// Index endpoint - returns API info
async fn index(State(state): State<Arc<AppState>>, user: Option<AuthUser>) -> impl IntoResponse {
    let (authenticated, user_info) = match user {
        Some(u) => (
            true,
            Some(UserInfo {
                account: u.account.clone(),
                label: u.label.clone(),
            }),
        ),
        None => (false, None),
    };

    Json(InfoResponse {
        message: "Cross-Origin Same-Site Demo API".to_string(),
        api_origin: state.api_origin.clone(),
        authenticated,
        user: user_info,
    })
}

/// Protected endpoint - requires authentication
async fn protected(user: AuthUser) -> impl IntoResponse {
    Json(serde_json::json!({
        "message": format!("Hello, {}! You have access to this protected resource.", user.account),
        "user": {
            "account": user.account,
            "label": user.label,
        }
    }))
}

/// Health check endpoint
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok"
    }))
}

/// Serve the frontend files for convenience
async fn serve_frontend() -> Response {
    // Redirect to the frontend server
    let body = r#"<!DOCTYPE html>
<html>
<head><title>API Server</title></head>
<body>
<h1>API Server</h1>
<p>This is the API server. The frontend is served separately.</p>
<p>Please access the frontend at: <a href="http://app.example.local:3000">http://app.example.local:3000</a></p>
<h2>Setup Instructions</h2>
<ol>
<li>Add to /etc/hosts: <code>127.0.0.1 app.example.local api.example.local</code></li>
<li>Start frontend server: <code>cd frontend && python -m http.server 3000 --bind 127.0.0.1</code></li>
<li>Open <a href="http://app.example.local:3000">http://app.example.local:3000</a></li>
</ol>
</body>
</html>"#;

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(axum::body::Body::from(body))
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo_cross_origin");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    // Get API origin from environment
    let api_origin =
        std::env::var("ORIGIN").unwrap_or_else(|_| "http://api.example.local:3001".to_string());

    let state = Arc::new(AppState {
        api_origin: api_origin.clone(),
    });

    // Build the router
    // Note: Routes with state must use .with_state() before merging with stateless routers
    let app_routes = Router::new()
        .route("/", get(serve_frontend))
        .route("/api/info", get(index))
        .route("/api/protected", get(protected))
        .route("/api/health", get(health))
        .nest_service("/frontend", ServeDir::new("frontend"))
        .with_state(state);

    // Merge with oauth2_passkey router (which has no state requirement)
    let app = app_routes.merge(oauth2_passkey_full_router());

    // Apply CORS layer if configured
    let app = if let Some(cors) = cors_layer() {
        tracing::info!("CORS layer enabled");
        app.layer(cors)
    } else {
        tracing::warn!("CORS layer not configured - cross-origin requests may fail");
        app
    };

    tracing::info!("API server starting on http://0.0.0.0:3001");
    tracing::info!("API origin: {}", api_origin);
    tracing::info!("");
    tracing::info!("=== Setup Instructions ===");
    tracing::info!("1. Add to /etc/hosts:");
    tracing::info!("   127.0.0.1 app.example.local api.example.local");
    tracing::info!("");
    tracing::info!("2. Start the frontend server (in another terminal):");
    tracing::info!(
        "   cd demo-cross-origin/frontend && python -m http.server 3000 --bind 127.0.0.1"
    );
    tracing::info!("");
    tracing::info!("3. Open http://app.example.local:3000 in your browser");
    tracing::info!("==========================");

    // Spawn HTTP server only (no HTTPS for local demo)
    let http_server = spawn_http_server(3001, app);
    http_server.await?;

    Ok(())
}
