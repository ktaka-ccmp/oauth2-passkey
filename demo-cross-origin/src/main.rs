//! Demo application for Cross-Origin Same-Site cookie authentication (Pattern 2).
//!
//! This demo demonstrates how to configure oauth2-passkey for cross-origin deployments
//! where the frontend and API are on different subdomains of the same site.
//!
//! # Architecture
//!
//! ```text
//! http://auth.example.local:3000    (Auth Server + Frontend)
//!     |
//!     +-- Frontend (static files)
//!     +-- oauth2_passkey (authentication)
//!     +-- Set-Cookie: Domain=.example.local
//!
//! http://api.example.local:3001     (Resource API)
//!     |
//!     +-- Protected endpoints
//!     +-- Session validation (same Cookie)
//!     +-- CORS: Access-Control-Allow-Origin: http://auth.example.local:3000
//! ```
//!
//! # Pattern 2 Demonstration
//!
//! This demo shows how a **separate API server** can validate sessions using
//! cookies issued by the auth server. The key is:
//!
//! 1. Auth server sets `Cookie: Domain=.example.local`
//! 2. Browser sends the same cookie to `api.example.local`
//! 3. Resource API validates the cookie and authorizes the request
//!
//! # Setup
//!
//! 1. Add to /etc/hosts:
//!    ```
//!    127.0.0.1 auth.example.local
//!    127.0.0.1 api.example.local
//!    ```
//!
//! 2. Start both servers (single command):
//!    ```bash
//!    cd demo-cross-origin && cargo run
//!    ```
//!
//! 3. Open http://auth.example.local:3000 in your browser

use axum::{Json, Router, response::IntoResponse, routing::get};
use dotenvy::dotenv;
use serde::Serialize;
use tower_http::services::ServeDir;

use oauth2_passkey_axum::{AuthUser, cors_layer, oauth2_passkey_full_router};

mod server;
use crate::server::{init_tracing, spawn_http_server};

// ============================================================================
// Resource API endpoints (for api.example.local:3001)
// ============================================================================

#[derive(Serialize)]
struct UserInfo {
    account: String,
    label: String,
}

/// Public endpoint on Resource API - shows auth status
async fn resource_info(user: Option<AuthUser>) -> impl IntoResponse {
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

    Json(serde_json::json!({
        "server": "Resource API",
        "endpoint": "/api/info",
        "authenticated": authenticated,
        "user": user_info,
        "note": "This endpoint is on a DIFFERENT server than auth, but shares the same session cookie"
    }))
}

/// Protected endpoint on Resource API - requires authentication
async fn resource_protected(user: AuthUser) -> impl IntoResponse {
    Json(serde_json::json!({
        "server": "Resource API",
        "endpoint": "/api/protected",
        "message": format!("Hello, {}! You accessed a protected resource on a SEPARATE server.", user.account),
        "user": {
            "account": user.account,
            "label": user.label,
        },
        "note": "Cookie issued by auth.example.local:3000 is valid here on api.example.local:3001"
    }))
}

/// Health check for Resource API
async fn resource_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "server": "Resource API",
        "status": "ok"
    }))
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo_cross_origin");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    // Get ports from environment (or use defaults)
    let auth_port: u16 = std::env::var("AUTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let api_port: u16 = std::env::var("API_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);

    // ========================================================================
    // Auth Server (auth.example.local:3000)
    // - Frontend static files
    // - oauth2_passkey authentication endpoints
    // - No CORS needed (Same-Origin with frontend)
    // ========================================================================
    let auth_app = Router::new()
        .merge(oauth2_passkey_full_router())
        .fallback_service(ServeDir::new("frontend"));

    // ========================================================================
    // Resource API Server (api.example.local:3001)
    // - Protected business logic endpoints
    // - Session validation via Cookie (issued by Auth Server)
    // - CORS enabled for cross-origin requests from frontend
    // ========================================================================
    let resource_api = Router::new()
        .route("/api/info", get(resource_info))
        .route("/api/protected", get(resource_protected))
        .route("/api/health", get(resource_health));

    // Apply CORS layer for cross-origin requests from auth server
    let resource_api = if let Some(cors) = cors_layer() {
        tracing::info!("CORS layer enabled on Resource API");
        resource_api.layer(cors)
    } else {
        tracing::warn!("CORS not configured - cross-origin requests to Resource API will fail!");
        tracing::warn!("Set CORS_ALLOWED_ORIGINS=http://auth.example.local:3000");
        resource_api
    };

    // ========================================================================
    // Startup
    // ========================================================================
    tracing::info!("");
    tracing::info!("=== Cross-Origin Same-Site Demo (Pattern 2) ===");
    tracing::info!("");
    tracing::info!("Auth Server:     http://auth.example.local:{}", auth_port);
    tracing::info!("  - Frontend (static files)");
    tracing::info!("  - Authentication endpoints (/o2p/*)");
    tracing::info!("  - Issues Cookie with Domain=.example.local");
    tracing::info!("");
    tracing::info!("Resource API:    http://api.example.local:{}", api_port);
    tracing::info!("  - Protected endpoints (/api/*)");
    tracing::info!("  - Validates Cookie issued by Auth Server");
    tracing::info!("  - CORS enabled for auth server origin");
    tracing::info!("");
    tracing::info!("Setup: Add to /etc/hosts:");
    tracing::info!("  127.0.0.1 auth.example.local api.example.local");
    tracing::info!("");
    tracing::info!("Then open: http://auth.example.local:{}", auth_port);
    tracing::info!("================================================");

    // Spawn both servers
    let auth_server = spawn_http_server(auth_port, auth_app);
    let api_server = spawn_http_server(api_port, resource_api);

    // Wait for both servers (they run indefinitely)
    tokio::try_join!(auth_server, api_server)?;

    Ok(())
}
