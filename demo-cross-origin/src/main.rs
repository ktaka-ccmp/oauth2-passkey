//! Cross-Origin Same-Site Demo (Pattern 2)
//!
//! Demonstrates how a **separate API server** can validate session cookies
//! issued by the Auth Server, using cookie domain sharing.
//!
//! # Architecture
//!
//! ```text
//! Auth Server (auth.example.local:3000)
//!   ├── Frontend (this demo's UI)
//!   ├── oauth2_passkey (OAuth2 + Passkey authentication)
//!   └── Issues Cookie: Domain=.example.local
//!
//! API Server (api.example.local:3001)
//!   ├── Business logic endpoints (/api/*)
//!   ├── Validates same session Cookie
//!   └── CORS enabled for Auth Server origin
//! ```
//!
//! # Key Points
//!
//! 1. **Auth Server**: Uses `oauth2_passkey_full_router()` for complete auth
//! 2. **API Server**: Separate server that only validates cookies (no auth routes)
//! 3. **Cookie Domain**: `SESSION_COOKIE_DOMAIN=.example.local` enables sharing
//! 4. **CORS**: Only needed on API Server (Auth Server is Same-Origin with frontend)
//!
//! # Setup
//!
//! 1. Add to /etc/hosts:
//!    ```
//!    127.0.0.1 auth.example.local api.example.local
//!    ```
//!
//! 2. Configure `.env` (copy from `.env.example`)
//!
//! 3. Start both servers:
//!    ```bash
//!    cd demo-cross-origin && cargo run
//!    ```
//!
//! 4. Open http://auth.example.local:3000

use askama::Template;
use axum::{
    Extension, Json, Router,
    http::StatusCode,
    middleware::from_fn,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use dotenvy::dotenv;
use serde::Serialize;
use std::sync::LazyLock;

use oauth2_passkey_axum::{
    AuthUser, O2P_CUSTOM_CSS_URL, O2P_ROUTE_PREFIX, cors_layer, is_authenticated_user_401,
    oauth2_passkey_full_router,
};

mod server;
use crate::server::{init_tracing, spawn_http_server};

// =============================================================================
// Configuration
// =============================================================================

/// API server origin (e.g., "http://api.example.local:3001")
/// This is where the frontend will make cross-origin requests to.
pub static API_ORIGIN: LazyLock<String> = LazyLock::new(|| {
    std::env::var("API_ORIGIN").unwrap_or_else(|_| "http://api.example.local:3001".to_string())
});

/// Cookie domain for cross-subdomain sharing
pub static COOKIE_DOMAIN: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_DOMAIN").unwrap_or_else(|_| ".example.local".to_string())
});

// =============================================================================
// Auth Server Templates
// =============================================================================

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate<'a> {
    prefix: &'a str,
    custom_css_url: Option<&'a str>,
    authenticated: bool,
    user_account: &'a str,
    auth_origin: &'a str,
    api_origin: &'a str,
}

// =============================================================================
// Auth Server Handlers
// =============================================================================

/// Main page - shows authentication status and API test buttons
async fn index(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    let auth_origin =
        std::env::var("ORIGIN").unwrap_or_else(|_| "http://auth.example.local:3000".to_string());

    let (authenticated, user_account) = match &user {
        Some(u) => (true, u.account.as_str()),
        None => (false, ""),
    };

    let template = IndexTemplate {
        prefix: O2P_ROUTE_PREFIX.as_str(),
        custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
        authenticated,
        user_account,
        auth_origin: &auth_origin,
        api_origin: API_ORIGIN.as_str(),
    };

    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// =============================================================================
// API Handlers
// =============================================================================

#[derive(Serialize)]
struct UserInfo {
    account: String,
    label: String,
}

/// Public endpoint - shows whether the cookie-based auth works cross-origin
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
        "server": "API",
        "endpoint": "/api/info",
        "authenticated": authenticated,
        "user": user_info,
        "note": "Cookie issued by Auth Server is validated here on API server"
    }))
}

/// Protected endpoint - requires valid session cookie
/// Uses middleware `is_authenticated_user_401` for authentication (returns 401, not redirect)
async fn resource_protected(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Json(serde_json::json!({
        "server": "API",
        "endpoint": "/api/protected",
        "authenticated": true,
        "message": format!("Hello, {}! Cross-origin cookie sharing works!", user.account),
        "user": {
            "account": user.account,
            "label": user.label,
        }
    }))
}

/// Health check
async fn resource_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "server": "API",
        "status": "ok"
    }))
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing("demo_cross_origin");

    if std::env::var("DEMO_CROSS_ORIGIN_SKIP_DOTENV").is_err() {
        dotenv().ok();
    }
    oauth2_passkey_axum::init().await?;

    // Get ports from environment
    let auth_port: u16 = std::env::var("AUTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let api_port: u16 = std::env::var("API_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);

    // =========================================================================
    // Auth Server (auth.example.local:3000)
    // - Frontend UI (index page)
    // - Full oauth2_passkey authentication (OAuth2 + Passkey)
    // - No CORS needed (Same-Origin with frontend)
    // =========================================================================
    let auth_route = Router::new()
        .route("/", get(index))
        .merge(oauth2_passkey_full_router());

    // =========================================================================
    // API Server (api.example.local:3001)
    // - Business logic endpoints only
    // - Validates session cookie (issued by Auth Server)
    // - CORS required for cross-origin requests from frontend
    // =========================================================================
    let api_route = Router::new()
        .route("/api/info", get(resource_info))
        .route("/api/health", get(resource_health))
        // Protected route uses middleware that returns 401 (not redirect)
        .route(
            "/api/protected",
            get(resource_protected).layer(from_fn(is_authenticated_user_401)),
        );

    // Apply CORS layer
    let api_route = if let Some(cors) = cors_layer() {
        tracing::info!("CORS enabled on API server");
        api_route.layer(cors)
    } else {
        tracing::warn!("CORS not configured! Set CORS_ALLOWED_ORIGINS in .env");
        api_route
    };

    // =========================================================================
    // Startup
    // =========================================================================
    let auth_origin =
        std::env::var("ORIGIN").unwrap_or_else(|_| "http://localhost:3001".to_string());

    tracing::info!("");
    tracing::info!("=== Cross-Origin Same-Site Demo (Pattern 2) ===");
    tracing::info!("");
    tracing::info!("Auth Server:     {}", auth_origin);
    tracing::info!("  - Frontend + OAuth2/Passkey authentication");
    if !COOKIE_DOMAIN.is_empty() {
        tracing::info!("  - Cookie Domain: {}", *COOKIE_DOMAIN);
    }
    tracing::info!("");
    tracing::info!("API Server:      {}", *API_ORIGIN);
    tracing::info!("  - Cross-origin endpoints (/api/*)");
    tracing::info!("  - Validates session cookie from Auth Server");
    tracing::info!("");
    tracing::info!("Open: {}", auth_origin);
    tracing::info!("================================================");

    // Spawn both HTTP servers
    let auth_server = spawn_http_server(auth_port, auth_route);
    let api_server = spawn_http_server(api_port, api_route);
    tokio::try_join!(auth_server, api_server)?;

    Ok(())
}
