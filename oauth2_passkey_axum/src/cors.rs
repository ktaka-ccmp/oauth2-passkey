//! CORS configuration support for cross-origin deployments.
//!
//! This module provides configurable CORS (Cross-Origin Resource Sharing) support
//! for Pattern 2 deployments where the frontend and API are on different subdomains.
//!
//! # Configuration
//!
//! CORS is configured via environment variables:
//!
//! - `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed origins, or `*` for any origin
//! - `CORS_ALLOW_CREDENTIALS`: Set to `true` to allow credentials (cookies) in cross-origin requests
//!
//! # Example
//!
//! ```bash
//! # Allow requests from app.example.com with credentials
//! CORS_ALLOWED_ORIGINS='https://app.example.com'
//! CORS_ALLOW_CREDENTIALS=true
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use axum::Router;
//! use oauth2_passkey_axum::{oauth2_passkey_full_router, cors_layer};
//!
//! let app = Router::new()
//!     .merge(oauth2_passkey_full_router());
//!
//! // Apply CORS layer if configured
//! let app = if let Some(cors) = cors_layer() {
//!     app.layer(cors)
//! } else {
//!     app
//! };
//! ```

use std::sync::LazyLock;

use http::{HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Comma-separated list of allowed origins for CORS.
///
/// Examples:
/// - Single origin: `https://app.example.com`
/// - Multiple origins: `https://app.example.com,https://admin.example.com`
/// - Any origin: `*` (not recommended for production with credentials)
pub static CORS_ALLOWED_ORIGINS: LazyLock<Option<Vec<String>>> = LazyLock::new(|| {
    std::env::var("CORS_ALLOWED_ORIGINS").ok().map(|s| {
        s.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
});

/// Whether to allow credentials (cookies) in cross-origin requests.
///
/// Set to `true` for cookie-based authentication across origins.
/// When enabled, `CORS_ALLOWED_ORIGINS` cannot be `*`.
pub static CORS_ALLOW_CREDENTIALS: LazyLock<bool> =
    LazyLock::new(|| match std::env::var("CORS_ALLOW_CREDENTIALS") {
        Err(_) => false,
        Ok(val) => match val.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => panic!("CORS_ALLOW_CREDENTIALS='{val}' is invalid. Valid values: true, false"),
        },
    });

/// Creates a CORS layer based on environment configuration.
///
/// Returns `None` if `CORS_ALLOWED_ORIGINS` is not set.
///
/// # Example
///
/// ```rust,no_run
/// use axum::Router;
/// use oauth2_passkey_axum::cors_layer;
///
/// let app: Router = Router::new()
///     .route("/", axum::routing::get(|| async { "Hello" }));
///
/// // Apply CORS if configured
/// let app = if let Some(cors) = cors_layer() {
///     app.layer(cors)
/// } else {
///     app
/// };
/// ```
pub fn cors_layer() -> Option<CorsLayer> {
    let origins = CORS_ALLOWED_ORIGINS.as_ref()?;

    if origins.is_empty() {
        return None;
    }

    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::AUTHORIZATION,
            HeaderName::from_static("x-csrf-token"),
        ]);

    // Set credentials
    if *CORS_ALLOW_CREDENTIALS {
        layer = layer.allow_credentials(true);
    }

    // Set allowed origins
    if origins.len() == 1 && origins[0] == "*" {
        if *CORS_ALLOW_CREDENTIALS {
            tracing::warn!(
                "CORS_ALLOWED_ORIGINS='*' with CORS_ALLOW_CREDENTIALS=true is not supported. \
                 Using permissive origin matching instead."
            );
            // When credentials are needed, we can't use Any, so we use a permissive predicate
            layer = layer.allow_origin(AllowOrigin::predicate(|_origin, _request_parts| true));
        } else {
            layer = layer.allow_origin(tower_http::cors::Any);
        }
    } else {
        let origins: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();

        if origins.is_empty() {
            tracing::warn!("No valid origins in CORS_ALLOWED_ORIGINS");
            return None;
        }

        layer = layer.allow_origin(origins);
    }

    Some(layer)
}

#[cfg(test)]
mod tests;
