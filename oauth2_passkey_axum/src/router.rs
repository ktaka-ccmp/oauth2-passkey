//! Combined router for all authentication endpoints

use axum::Router;
use oauth2_passkey::{O2P_ROUTE_PREFIX, get_related_origin_json};

/// Create a combined router for all authentication endpoints
///
/// This router combines the OAuth2, Passkey, and Summary endpoints under a single mount point.
/// The endpoints will be available at:
/// - {O2P_ROUTE_PREFIX}/oauth2/...
/// - {O2P_ROUTE_PREFIX}/passkey/...
/// - {O2P_ROUTE_PREFIX}/user/...
/// - {O2P_ROUTE_PREFIX}/admin/...
///
/// This simplifies integration by requiring only a single router to be mounted in the application.
///
/// # Adding HTTP Tracing
///
/// If you want HTTP request/response tracing, you can add tower-http's TraceLayer yourself:
///
/// ```text
/// use axum::Router;
/// use tower_http::trace::TraceLayer;
/// use oauth2_passkey_axum::oauth2_passkey_router;
///
/// let app = Router::new()
///     .nest("/auth", oauth2_passkey_router())
///     .layer(TraceLayer::new_for_http());
/// ```
pub fn oauth2_passkey_router() -> Router {
    Router::new()
        .nest("/oauth2", super::oauth2::router())
        .nest("/passkey", super::passkey::router())
        .nest("/user", super::user::router())
        .nest("/admin", super::admin::router())
        .nest("/themes", super::themes::router())
}

/// Creates a complete router with all authentication endpoints
///
/// This is the recommended way to add authentication to your application.
/// It includes:
/// - All auth endpoints nested under `O2P_ROUTE_PREFIX` (default: `/o2p`)
/// - The `/.well-known/webauthn` endpoint (only when `WEBAUTHN_ADDITIONAL_ORIGINS` is set)
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use oauth2_passkey_axum::oauth2_passkey_full_router;
///
/// let app = Router::new()
///     .merge(oauth2_passkey_full_router())
///     .route("/", axum::routing::get(|| async { "Hello" }));
/// ```
///
/// # Multi-Origin Setup
///
/// When `WEBAUTHN_ADDITIONAL_ORIGINS` environment variable is set with additional origins,
/// this router automatically includes the `/.well-known/webauthn` endpoint for cross-origin
/// passkey support.
///
/// For single-origin deployments (the common case), the well-known endpoint is not included.
pub fn oauth2_passkey_full_router() -> Router {
    let router = Router::new().nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // Conditionally add well-known endpoint for multi-origin setups
    // Check if there are additional origins by parsing the related origin JSON
    let has_additional_origins = get_related_origin_json()
        .ok()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
        .and_then(|v| v.get("origins")?.as_array().map(|a| a.len() > 1))
        .unwrap_or(false);

    if has_additional_origins {
        router.merge(super::passkey::passkey_well_known_router())
    } else {
        router
    }
}
