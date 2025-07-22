//! Combined router for all authentication endpoints

use axum::Router;

/// Create a combined router for all authentication endpoints
///
/// This router combines the OAuth2, Passkey, and Summary endpoints under a single mount point.
/// The endpoints will be available at:
/// - {O2P_ROUTE_PREFIX}/oauth2/...
/// - {O2P_ROUTE_PREFIX}/passkey/...
/// - {O2P_ROUTE_PREFIX}/user/...
///
/// This simplifies integration by requiring only a single router to be mounted in the application.
///
/// # Adding HTTP Tracing
///
/// If you want HTTP request/response tracing, you can add tower-http's TraceLayer yourself:
///
/// ```rust,no_run
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
}
