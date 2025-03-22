//! Combined router for all authentication endpoints

use axum::Router;
use oauth2_passkey::{OAUTH2_SUB_ROUTE, PASSKEY_SUB_ROUTE, SUMMARY_SUB_ROUTE};

/// Create a combined router for all authentication endpoints
///
/// This router combines the OAuth2, Passkey, and Summary endpoints under a single mount point.
/// The endpoints will be available at:
/// - {O2P_ROUTE_PREFIX}/oauth2/...
/// - {O2P_ROUTE_PREFIX}/passkey/...
/// - {O2P_ROUTE_PREFIX}/summary/...
///
/// This simplifies integration by requiring only a single router to be mounted in the application.
pub fn oauth2_passkey_router() -> Router {
    Router::new()
        .nest(OAUTH2_SUB_ROUTE, super::oauth2::router())
        .nest(PASSKEY_SUB_ROUTE, super::passkey::router())
        .nest(SUMMARY_SUB_ROUTE, super::summary::router())
}
