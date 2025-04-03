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
pub fn oauth2_passkey_router() -> Router {
    let mut user_router = super::user::router();
    #[cfg(feature = "default-pages")]
    {
        user_router = user_router.merge(super::default_pages::router());
    }

    Router::new()
        .nest("/oauth2", super::oauth2::router())
        .nest("/passkey", super::passkey::router())
        .nest("/user", user_router)
}
