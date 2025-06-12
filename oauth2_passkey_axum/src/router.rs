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
    Router::new()
        .nest("/oauth2", super::oauth2::router())
        .nest("/passkey", super::passkey::router())
        .nest("/user", super::user::router())
        .nest("/admin", super::admin::router())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth2_passkey_router() {
        // Create the router
        let _router = oauth2_passkey_router();

        // We can't easily test the exact routes in a unit test,
        // but we can verify the router is created successfully without panicking
        // If we get here without panicking, the test passes
        assert!(true);
    }

    /// Test the structure of the router to ensure it has the expected nested routes
    /// This test checks that the router contains the expected paths
    /// without validating the actual handlers or functionality.
    /// This is a basic structural test that ensures the router is set up correctly.
    #[test]
    fn test_router_structure() {
        // This test verifies the basic structure of the router
        // by checking that it has the expected nested routes

        // Create the router
        let router = oauth2_passkey_router();

        // Convert to a string representation for basic inspection
        let router_debug = format!("{:?}", router);

        // Check that all expected route paths are present
        // This is a basic structural test that doesn't validate the handlers
        let expected_paths = ["/oauth2", "/passkey", "/user", "/admin"];

        for path in expected_paths {
            assert!(
                router_debug.contains(path),
                "Router is missing expected path: {}",
                path
            );
        }
    }
}
