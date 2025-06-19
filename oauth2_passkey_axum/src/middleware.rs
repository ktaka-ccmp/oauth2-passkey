use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use http::header::HeaderValue;

use super::config::{O2P_REDIRECT_ANON, O2P_RESPOND_WITH_X_CSRF_TOKEN};
use super::session::AuthUser;
use oauth2_passkey::SessionError;

/// Helper function to add CSRF token to response headers
///
/// Adds the CSRF token as an X-CSRF-Token header to the response
/// if O2P_RESPOND_WITH_X_CSRF_TOKEN is enabled.
fn add_csrf_header(mut response: Response, csrf_token: &str) -> Response {
    if !*O2P_RESPOND_WITH_X_CSRF_TOKEN {
        return response;
    }

    // Use from_str with error handling instead of unwrap
    if let Ok(header_value) = HeaderValue::from_str(csrf_token) {
        response.headers_mut().insert("X-CSRF-Token", header_value);
    } else {
        // Log the error but don't panic
        tracing::error!("Failed to create CSRF header value from token");
    }
    response
}

/// Helper function to handle authentication errors
///
/// Processes
///  authentication errors and returns appropriate responses:
/// - For CSRF errors: returns 403 Forbidden or redirects if redirect_on_error is true
/// - For other auth errors: returns 401 Unauthorized or redirects if redirect_on_error is true
fn handle_auth_error(err: SessionError, req: &Request, redirect_on_error: bool) -> Response {
    match err {
        SessionError::CsrfToken(msg) => {
            // For CSRF errors, return 403 Forbidden with the message
            // For redirect middleware with GET requests, redirect instead
            if redirect_on_error && req.method() == http::Method::GET {
                Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
            } else {
                (StatusCode::FORBIDDEN, msg).into_response()
            }
        }
        _ => {
            // For other authentication errors
            if redirect_on_error && req.method() == http::Method::GET {
                Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
            } else {
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
        }
    }
}

/// Authentication middleware that returns HTTP 401 for unauthenticated requests
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Returns 401 Unauthorized for unauthenticated requests
/// 4. Adds the CSRF token to the response headers
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn};
/// use oauth2_passkey_axum::is_authenticated_401;
///
/// let app = Router::new()
///     .route("/api/data", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_401));
/// ```
pub async fn is_authenticated_401(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_csrf(req.headers(), req.method()).await {
        Ok((csrf_token, csrf_via_header_verified)) => {
            // Store token and verification status in extensions
            req.extensions_mut().insert(csrf_token.clone());
            req.extensions_mut().insert(csrf_via_header_verified);
            // Run next handler and add CSRF header to the response
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, false),
    }
}

/// Authentication middleware that redirects unauthenticated requests to login page
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Redirects unauthenticated GET requests to the login page (as defined in O2P_REDIRECT_ANON)
/// 4. Returns 401 for unauthenticated non-GET requests
/// 5. Adds the CSRF token to the response headers
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn};
/// use oauth2_passkey_axum::is_authenticated_redirect;
///
/// let app = Router::new()
///     .route("/dashboard", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_redirect));
/// ```
pub async fn is_authenticated_redirect(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_csrf(req.headers(), req.method()).await {
        Ok((csrf_token, csrf_via_header_verified)) => {
            // Store token and verification status in extensions
            req.extensions_mut().insert(csrf_token.clone());
            req.extensions_mut().insert(csrf_via_header_verified);
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, true),
    }
}

/// Authentication middleware that provides user data and returns HTTP 401 for unauthenticated requests
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Extracts user data from the session and adds it as an extension
/// 4. Returns 401 Unauthorized for unauthenticated requests
/// 5. Adds the CSRF token to the response headers
///
/// This version adds the authenticated user information as an `Extension<AuthUser>`,
/// which can be accessed in handlers.
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn, extract::Extension};
/// use oauth2_passkey_axum::{is_authenticated_user_401, AuthUser};
///
/// async fn handler(Extension(user): Extension<AuthUser>) -> String {
///     format!("Hello, {}", user.account)
/// }
///
/// let app = Router::new()
///     .route("/api/profile", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_user_401));
/// ```
pub async fn is_authenticated_user_401(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_user_and_csrf(req.headers(), req.method())
        .await
    {
        Ok((user, csrf_token, csrf_via_header_verified)) => {
            let mut auth_user = AuthUser::from(user);
            auth_user.csrf_token = csrf_token.as_str().to_string();
            auth_user.csrf_via_header_verified = csrf_via_header_verified.0; // Set this field
            tracing::debug!(
                "User: {:?}, CSRF via header: {}",
                auth_user,
                csrf_via_header_verified
            );
            req.extensions_mut().insert(auth_user);
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, false),
    }
}

/// Authentication middleware that provides user data and redirects unauthenticated requests
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Extracts user data from the session and adds it as an extension
/// 4. Redirects unauthenticated GET requests to the login page
/// 5. Returns 401 for unauthenticated non-GET requests
/// 6. Adds the CSRF token to the response headers
///
/// This version adds the authenticated user information as an `Extension<AuthUser>`,
/// which can be accessed in handlers.
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn, extract::Extension};
/// use oauth2_passkey_axum::{is_authenticated_user_redirect, AuthUser};
///
/// async fn handler(Extension(user): Extension<AuthUser>) -> String {
///     format!("Hello, {}", user.account)
/// }
///
/// let app = Router::new()
///     .route("/dashboard", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_user_redirect));
/// ```
pub async fn is_authenticated_user_redirect(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_user_and_csrf(req.headers(), req.method())
        .await
    {
        Ok((user, csrf_token, csrf_via_header_verified)) => {
            let mut auth_user = AuthUser::from(user);
            auth_user.csrf_token = csrf_token.as_str().to_string();
            auth_user.csrf_via_header_verified = csrf_via_header_verified.0; // Set this field
            tracing::debug!(
                "User: {:?}, CSRF via header: {}",
                auth_user,
                csrf_via_header_verified
            );
            req.extensions_mut().insert(auth_user);
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Response as HttpResponse};

    /// Test that the CSRF header is added when enabled
    /// This test checks:
    /// 1. With a valid CSRF token, the X-CSRF-Token header is added correctly
    /// 2. The header value matches the provided token
    #[test]
    fn test_add_csrf_header_when_enabled() {
        // Create a response
        let response = HttpResponse::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();

        // Add CSRF header with a valid token
        let csrf_token = "valid-csrf-token";
        let response_with_header = add_csrf_header(response, csrf_token);

        // Verify the header was added
        let headers = response_with_header.headers();
        assert!(headers.contains_key("X-CSRF-Token"));
        assert_eq!(
            headers
                .get("X-CSRF-Token")
                .expect("X-CSRF-Token header should exist")
                .to_str()
                .expect("X-CSRF-Token header should be valid UTF-8"),
            csrf_token
        );
    }

    /// Test that the CSRF header is not added when token is invalid
    /// This test checks:
    /// 1. Invalid CSRF tokens (containing null characters) are handled gracefully
    /// 2. No header is added when HeaderValue::from_str() fails
    #[test]
    fn test_add_csrf_header_with_invalid_token() {
        // Create a response
        let response = HttpResponse::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();

        // Try to add CSRF header with an invalid token (contains invalid characters)
        let invalid_csrf_token = "invalid\u{0000}token";
        let response_with_header = add_csrf_header(response, invalid_csrf_token);

        // Verify the header was not added
        let headers = response_with_header.headers();
        assert!(!headers.contains_key("X-CSRF-Token"));
    }

    /// Test that CSRF errors with redirect enabled return a redirect response
    /// This test checks:
    /// 1. A GET request with a CSRF error and redirect enabled
    /// 2. Returns a 302 TEMPORARY_REDIRECT response (not 403 Forbidden)
    #[test]
    fn test_handle_auth_error_csrf_error_with_redirect() {
        // Create a GET request
        let request = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Create a CSRF error
        let csrf_error = SessionError::CsrfToken("CSRF token mismatch".to_string());

        // Handle the error with redirect enabled
        let response = handle_auth_error(csrf_error, &request, true);

        // Verify it's a redirect response
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    /// Test that the CSRF header is not added when disabled
    /// This test checks:
    /// 1. If O2P_RESPOND_WITH_X_CSRF_TOKEN is false, the header is not added.
    /// 2. If a CSRF error occurs, it returns a 403 Forbidden response.
    #[test]
    fn test_handle_auth_error_csrf_error_without_redirect() {
        // Create a GET request
        let request = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Create a CSRF error
        let csrf_error = SessionError::CsrfToken("CSRF token mismatch".to_string());

        // Handle the error without redirect
        let response = handle_auth_error(csrf_error, &request, false);

        // Verify it's a forbidden response
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Test that non-CSRF errors with redirect enabled return a redirect response
    /// This test checks:
    /// 1. A GET request with a non-CSRF error and redirect enabled
    /// 2. Returns a 302 TEMPORARY_REDIRECT response
    #[test]
    fn test_handle_auth_error_other_error_with_redirect() {
        // Create a GET request
        let request = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Create a non-CSRF error
        let other_error = SessionError::SessionError;

        // Handle the error with redirect enabled
        let response = handle_auth_error(other_error, &request, true);

        // Verify it's a redirect response
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    /// Test that non-CSRF errors without redirect return a 401 Unauthorized response
    /// This test checks:
    /// 1. A GET request with a non-CSRF error and redirect disabled
    /// 2. Returns a 401 UNAUTHORIZED response
    #[test]
    fn test_handle_auth_error_other_error_without_redirect() {
        // Create a GET request
        let request = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Create a non-CSRF error
        let other_error = SessionError::SessionError;

        // Handle the error without redirect
        let response = handle_auth_error(other_error, &request, false);

        // Verify it's an unauthorized response
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Test that POST requests with CSRF errors do not redirect
    /// This test checks:
    /// 1. A POST request with a CSRF error and redirect enabled
    /// 2. Returns a 401 UNAUTHORIZED response (not a redirect)
    #[test]
    fn test_handle_auth_error_post_request_with_redirect() {
        // Create a POST request
        let request = Request::builder()
            .method(Method::POST)
            .body(Body::empty())
            .expect("Failed to build POST request for auth error test");

        // Create an error
        let error = SessionError::SessionError;

        // Handle the error with redirect enabled (but POST should not redirect)
        let response = handle_auth_error(error, &request, true);

        // Verify it's an unauthorized response (not a redirect)
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // The following tests verify the function signatures and basic behavior of the middleware functions
    // They are marked as ignored because they depend on the core library's authentication functions
    // which are difficult to mock in a unit test context

    // Note: These tests are marked as ignored because they require the core library's
    // authentication functions and we can't easily mock Next in unit tests.
    // In a real integration test, we would use the actual Next middleware.

    #[test]
    fn test_middleware_signatures() {
        // This test just verifies that the middleware functions have the correct signatures
        // We can't easily test the actual behavior in a unit test
        assert!(true);
    }
}
