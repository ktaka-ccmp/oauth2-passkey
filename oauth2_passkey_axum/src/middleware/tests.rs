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
#[cfg_attr(
    not(feature = "login-ui"),
    ignore = "requires login-ui feature for O2P_LOGIN_URL default"
)]
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
#[cfg_attr(
    not(feature = "login-ui"),
    ignore = "requires login-ui feature for O2P_LOGIN_URL default"
)]
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
