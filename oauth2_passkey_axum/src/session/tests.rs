use super::*;
use chrono::Utc;

/// Test the conversion between SessionUser and AuthUser
/// This test verifies that all fields are correctly converted between the two types.
#[test]
fn test_from_session_user_to_auth_user() {
    // Create a SessionUser instance
    let now = Utc::now();
    let session_user = SessionUser {
        id: "user123".to_string(),
        account: "test@example.com".to_string(),
        label: "Test User".to_string(),
        is_admin: true,
        sequence_number: Some(42),
        created_at: now,
        updated_at: now,
    };

    // Convert to AuthUser
    let auth_user = AuthUser::from(session_user);

    // Verify all fields were correctly converted
    assert_eq!(auth_user.id, "user123");
    assert_eq!(auth_user.account, "test@example.com");
    assert_eq!(auth_user.label, "Test User");
    assert!(auth_user.is_admin);
    assert_eq!(auth_user.sequence_number, Some(42));
    assert_eq!(auth_user.created_at, now);
    assert_eq!(auth_user.updated_at, now);

    // Verify default values for AuthUser-specific fields
    assert_eq!(auth_user.csrf_token, "");
    assert!(!auth_user.csrf_via_header_verified);
    assert_eq!(auth_user.session_id, "");
}

/// Test the conversion from AuthUser to SessionUser
/// This test verifies that all fields are correctly converted from AuthUser to SessionUser.
#[test]
fn test_from_auth_user_to_session_user() {
    // Create an AuthUser instance
    let now = Utc::now();
    let auth_user = AuthUser {
        id: "user123".to_string(),
        account: "test@example.com".to_string(),
        label: "Test User".to_string(),
        is_admin: true,
        sequence_number: Some(42),
        created_at: now,
        updated_at: now,
        csrf_token: "csrf-token-value".to_string(),
        csrf_via_header_verified: true,
        session_id: "session-123".to_string(),
    };

    // Convert to SessionUser
    let session_user = SessionUser::from(&auth_user);

    // Verify all fields were correctly converted
    assert_eq!(session_user.id, "user123");
    assert_eq!(session_user.account, "test@example.com");
    assert_eq!(session_user.label, "Test User");
    assert!(session_user.is_admin);
    assert_eq!(session_user.sequence_number, Some(42));
    assert_eq!(session_user.created_at, now);
    assert_eq!(session_user.updated_at, now);

    // AuthUser-specific fields should not be present in SessionUser
}

/// Test the AuthRedirect struct's new method
/// This test verifies that the AuthRedirect can be created with different HTTP methods
#[test]
fn test_auth_redirect_new() {
    // Test creating AuthRedirect with different HTTP methods
    // We're just testing that the constructor doesn't panic with different methods
    // The variables are prefixed with _ to indicate they're intentionally unused
    let _get_redirect = AuthRedirect::new(Method::GET);
    let _post_redirect = AuthRedirect::new(Method::POST);
    let _put_redirect = AuthRedirect::new(Method::PUT);
    let _delete_redirect = AuthRedirect::new(Method::DELETE);

    // If we get here without panicking, the test passes
    // assert!(true);
}

/// Test the AuthRedirect's into_response_with_method method
/// This test verifies that the method returns the correct response based on the HTTP method.
#[test]
#[cfg_attr(
    not(feature = "login-ui"),
    ignore = "requires login-ui feature for O2P_LOGIN_URL default"
)]
fn test_auth_redirect_into_response_with_method() {
    // Test with GET method
    let auth_redirect = AuthRedirect::new(Method::GET);
    let response = auth_redirect.into_response_with_method();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    // Test with POST method
    let auth_redirect = AuthRedirect::new(Method::POST);
    let response = auth_redirect.into_response_with_method();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test with PUT method
    let auth_redirect = AuthRedirect::new(Method::PUT);
    let response = auth_redirect.into_response_with_method();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test with DELETE method
    let auth_redirect = AuthRedirect::new(Method::DELETE);
    let response = auth_redirect.into_response_with_method();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
