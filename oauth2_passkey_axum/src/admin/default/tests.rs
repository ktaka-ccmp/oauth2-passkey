use super::*;

/// Test that the delete_user_account_handler returns an error
/// when a non-admin user tries to delete another user's account.
/// This test checks:
/// 1. The handler returns an error status code (UNAUTHORIZED).
/// 2. The error message is "Not authorized".
#[tokio::test]
async fn test_delete_user_account_handler_unauthorized() {
    // Create a non-admin user (not the first user)
    let auth_user = AuthUser {
        id: "user123".to_string(),
        account: "test@example.com".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: Some(2), // Not the first user, so no admin privileges
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        csrf_token: "token123".to_string(),
        csrf_via_header_verified: true,
        session_id: "session123".to_string(),
    };

    // Create a delete request
    let payload = DeleteUserRequest {
        user_id: "user456".to_string(),
    };

    // Call the handler
    let result = delete_user_account_handler(auth_user, ExtractJson(payload)).await;

    // Verify that it returns an unauthorized error
    assert!(result.is_err());
    if let Err((status, message)) = result {
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(message, "Not authorized".to_string());
    } else {
        panic!("Expected an error but got Ok");
    }
}

/// Test that the update_admin_status_handler returns an error
/// when a non-admin user tries to update another user's admin status.
/// This test checks:
/// 1. The handler returns an error status code (UNAUTHORIZED).
/// 2. The error message is "Not authorized".
/// 3. The handler does not panic or return Ok when it should return an error.
#[tokio::test]
async fn test_update_admin_status_handler_unauthorized() {
    // Create a non-admin user (not the first user)
    let auth_user = AuthUser {
        id: "user123".to_string(),
        account: "test@example.com".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: Some(2), // Not the first user, so no admin privileges
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        csrf_token: "token123".to_string(),
        csrf_via_header_verified: true,
        session_id: "session123".to_string(),
    };

    // Create an update request
    let payload = UpdateAdminStatusRequest {
        user_id: "user456".to_string(),
        is_admin: true,
    };

    // Call the handler
    let result = update_admin_status_handler(auth_user, ExtractJson(payload)).await;

    // Verify that it returns an unauthorized error
    assert!(result.is_err());
    if let Err((status, message)) = result {
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(message, "Not authorized".to_string());
    } else {
        panic!("Expected an error but got Ok");
    }
}
