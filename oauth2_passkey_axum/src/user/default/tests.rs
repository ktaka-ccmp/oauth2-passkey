use super::*;
use chrono::Utc;

/// Test that the update_user_account_handler returns an error
/// when a non-admin user tries to update another user's account.
/// /// This test simulates a scenario where the authenticated user
/// tries to update a different user's account, which should be forbidden.
#[tokio::test]
async fn test_update_user_account_handler_id_mismatch() {
    // Create a mock AuthUser
    let now = Utc::now();
    let auth_user = AuthUser {
        id: "user456".to_string(), // Different from request
        account: "test@example.com".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: Some(1),
        created_at: now,
        updated_at: now,
        csrf_token: "token".to_string(),
        csrf_via_header_verified: true,
        session_id: "session456".to_string(),
    };

    // Create a request payload with a different user ID
    let payload = UpdateUserRequest {
        user_id: "user123".to_string(), // Different from auth_user.id
        account: Some("new@example.com".to_string()),
        label: Some("New Label".to_string()),
    };

    // Call the handler
    let result = update_user_account_handler(auth_user, ExtractJson(payload)).await;

    // Verify the result is an error with FORBIDDEN status
    assert!(result.is_err());
    if let Err((status, message)) = result {
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(message, "Cannot update another user's account");
    }
}

/// Test that the delete_user_account_handler returns an error
/// when a non-admin user tries to delete another user's account.
/// This test simulates a scenario where the authenticated user
/// tries to delete a different user's account, which should be forbidden.
#[tokio::test]
async fn test_delete_user_account_handler_id_mismatch() {
    // Create a mock AuthUser with a different ID
    let now = Utc::now();
    let auth_user = AuthUser {
        id: "user456".to_string(), // Different from request
        account: "test@example.com".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: Some(1),
        created_at: now,
        updated_at: now,
        csrf_token: "token".to_string(),
        csrf_via_header_verified: true,
        session_id: "session456".to_string(),
    };

    // Create a request payload with a different user ID
    let payload = DeleteUserRequest {
        user_id: "user123".to_string(), // Different from auth_user.id
    };

    // Call the handler
    let result = delete_user_account_handler(auth_user, ExtractJson(payload)).await;

    // Verify the result is an error with FORBIDDEN status
    assert!(result.is_err());
    if let Err((status, message)) = result {
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(message, "Cannot delete another user's account");
    }
}
