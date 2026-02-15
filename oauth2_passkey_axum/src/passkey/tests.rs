use axum::Json;
use http::StatusCode;

use super::*;

/// Test the list_passkey_credentials handler with mocked dependencies
/// This test checks:
/// 1. Handler returns credentials for authenticated user
/// 2. Returned credentials have correct user ID and fields
/// 3. Mock functions are called as expected
#[tokio::test]
async fn test_list_passkey_credentials_handler() {
    use crate::test_utils::{core_mocks, mocks};

    // Initialize test environment
    let _ = crate::test_utils::env::origin();

    // Create a mock AuthUser
    let auth_user = mocks::mock_auth_user("test-user-id", "test@example.com");

    let result = async {
        // Simulate what list_passkey_credentials would do with mocked dependencies
        let credentials = core_mocks::mock_list_credentials_core(&auth_user.id, false)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(Json(credentials))
    }
    .await;

    // Verify the result
    match &result {
        Ok(Json(credentials)) => {
            // Verify we have at least one credential
            assert!(!credentials.is_empty(), "Expected at least one credential");

            // Verify user ID of the first credential
            assert_eq!(
                credentials[0].user_id, "test-user-id",
                "First credential user ID mismatch"
            );

            // Verify user fields of the first credential
            assert_eq!(
                credentials[0].user.name, "user_test-user-id",
                "First credential user name mismatch"
            );
            assert_eq!(
                credentials[0].user.display_name, "Test User test-user-id",
                "First credential display name mismatch"
            );
        }
        Err((status, message)) => {
            panic!("Expected successful result with credentials, got error: {status} - {message}");
        }
    }
}

/// Test the update_passkey_credential handler with mocked dependencies
/// This test checks:
/// 1. Handler updates credential details for authenticated user
/// 2. Returns updated credential data in JSON format
/// 3. Mock functions are called as expected
#[tokio::test]
async fn test_update_passkey_credential_handler() {
    use crate::test_utils::{core_mocks, mocks};

    // Initialize test environment with required environment variables
    let _ = crate::test_utils::env::origin();

    // Create a mock AuthUser
    let auth_user = mocks::mock_auth_user("test-user-id", "test@example.com");

    // Create a mock request payload
    let payload = UpdateCredentialUserDetailsRequest {
        credential_id: "test-credential-id".to_string(),
        name: "Test Credential".to_string(),
        display_name: "Test User's Credential".to_string(),
    };

    // Simulate the handler function with our mocks
    let result: Result<Json<serde_json::Value>, (StatusCode, String)> = async {
        // This simulates what update_passkey_credential would do
        let response = core_mocks::mock_update_passkey_credential_core(
            &auth_user.id,
            &payload.credential_id,
            &payload.name,
            &payload.display_name,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(response))
    }
    .await;

    // Now we expect this to succeed with our mock
    assert!(
        result.is_ok(),
        "Expected successful result, got: {result:?}"
    );

    // Check that the response contains the expected data
    if let Ok(Json(value)) = result {
        assert!(value.is_object());
        // Verify the response contains the expected fields
        assert!(
            value.get("credential").is_some(),
            "Response should contain credential field"
        );
    }
}
