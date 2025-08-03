/// Passkey security tests - negative tests for WebAuthn/Passkey authentication flows
///
/// These tests verify that Passkey security controls properly reject:
/// - Invalid WebAuthn credential responses
/// - Challenge tampering and replay attacks
/// - Origin mismatches in WebAuthn assertions
/// - Expired challenge handling
/// - Invalid authenticator data validation
use crate::common::{
    MockBrowser, MockWebAuthnCredentials, TestServer, TestUsers,
    attack_scenarios::passkey_attacks::*, security_utils::*,
};
use serde_json::json;
use serial_test::serial;

/// Test environment setup for Passkey security tests
struct PasskeySecurityTestSetup {
    server: TestServer,
    browser: MockBrowser,
}

impl PasskeySecurityTestSetup {
    /// Create a new security test environment
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let server = TestServer::start().await?;
        let browser = MockBrowser::new(&server.base_url, true);
        Ok(Self { server, browser })
    }

    /// Shutdown the test server
    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.server.shutdown().await;
        Ok(())
    }
}

/// Test passkey registration with invalid WebAuthn response structure - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_invalid_registration_response()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey invalid registration response rejection");

    let test_user = TestUsers::passkey_user();

    // Start registration to get a valid challenge
    let registration_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "create_user"
    });

    let start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &registration_request)
        .await?;

    let start_body: serde_json::Value = start_response.json().await?;
    let user_handle = start_body["user"]["user_handle"]
        .as_str()
        .unwrap_or("missing_user_handle");
    let challenge = start_body["challenge"]
        .as_str()
        .unwrap_or("missing_challenge");

    // Create invalid registration response (attack scenario) using real challenge to pass challenge validation
    let mut invalid_response = create_invalid_registration_response(challenge);
    invalid_response["user_handle"] = serde_json::Value::String(user_handle.to_string());

    // Attempt to complete registration with invalid response
    let response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &invalid_response)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (400 for invalid client data)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "invalid registration response test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration with invalid CBOR data - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_invalid_cbor_response() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey invalid CBOR response rejection");

    let test_user = TestUsers::passkey_user();

    // Start registration to get a valid challenge
    let registration_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "create_user"
    });

    let start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &registration_request)
        .await?;

    let start_body: serde_json::Value = start_response.json().await?;
    let user_handle = start_body["user"]["user_handle"]
        .as_str()
        .unwrap_or("missing_user_handle");
    let challenge = start_body["challenge"]
        .as_str()
        .unwrap_or("missing_challenge");

    // Create response with invalid CBOR data (attack scenario) using real challenge to pass challenge validation
    let mut invalid_cbor_response = create_invalid_cbor_response(challenge);
    invalid_cbor_response["user_handle"] = serde_json::Value::String(user_handle.to_string());

    // Attempt to complete registration with invalid CBOR
    let response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &invalid_cbor_response)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (400 for invalid CBOR)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "invalid CBOR response test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration with tampered challenge - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_tampered_challenge_response()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey tampered challenge rejection");

    let test_user = TestUsers::passkey_user();

    // Start registration to get a valid challenge
    let registration_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "create_user"
    });

    let start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &registration_request)
        .await?;

    // Extract the challenge and user handle from the response
    let start_body: serde_json::Value = start_response.json().await?;
    let original_challenge = start_body["challenge"]
        .as_str()
        .unwrap_or("original_challenge");
    let user_handle = start_body["user"]["user_handle"]
        .as_str()
        .unwrap_or("missing_user_handle");

    // Create response with tampered challenge (attack scenario) with valid user handle
    let mut tampered_response = create_tampered_challenge_response(original_challenge);
    tampered_response["user_handle"] = serde_json::Value::String(user_handle.to_string());

    // Attempt to complete registration with tampered challenge
    let response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &tampered_response)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (400 for invalid challenge)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "tampered challenge test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration with wrong origin - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_wrong_origin_response() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey wrong origin rejection");

    let test_user = TestUsers::passkey_user();

    // Start registration to get a valid challenge
    let registration_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "create_user"
    });

    let start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &registration_request)
        .await?;

    // Extract the challenge and user handle from the response
    let start_body: serde_json::Value = start_response.json().await?;
    let original_challenge = start_body["challenge"]
        .as_str()
        .unwrap_or("original_challenge");
    let user_handle = start_body["user"]["user_handle"]
        .as_str()
        .unwrap_or("missing_user_handle");

    // Create response with wrong origin (attack scenario) with valid user handle
    let mut wrong_origin_response = create_wrong_origin_response(original_challenge);
    wrong_origin_response["user_handle"] = serde_json::Value::String(user_handle.to_string());

    // Attempt to complete registration with wrong origin
    let response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &wrong_origin_response)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (400 for invalid origin)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "wrong origin test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey authentication with nonexistent challenge ID - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_nonexistent_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey nonexistent challenge ID rejection");

    // Create nonexistent challenge ID (attack scenario)
    let nonexistent_challenge_id = create_nonexistent_challenge_id();

    // Attempt to start authentication with nonexistent challenge ID
    let auth_request = json!({
        "challenge_id": nonexistent_challenge_id
    });

    let response = setup
        .browser
        .post_json("/auth/passkey/authenticate/start", &auth_request)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::NOT_FOUND, None),
        "nonexistent challenge test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey authentication with expired authentication response - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_expired_auth_response() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey expired authentication response rejection");

    // Create expired authentication response (attack scenario)
    let expired_response = create_expired_auth_response();

    // Attempt to complete authentication with expired response
    let response = setup
        .browser
        .post_json("/auth/passkey/authenticate/finish", &expired_response)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::NOT_FOUND, None),
        "expired auth response test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration start with add_to_user mode but no session - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_add_to_user_no_session() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey add_to_user mode without session rejection");

    let test_user = TestUsers::passkey_user();

    // Attempt to start registration in add_to_user mode without existing session
    let registration_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "add_to_user"
    });

    let response = setup
        .browser
        .post_json("/auth/passkey/register/start", &registration_request)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (add_to_user requires existing session)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "add_to_user no session test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration mode validation with proper session establishment
#[tokio::test]
#[serial]
async fn test_security_passkey_create_user_with_session() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey registration mode validation");

    let test_user = TestUsers::passkey_user();

    // First, create a session by completing a successful registration
    let first_registration_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "create_user"
    });

    // Start first registration (this should work)
    let start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &first_registration_request)
        .await?;

    let start_body: serde_json::Value = start_response.json().await?;
    let user_handle = start_body["user"]["user_handle"]
        .as_str()
        .unwrap_or("test_user_handle");

    // Extract real challenge from start response for proper session establishment
    let challenge = start_body["challenge"]
        .as_str()
        .unwrap_or("missing_challenge");

    // Create a valid WebAuthn registration response using the proper mock credential factory
    // This ensures proper RP ID hash validation and all WebAuthn requirements
    let mock_credential =
        MockWebAuthnCredentials::registration_response_with_challenge_user_handle_and_origin(
            &test_user.email,
            &test_user.name,
            challenge,
            user_handle,
            &setup.server.base_url,
        );

    // Complete the first registration to establish a real session
    let finish_response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &mock_credential)
        .await?;

    // Verify the first registration succeeded and established a session
    assert!(
        finish_response.status().is_success(),
        "First registration should succeed to establish session"
    );

    // Verify session was actually established
    assert!(
        setup.browser.has_active_session().await,
        "Session should be established after successful registration"
    );

    // Test 1: First verify that add_to_user WORKS with the session (using proper session-aware method)
    println!("🔧 Testing add_to_user mode with existing session - should work");

    let add_to_user_result = setup
        .browser
        .start_passkey_registration(&test_user.email, "Additional Passkey", "add_to_user")
        .await;

    match add_to_user_result {
        Ok(_) => {
            println!("✅ add_to_user mode worked as expected with session");
        }
        Err(e) => {
            return Err(format!(
                "add_to_user mode should work with established session but failed: {e}"
            )
            .into());
        }
    }

    // Test 2: Now test create_user mode which should FAIL because create_user mode rejects authenticated users
    println!("🔧 Testing create_user with existing session - should be rejected");

    // Use the new post_json_with_headers method to properly test with session cookies
    println!("🔧 Getting CSRF token to make session-aware create_user request");
    let csrf_response = setup.browser.get("/auth/user/csrf_token").await?;

    if csrf_response.status().is_success() {
        let csrf_data: serde_json::Value = csrf_response.json().await?;
        if let Some(csrf_token) = csrf_data.get("csrf_token").and_then(|v| v.as_str()) {
            println!("🔧 Making create_user request with JSON and session cookies (proper test)");

            let request_data = serde_json::json!({
                "username": "another_user@example.com",
                "displayname": "Another User",
                "mode": "create_user"
            });

            // Use the post_json_with_headers method to properly handle session cookies
            let response = setup
                .browser
                .post_json_with_headers(
                    "/auth/passkey/register/start",
                    &request_data,
                    &[("X-CSRF-Token", csrf_token)],
                )
                .await?;

            let status = response.status();
            let response_body = response.text().await?;

            println!("🔧 create_user response status: {status}");
            println!("🔧 create_user response body: {response_body}");

            if status.is_success() {
                return Err(
                    "create_user mode should reject authenticated users but it succeeded".into(),
                );
            } else if status == 500
                || response_body.contains("UnexpectedlyAuthorized")
                || response_body.contains("Internal Server Error")
            {
                println!("✅ create_user mode correctly rejected with existing session");
                println!("📋 Error: {response_body}");
            } else {
                return Err(format!(
                    "create_user mode was rejected but with unexpected error: {status} - {response_body}"
                )
                .into());
            }
        } else {
            return Err("Could not get CSRF token to test create_user with session".into());
        }
    } else {
        return Err("Could not access CSRF endpoint to test create_user with session".into());
    }

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration with malformed JSON request body - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_malformed_json_request() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey malformed JSON request rejection");

    // For this test, we'll use an incomplete request that should be rejected
    let incomplete_request = json!({
        "username": "test"
        // Missing required fields to trigger validation error
    });

    // Attempt to start registration with incomplete JSON
    let response = setup
        .browser
        .post_json("/auth/passkey/register/start", &incomplete_request)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::UNPROCESSABLE_ENTITY, None),
        "malformed JSON test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test passkey registration with missing required fields - should be rejected
#[tokio::test]
#[serial]
async fn test_security_passkey_missing_required_fields() -> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing Passkey missing required fields rejection");

    // Create request with missing required fields
    let incomplete_request = json!({
        "username": "test@example.com"
        // Missing displayname and mode
    });

    let response = setup
        .browser
        .post_json("/auth/passkey/register/start", &incomplete_request)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::UNPROCESSABLE_ENTITY, None),
        "missing required fields test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}
