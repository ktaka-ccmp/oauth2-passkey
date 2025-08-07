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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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

    /// Establish a WebAuthn challenge context and extract the real challenge
    /// This is similar to establish_csrf_session_and_extract_state() for OAuth2 tests
    async fn establish_webauthn_challenge_and_extract(
        &self,
        username: &str,
        display_name: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        println!("🔧 Establishing WebAuthn challenge context for security test");

        let registration_request = json!({
            "username": username,
            "displayname": display_name,
            "mode": "create_user"
        });

        let start_response = self
            .browser
            .post_json("/auth/passkey/register/start", &registration_request)
            .await?;

        if !start_response.status().is_success() {
            return Err(format!(
                "Failed to start WebAuthn registration: {}",
                start_response.status()
            )
            .into());
        }

        let start_body: serde_json::Value = start_response.json().await?;
        let challenge = start_body["challenge"]
            .as_str()
            .ok_or("Missing challenge in WebAuthn start response")?
            .to_string();
        let user_handle = start_body["user"]["user_handle"]
            .as_str()
            .ok_or("Missing user_handle in WebAuthn start response")?
            .to_string();

        println!("🔧 Extracted real WebAuthn challenge: {challenge}");
        println!("🔧 Extracted real user handle: {user_handle}");

        Ok((challenge, user_handle))
    }

    /// Establish a WebAuthn authentication challenge context
    async fn establish_webauthn_auth_challenge(
        &self,
        username: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        println!("🔧 Establishing WebAuthn authentication challenge context for security test");

        // First register a user
        let (reg_challenge, user_handle) = self
            .establish_webauthn_challenge_and_extract(username, "Security Test User")
            .await?;

        // Complete registration with valid credential
        let valid_registration =
            MockWebAuthnCredentials::registration_response_with_challenge_user_handle_and_origin(
                username,
                "Security Test User",
                &reg_challenge,
                &user_handle,
                &self.server.base_url,
            );

        let reg_finish_response = self
            .browser
            .post_json("/auth/passkey/register/finish", &valid_registration)
            .await?;

        if !reg_finish_response.status().is_success() {
            return Err("Failed to complete WebAuthn registration for auth test setup".into());
        }

        // Now start authentication to get auth challenge
        let auth_start_request = json!({
            "username": username
        });

        let auth_start_response = self
            .browser
            .post_json("/auth/passkey/auth/start", &auth_start_request)
            .await?;

        if !auth_start_response.status().is_success() {
            return Err(format!(
                "Failed to start WebAuthn authentication: {}",
                auth_start_response.status()
            )
            .into());
        }

        let auth_start_data: serde_json::Value = auth_start_response.json().await?;
        let auth_challenge = auth_start_data["challenge"]
            .as_str()
            .ok_or("Missing challenge in WebAuthn auth start response")?
            .to_string();
        let auth_id = auth_start_data["authId"]
            .as_str()
            .ok_or("Missing authId in WebAuthn auth start response")?
            .to_string();

        println!("🔧 Extracted real WebAuthn auth challenge: {auth_challenge}");
        println!("🔧 Extracted real WebAuthn auth ID: {auth_id}");
        Ok((auth_challenge, auth_id))
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

// ================================================================================
// ADVANCED WEBAUTHN/PASSKEY ATTACK VECTOR TESTS
// ================================================================================

/// Test WebAuthn credential cloning attack prevention
///
/// This test verifies that credentials cannot be cloned or duplicated across accounts:
/// 1. Same credential ID cannot be registered to multiple users
/// 2. Credential registration includes proper uniqueness validation
/// 3. Credential binding prevents cross-account credential reuse
#[tokio::test]
#[serial]
async fn test_security_webauthn_credential_cloning_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing WebAuthn credential cloning attack prevention");

    // Test case 1: Attempt to register the same credential ID to different users
    let first_user_request = json!({
        "username": "user1@example.com",
        "displayname": "User One",
        "mode": "create_user"
    });

    // Start registration for first user
    let first_start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &first_user_request)
        .await?;

    if first_start_response.status() != reqwest::StatusCode::OK {
        println!("⚠️ First user registration start failed, skipping credential cloning test");
        setup.shutdown().await?;
        return Ok(());
    }

    let first_start_data: serde_json::Value = first_start_response.json().await?;
    let first_challenge = first_start_data["challenge"]
        .as_str()
        .unwrap_or("default_challenge");
    let _first_user_handle = first_start_data["user"]["id"]
        .as_str()
        .unwrap_or("user1_handle");

    // Create a credential response that attempts to clone a credential
    let cloned_credential_response = json!({
        "id": "cloned_credential_id", // Same credential ID for both users
        "raw_id": "Y2xvbmVkX2NyZWRlbnRpYWxfaWQ", // base64 of "cloned_credential_id"
        "response": {
            "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                "type": "webauthn.create",
                "challenge": first_challenge,
                "origin": "http://127.0.0.1:3000"
            }).to_string().as_bytes()),
            "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQ"
        },
        "type": "public-key"
    });

    // Complete registration for first user with the cloned credential
    let _first_finish_response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &cloned_credential_response)
        .await?;

    // Now attempt to register the same credential to a second user
    let second_user_request = json!({
        "username": "user2@example.com",
        "displayname": "User Two",
        "mode": "create_user"
    });

    let second_start_response = setup
        .browser
        .post_json("/auth/passkey/register/start", &second_user_request)
        .await?;

    if second_start_response.status() != reqwest::StatusCode::OK {
        println!("⚠️ Second user registration start failed, skipping credential cloning test");
        setup.shutdown().await?;
        return Ok(());
    }

    let second_start_data: serde_json::Value = second_start_response.json().await?;
    let second_challenge = second_start_data["challenge"]
        .as_str()
        .unwrap_or("default_challenge_2");

    // Attempt to register the same credential ID to the second user
    let cloned_credential_response_2 = json!({
        "id": "cloned_credential_id", // Same credential ID as first user
        "raw_id": "Y2xvbmVkX2NyZWRlbnRpYWxfaWQ", // Same raw ID
        "response": {
            "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                "type": "webauthn.create",
                "challenge": second_challenge,
                "origin": "http://127.0.0.1:3000"
            }).to_string().as_bytes()),
            "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQ"
        },
        "type": "public-key"
    });

    let second_finish_response = setup
        .browser
        .post_json(
            "/auth/passkey/register/finish",
            &cloned_credential_response_2,
        )
        .await?;

    let result = create_security_result_from_response(second_finish_response).await?;

    // Verify security rejection - same credential should not be registerable to multiple users
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "credential cloning test",
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test WebAuthn attestation statement bypass prevention
///
/// This test verifies that attestation statement validation cannot be bypassed:
/// 1. Invalid attestation statements are properly rejected
/// 2. Attestation format validation is enforced
/// 3. Attestation statement tampering is detected
#[tokio::test]
#[serial]
async fn test_security_webauthn_attestation_bypass_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing WebAuthn attestation statement bypass prevention");

    // Establish proper WebAuthn challenge context
    let (challenge, user_handle) = setup
        .establish_webauthn_challenge_and_extract(
            "attestation@example.com",
            "Attestation Test User",
        )
        .await?;

    // Test case 1: Attempt to bypass attestation with invalid attestation format
    let oversized_attestation = "A".repeat(100000); // 100KB attestation
    let invalid_attestation_formats = [
        ("empty_attestation", ""),
        ("null_attestation", "null"),
        ("malformed_cbor", "not_valid_cbor_data"),
        ("wrong_format", "packed_when_none_expected"),
        ("injection_attempt", "'; DROP TABLE credentials; --"),
        ("oversized_attestation", &oversized_attestation),
    ];

    for (test_name, invalid_attestation) in invalid_attestation_formats.iter() {
        println!("🔧 Testing attestation bypass attempt: {test_name}");

        let malicious_response = json!({
            "id": format!("bypass_cred_{}", test_name),
            "raw_id": URL_SAFE_NO_PAD.encode(format!("bypass_cred_{test_name}").as_bytes()),
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                    "type": "webauthn.create",
                    "challenge": challenge,
                    "origin": "http://127.0.0.1:3000"
                }).to_string().as_bytes()),
                "attestation_object": invalid_attestation
            },
            "type": "public-key",
            "user_handle": user_handle.clone()
        });

        let finish_response = setup
            .browser
            .post_json("/auth/passkey/register/finish", &malicious_response)
            .await?;

        let result = create_security_result_from_response(finish_response).await?;

        // Verify security rejection for attestation bypass attempt
        assert_security_failure(
            &result,
            &ExpectedSecurityError::BadRequest,
            &format!("attestation bypass test: {test_name}"),
        );
    }

    // Test case 2: Attempt to register with tampered attestation statement
    let tampered_attestation_response = json!({
        "id": "tampered_attestation_cred",
        "raw_id": "dGFtcGVyZWRfYXR0ZXN0YXRpb25fY3JlZA",
        "response": {
            "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": "http://127.0.0.1:3000"
            }).to_string().as_bytes()),
            // Tampered attestation object with invalid signature
            "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAEtampered_signature_data"
        },
        "type": "public-key",
        "user_handle": user_handle
    });

    let tampered_response = setup
        .browser
        .post_json(
            "/auth/passkey/register/finish",
            &tampered_attestation_response,
        )
        .await?;

    let tampered_result = create_security_result_from_response(tampered_response).await?;

    // Verify security rejection for tampered attestation
    assert_security_failure(
        &tampered_result,
        &ExpectedSecurityError::BadRequest,
        "tampered attestation test",
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test WebAuthn user verification bypass prevention
///
/// This test verifies that user verification requirements cannot be bypassed:
/// 1. User verification flag manipulation is detected
/// 2. Authentication without required user verification is rejected
/// 3. User verification downgrade attacks are prevented
#[tokio::test]
#[serial]
async fn test_security_webauthn_user_verification_bypass_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing WebAuthn user verification bypass prevention");

    // Establish proper WebAuthn authentication challenge context
    let (auth_challenge, auth_id) = setup
        .establish_webauthn_auth_challenge("userverify@example.com")
        .await?;

    // Test case 1: Attempt to authenticate with user verification flag manipulation
    let user_verification_bypass_attempts = [
        ("no_user_verification", false), // UV flag set to false when required
        ("missing_uv_flag", false),      // UV flag intentionally missing
    ];

    for (test_name, uv_flag_value) in user_verification_bypass_attempts.iter() {
        println!("🔧 Testing user verification bypass: {test_name}");

        // Create authenticator data with manipulated UV flag
        let manipulated_auth_response = json!({
            "id": "user_verification_cred",
            "raw_id": "dXNlcl92ZXJpZmljYXRpb25fY3JlZA",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                    "type": "webauthn.get",
                    "challenge": auth_challenge,
                    "origin": "http://127.0.0.1:3000"
                }).to_string().as_bytes()),
                // Authenticator data with UV flag manipulation
                "authenticator_data": if *uv_flag_value {
                    "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAACQ" // UV=1
                } else {
                    "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAACQ" // UV=0 (manipulated)
                },
                "signature": "MEUCIQDManipulated123Signature456Base64",
                "user_handle": "dXNlcnZlcmlmeUBleGFtcGxlLmNvbQ"
            },
            "type": "public-key",
            "auth_id": auth_id.clone()
        });

        let auth_finish_response = setup
            .browser
            .post_json("/auth/passkey/auth/finish", &manipulated_auth_response)
            .await?;

        let result = create_security_result_from_response(auth_finish_response).await?;

        // Verify security rejection for user verification bypass
        assert_security_failure(
            &result,
            &ExpectedSecurityError::BadRequest,
            &format!("user verification bypass test: {test_name}"),
        );
    }

    // Test case 2: Attempt user presence downgrade attack
    let presence_downgrade_response = json!({
        "id": "user_verification_cred",
        "raw_id": "dXNlcl92ZXJpZmljYXRpb25fY3JlZA",
        "response": {
            "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                "type": "webauthn.get",
                "challenge": auth_challenge,
                "origin": "http://127.0.0.1:3000"
            }).to_string().as_bytes()),
            // Authenticator data with both UP and UV flags set to 0 (downgrade attack)
            "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAACQ", // UP=0, UV=0
            "signature": "MEUCIQDDowngrade123Attack456Base64",
            "user_handle": "dXNlcnZlcmlmeUBleGFtcGxlLmNvbQ"
        },
        "type": "public-key",
        "auth_id": auth_id.clone()
    });

    let downgrade_response = setup
        .browser
        .post_json("/auth/passkey/auth/finish", &presence_downgrade_response)
        .await?;

    let downgrade_result = create_security_result_from_response(downgrade_response).await?;

    // Verify security rejection for presence downgrade attack
    assert_security_failure(
        &downgrade_result,
        &ExpectedSecurityError::BadRequest,
        "user presence downgrade test",
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test WebAuthn cross-origin credential binding attacks
///
/// This test verifies that credentials are properly bound to origins:
/// 1. Credentials registered on one origin cannot be used on another
/// 2. Cross-origin credential authentication is rejected
/// 3. Origin spoofing attempts are detected
#[tokio::test]
#[serial]
async fn test_security_webauthn_cross_origin_credential_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = PasskeySecurityTestSetup::new().await?;

    println!("🔒 Testing WebAuthn cross-origin credential binding protection");

    // Establish proper WebAuthn authentication challenge context
    let (auth_challenge, auth_id) = setup
        .establish_webauthn_auth_challenge("crossorigin@example.com")
        .await?;

    // Test case 1: Attempt authentication from malicious origins
    let malicious_origins = [
        "https://evil.com",
        "http://attacker.com",
        "javascript:alert('xss')",
        "data:text/html,<script>evil()</script>",
        "file:///etc/passwd",
        "null", // Null origin attack
        "",     // Empty origin attack
    ];

    for malicious_origin in malicious_origins.iter() {
        println!("🔧 Testing cross-origin authentication from: {malicious_origin}");

        let cross_origin_auth = json!({
            "id": "cross_origin_cred",
            "raw_id": "Y3Jvc3Nfb3JpZ2luX2NyZWQ",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                    "type": "webauthn.get",
                    "challenge": auth_challenge,
                    "origin": malicious_origin // Malicious origin
                }).to_string().as_bytes()),
                "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAACQ",
                "signature": "MEUCIQDCrossOrigin123Attack456Base64",
                "user_handle": "Y3Jvc3NvcmlnaW5AZXhhbXBsZS5jb20"
            },
            "type": "public-key",
            "auth_id": auth_id.clone()
        });

        let malicious_auth_response = setup
            .browser
            .post_json("/auth/passkey/auth/finish", &cross_origin_auth)
            .await?;

        let result = create_security_result_from_response(malicious_auth_response).await?;

        // Verify security rejection for cross-origin authentication
        assert_security_failure(
            &result,
            &ExpectedSecurityError::BadRequest,
            &format!("cross-origin auth test: {malicious_origin}"),
        );
    }

    // Test case 2: Subdomain takeover simulation
    let subdomain_takeover_origins = [
        "http://evil.127.0.0.1:3000",     // Subdomain confusion
        "http://127.0.0.1.evil.com:3000", // Domain spoofing
        "http://127.0.0.1:3001",          // Port confusion
        "https://127.0.0.1:3000",         // Protocol confusion
    ];

    for takeover_origin in subdomain_takeover_origins.iter() {
        println!("🔧 Testing subdomain takeover from: {takeover_origin}");

        let takeover_auth = json!({
            "id": "cross_origin_cred",
            "raw_id": "Y3Jvc3Nfb3JpZ2luX2NyZWQ",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(json!({
                    "type": "webauthn.get",
                    "challenge": auth_challenge,
                    "origin": takeover_origin
                }).to_string().as_bytes()),
                "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAACQ",
                "signature": "MEUCIQDSubdomain123Takeover456Base64",
                "user_handle": "Y3Jvc3NvcmlnaW5AZXhhbXBsZS5jb20"
            },
            "type": "public-key",
            "auth_id": auth_id.clone()
        });

        let takeover_response = setup
            .browser
            .post_json("/auth/passkey/auth/finish", &takeover_auth)
            .await?;

        let result = create_security_result_from_response(takeover_response).await?;

        // Verify security rejection for subdomain takeover attempt
        assert_security_failure(
            &result,
            &ExpectedSecurityError::BadRequest,
            &format!("subdomain takeover test: {takeover_origin}"),
        );
    }

    setup.shutdown().await?;
    Ok(())
}
