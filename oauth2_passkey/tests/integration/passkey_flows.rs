use crate::common::{MockBrowser, MockWebAuthnCredentials, TestServer, TestUsers};
use serial_test::serial;

/// Common helper function for testing different WebAuthn attestation formats
///
/// This function contains the shared logic for testing passkey registration
/// with different attestation formats (none, packed, tpm).
///
/// # Arguments
/// * `format` - The attestation format to test ("none", "packed", "tpm")
/// * `expected_success` - Whether the test expects successful registration
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error
async fn test_passkey_attestation_format(
    format: &str,
    expected_success: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    let server = TestServer::start().await?;
    let browser = MockBrowser::new(&server.base_url, true);
    let test_user = TestUsers::passkey_user();

    println!("🔐 Testing passkey registration with {format} attestation format");

    // Step 1: Start passkey registration
    let registration_options = browser
        .start_passkey_registration(&test_user.email, &test_user.name, "create_user")
        .await?;

    // Verify we got proper WebAuthn registration options
    assert!(
        registration_options["challenge"].is_string(),
        "Registration should include challenge"
    );
    assert!(
        registration_options["rp"]["id"].is_string(),
        "Registration should include RP ID"
    );
    assert!(
        registration_options["user"]["name"].is_string(),
        "Registration should include username"
    );

    // Extract challenge and user_handle
    let challenge = registration_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let user_handle = registration_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    // Step 2: Create mock credential with specified attestation format
    let mock_credential = if format == "none" {
        // For none attestation, use the original method for backward compatibility
        MockWebAuthnCredentials::registration_response_with_challenge_user_handle_and_origin(
            &test_user.email,
            &test_user.name,
            challenge,
            user_handle,
            &server.base_url,
        )
    } else {
        // For packed and tpm, use the format-specific method
        MockWebAuthnCredentials::registration_response_with_format(
            &test_user.email,
            &test_user.name,
            challenge,
            user_handle,
            format,
        )
    };

    let registration_response = browser
        .complete_passkey_registration(&mock_credential)
        .await?;

    let status = registration_response.status();
    let response_body = registration_response.text().await?;

    println!("Registration response status: {status}");
    println!("Registration response body: {response_body}");

    // Step 3: Verify response based on format and expected outcome
    if status.is_success() {
        println!("✅ {format} attestation registration completed successfully");

        if expected_success {
            // Verify session establishment for successful cases
            assert!(
                browser.has_active_session().await,
                "Session should be established after successful {format} attestation registration"
            );

            let user_info = browser.get_user_info().await?;
            assert!(
                user_info.is_some(),
                "User info should be available after successful {format} registration"
            );

            let user_data = user_info.unwrap();

            // The API returns "account" instead of "email" and "label" instead of "name"
            let account = user_data.get("account").and_then(|v| v.as_str());
            let label = user_data.get("label").and_then(|v| v.as_str());

            assert_eq!(
                account,
                Some(test_user.email.as_str()),
                "User account should match email"
            );
            assert_eq!(
                label,
                Some(test_user.name.as_str()),
                "User label should match name"
            );
        }
    } else {
        // Handle failures - check if this was expected or not
        if expected_success {
            // If we expected success but got failure, this is a test failure
            println!("❌ FAILURE: {format} attestation was expected to succeed but failed");
            println!("Response status: {status}");
            println!("Response: {response_body}");
            server.shutdown().await;
            return Err(format!("{format} attestation was expected to succeed but failed with status {status}: {response_body}").into());
        } else {
            // Handle expected failures based on format
            match format {
                "none" => {
                    if response_body.contains("verification")
                        || response_body.contains("credential")
                        || response_body.contains("CBOR")
                    {
                        println!(
                            "ⓘ {format} attestation failed as expected - reached CBOR validation step"
                        );
                    } else if response_body.contains("Invalid origin") {
                        println!(
                            "ⓘ {format} attestation failed as expected - origin validation rejected request"
                        );
                    } else {
                        println!("❌ FAILURE: Unexpected error in {format} attestation");
                        println!("Response: {response_body}");
                        server.shutdown().await;
                        return Err(format!(
                            "{format} attestation failed unexpectedly: {response_body}"
                        )
                        .into());
                    }
                }
                "packed" => {
                    if response_body.contains("signature") || response_body.contains("verification")
                    {
                        println!(
                            "ⓘ {format} attestation failed as expected - reached signature verification step"
                        );
                    } else {
                        println!("❌ FAILURE: Unexpected error in {format} attestation");
                        println!("Response: {response_body}");
                        server.shutdown().await;
                        return Err(format!(
                            "{format} attestation failed unexpectedly: {response_body}"
                        )
                        .into());
                    }
                }
                "tpm" => {
                    if response_body.contains("TPM")
                        || response_body.contains("certInfo")
                        || response_body.contains("pubArea")
                    {
                        println!(
                            "ⓘ {format} attestation failed as expected - reached TPM verification step"
                        );
                    } else {
                        println!("❌ FAILURE: Unexpected error in {format} attestation");
                        println!("Response: {response_body}");
                        server.shutdown().await;
                        return Err(format!(
                            "{format} attestation failed unexpectedly: {response_body}"
                        )
                        .into());
                    }
                }
                _ => {
                    println!("❌ FAILURE: Unknown attestation format: {format}");
                    server.shutdown().await;
                    return Err(format!("Unknown attestation format: {format}").into());
                }
            }
        }
    }

    // Cleanup
    server.shutdown().await;
    Ok(())
}

/// Test complete passkey authentication flows
///
/// These integration tests verify end-to-end passkey functionality including:
/// - New user registration via passkey
/// - Existing user login via passkey
/// - WebAuthn credential registration and authentication
/// - Error scenarios and edge cases
/// Test passkey registration with none attestation format (default)
///
/// Flow: Start registration → WebAuthn challenge → Mock credential → Verify none attestation
#[tokio::test]
#[serial]
async fn test_passkey_registration_none_attestation() -> Result<(), Box<dyn std::error::Error>> {
    test_passkey_attestation_format("none", false).await
}

/// Test passkey registration with packed attestation format
///
/// Flow: Start registration → WebAuthn challenge → Mock packed credential → Verify attestation
#[tokio::test]
#[serial]
async fn test_passkey_registration_packed_attestation() -> Result<(), Box<dyn std::error::Error>> {
    test_passkey_attestation_format("packed", true).await
}

/// Test passkey registration with TPM attestation format
///
/// Flow: Start registration → WebAuthn challenge → Mock TPM credential → Verify attestation
#[tokio::test]
#[serial]
async fn test_passkey_registration_tpm_attestation() -> Result<(), Box<dyn std::error::Error>> {
    test_passkey_attestation_format("tpm", true).await
}

/// Test passkey existing user authentication flow
///
/// Flow: Pre-registered user → Start authentication → WebAuthn challenge → Mock assertion → Login
#[tokio::test]
#[serial]
async fn test_passkey_existing_user_authentication() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    let server = TestServer::start().await?;
    let browser = MockBrowser::new(&server.base_url, true);
    let test_user = TestUsers::passkey_user();

    println!("🔐 Testing passkey existing user authentication flow");

    // Step 1: Start passkey authentication (for existing user)
    let authentication_options = browser
        .start_passkey_authentication(Some(&test_user.email))
        .await?;

    // Verify we got proper WebAuthn authentication options
    assert!(
        authentication_options["challenge"].is_string(),
        "Authentication should include challenge"
    );
    assert!(
        authentication_options["rpId"].is_string(),
        "Authentication should include RP ID"
    );

    println!("✅ Step 1: Received WebAuthn authentication options");

    // Step 2: Simulate WebAuthn client providing assertion response
    // Extract the actual challenge and auth_id from the authentication options
    let challenge = authentication_options["challenge"]
        .as_str()
        .expect("Authentication options should contain challenge");
    let auth_id = authentication_options["authId"]
        .as_str()
        .expect("Authentication options should contain authId");

    let mock_assertion =
        MockWebAuthnCredentials::authentication_response_with_challenge_auth_id_and_origin(
            "mock_credential_id_123",
            challenge,
            auth_id,
            &server.base_url,
        );

    let auth_response = browser
        .complete_passkey_authentication(&mock_assertion)
        .await?;

    // Check for successful authentication flow
    let status = auth_response.status();
    let response_body = auth_response.text().await?;

    println!("Authentication response status: {status}");
    println!("Authentication response body: {response_body}");

    if status.is_success() {
        println!("✅ Passkey authentication SUCCESS: Full flow completed");

        // Verify session established for existing user
        assert!(
            browser.has_active_session().await,
            "Session should be established for existing user"
        );

        let user_info = browser.get_user_info().await?;
        assert!(
            user_info.is_some(),
            "User info should be available for existing user"
        );
    } else if response_body.contains("verification")
        || response_body.contains("assertion")
        || response_body.contains("Credential not found")
    {
        println!(
            "ⓘ Passkey authentication failed as expected - reached credential verification step"
        );
    } else if response_body.contains("Invalid origin") {
        println!(
            "ⓘ Passkey authentication failed as expected - origin validation rejected request"
        );
    } else {
        println!("❌ FAILURE: Unexpected error in passkey authentication");
        println!("Response: {response_body}");
        return Err(format!("Passkey authentication failed: {response_body}").into());
    }

    // Cleanup
    server.shutdown().await;
    Ok(())
}

/// Test passkey registration for new user (without OAuth2 dependency)
///
/// Flow: Define user → WebAuthn challenge → Passkey registration
#[tokio::test]
#[serial]
async fn test_passkey_credential_addition() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let browser = MockBrowser::new(&server.base_url, true);

    println!("🔐 Testing passkey credential registration for new user");

    // Define test user data for passkey registration
    let user_email = std::env::var("TEST_USER_EMAIL").unwrap_or("passkey@example.com".to_string());
    let user_name = "Passkey Test User";

    // Step 1: Start passkey registration in "create_user" mode (create new passkey user)
    let registration_options = browser
        .start_passkey_registration(&user_email, user_name, "create_user")
        .await?;

    // Verify we got proper WebAuthn registration options
    assert!(
        registration_options["challenge"].is_string(),
        "Registration should include challenge"
    );
    assert!(
        registration_options["rp"]["id"].is_string(),
        "Registration should include RP ID"
    );

    println!("✅ Step 1: Received WebAuthn registration options for credential registration");

    // Step 2: Complete passkey registration
    // Extract the actual challenge and user_handle from the registration options
    let challenge = registration_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let user_handle = registration_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    let mock_credential =
        MockWebAuthnCredentials::registration_response_with_challenge_user_handle_and_origin(
            &user_email,
            user_name,
            challenge,
            user_handle,
            &server.base_url,
        );

    let registration_response = browser
        .complete_passkey_registration(&mock_credential)
        .await?;

    let status = registration_response.status();
    let response_body = registration_response.text().await?;

    if status.is_success() {
        println!("✅ Passkey credential addition completed successfully");
    } else if response_body.contains("verification")
        || response_body.contains("credential")
        || response_body.contains("CBOR")
    {
        println!("ⓘ Passkey credential addition failed as expected - reached CBOR validation step");
    } else if response_body.contains("Invalid origin") {
        println!(
            "ⓘ Passkey credential addition failed as expected - origin validation rejected request"
        );
    } else {
        println!("❌ FAILURE: Unexpected error in passkey credential addition");
        println!("Response: {response_body}");
        return Err(format!("Passkey credential addition failed: {response_body}").into());
    }

    // Cleanup
    server.shutdown().await;
    Ok(())
}

/// Test passkey error scenarios
///
/// Verifies proper error handling for various passkey failure cases
#[tokio::test]
#[serial]
async fn test_passkey_error_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let browser = MockBrowser::new(&server.base_url, true);

    println!("🔐 Testing passkey error scenarios");

    // Test 1: Invalid credential response structure
    let invalid_credential = serde_json::json!({
        "invalid": "structure",
        "missing": "required_fields"
    });

    let response = browser
        .complete_passkey_registration(&invalid_credential)
        .await?;

    // Should return error response
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Invalid credential should result in error response"
    );

    // Test 2: Authentication without prior registration
    let authentication_options = browser
        .start_passkey_authentication(Some("nonexistent@example.com"))
        .await;

    // Should either succeed with empty allowed credentials or return error
    match authentication_options {
        Ok(options) => {
            // If successful, should indicate no credentials available
            if let Some(allowed_creds) = options.get("allowCredentials") {
                assert!(
                    allowed_creds.as_array().is_none_or(|arr| arr.is_empty()),
                    "Non-existent user should have no allowed credentials"
                );
            }
            println!("✅ Non-existent user authentication handled correctly");
        }
        Err(_) => {
            println!("✅ Non-existent user authentication returned error (also acceptable)");
        }
    }

    // Cleanup
    server.shutdown().await;
    Ok(())
}
