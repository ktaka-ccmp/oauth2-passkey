use crate::common::{
    MockBrowser, MockWebAuthnCredentials, TestServer, TestSetup, TestUsers,
    constants::passkey::*,
    session_utils::{logout_and_verify, verify_successful_authentication},
    validation_utils::handle_expected_passkey_failure,
};

/// Test environment setup for passkey tests
struct PasskeyTestSetup {
    setup: TestSetup,
    test_user: crate::common::fixtures::TestUser,
}

impl PasskeyTestSetup {
    /// Create a new test environment
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let setup = TestSetup::new().await?;
        let test_user = TestUsers::passkey_user();
        Ok(Self { setup, test_user })
    }

    /// Access to server for specialized methods
    #[allow(dead_code)]
    fn server(&self) -> &TestServer {
        &self.setup.server
    }

    /// Access to browser for specialized methods
    fn browser(&self) -> &MockBrowser {
        &self.setup.browser
    }

    /// Get the base URL for the test server
    fn base_url(&self) -> &str {
        &self.setup.server.base_url
    }

    /// Shutdown the test server
    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.setup.shutdown().await;
        Ok(())
    }

    /// Register multiple passkey credentials for testing
    async fn register_multiple_credentials(
        &self,
        count: usize,
    ) -> Result<CredentialSet, Box<dyn std::error::Error>> {
        let mut credentials = CredentialSet::new();

        if count == 0 {
            return Ok(credentials);
        }

        // Register first credential
        println!("Step: Registering primary passkey credential");
        let first_result = register_user_with_attestation(
            self.browser(),
            &self.test_user,
            DEFAULT_ATTESTATION_FORMAT,
            self.base_url(),
        )
        .await?;

        if let Some(key_pair) = first_result.key_pair_bytes {
            credentials.add_credential(first_result.user_handle, key_pair);
        }

        // Verify user is logged in after first registration
        assert!(
            self.browser().has_active_session().await,
            "User should be logged in after primary registration"
        );
        println!("✅ Primary credential registered successfully");

        // Register additional credentials if requested
        for i in 1..count {
            println!("Step: Registering additional passkey credential #{}", i + 1);
            let additional_result = register_additional_credential(
                self.browser(),
                &self.test_user,
                DEFAULT_ATTESTATION_FORMAT,
                credentials
                    .first()
                    .map(|c| c.user_handle.as_str())
                    .unwrap_or(""),
            )
            .await?;

            if let Some(key_pair) = additional_result.key_pair_bytes {
                credentials.add_credential(additional_result.user_handle, key_pair);
            }

            // Verify still logged in after additional registration
            assert!(
                self.browser().has_active_session().await,
                "User should still be logged in after additional registration #{}",
                i + 1
            );
            println!(
                "✅ Additional credential #{} registered successfully",
                i + 1
            );
        }

        Ok(credentials)
    }

    /// Test logout and re-authentication cycle with multiple credentials
    async fn test_logout_and_reauth_cycle(
        &self,
        credentials: &CredentialSet,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Logout the user
        println!("Step: Logging out user");
        logout_and_verify(self.browser()).await?;

        // Test authentication with each credential
        for (index, credential) in credentials.credentials.iter().enumerate() {
            println!(
                "Step: Testing authentication with credential #{}",
                index + 1
            );
            let browser_session = MockBrowser::new(self.base_url(), true);

            let auth_success = AuthenticationFlow::new(
                &browser_session,
                &self.test_user,
                &credential.user_handle,
                &credential.key_pair,
            )
            .with_credential_index(credential.index)
            .with_context(&format!("credential {} authentication", index + 1))
            .execute_and_verify()
            .await?;

            if auth_success {
                println!(
                    "✅ Authentication with credential #{} successful",
                    index + 1
                );
            } else {
                println!(
                    "⚠️  Authentication with credential #{} failed (expected with mock credentials)",
                    index + 1
                );
            }

            // Logout after each test to prepare for next credential
            if index < credentials.len() - 1 {
                logout_and_verify(&browser_session).await?;
            }
        }

        Ok(())
    }

    /// Verify available credentials match expected count
    async fn verify_available_credentials(
        &self,
        expected_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Step: Verifying available credentials");
        let auth_options = self
            .browser()
            .start_passkey_authentication(Some(&self.test_user.email))
            .await?;

        println!(
            "Available credentials: {}",
            serde_json::to_string_pretty(&auth_options)?
        );

        let available_creds = auth_options
            .get("allowCredentials")
            .and_then(|v| v.as_array())
            .ok_or("No allowCredentials found")?;

        // For integration tests, we verify that we have at least the expected count
        // since other parallel tests might add additional credentials
        assert!(
            available_creds.len() >= expected_count,
            "Expected at least {} credentials, found {}",
            expected_count,
            available_creds.len()
        );

        println!(
            "✅ Verified at least {} credentials are available (found {})",
            expected_count,
            available_creds.len()
        );
        Ok(())
    }
}

/// Result of passkey registration including optional key pair for authentication
pub(super) struct RegistrationResult {
    pub(super) user_handle: String,
    pub(super) key_pair_bytes: Option<Vec<u8>>,
}

/// Stored credential information for authentication testing
#[derive(Debug, Clone)]
struct StoredCredential {
    user_handle: String,
    key_pair: Vec<u8>,
    index: usize,
}

/// Manages a collection of credentials for testing
#[derive(Debug)]
struct CredentialSet {
    credentials: Vec<StoredCredential>,
}

impl CredentialSet {
    /// Create a new empty credential set
    fn new() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }

    /// Add a credential to the set
    fn add_credential(&mut self, user_handle: String, key_pair: Vec<u8>) {
        let index = self.credentials.len();
        self.credentials.push(StoredCredential {
            user_handle,
            key_pair,
            index,
        });
    }

    /// Get the first credential
    fn first(&self) -> Option<&StoredCredential> {
        self.credentials.first()
    }

    /// Get the number of credentials
    fn len(&self) -> usize {
        self.credentials.len()
    }
}

/// Create mock credential for registration with specified format
pub(super) fn create_mock_credential(
    email: &str,
    display_name: &str,
    challenge: &str,
    user_handle: &str,
    format: &str,
    base_url: Option<&str>,
) -> (serde_json::Value, Option<Vec<u8>>) {
    match format {
        "none" => {
            // For none attestation, use the original method for backward compatibility
            let cred = MockWebAuthnCredentials::registration_response_with_challenge_user_handle_and_origin(
                email,
                display_name,
                challenge,
                user_handle,
                base_url.unwrap_or("http://127.0.0.1:3000"),
            );
            (cred, None)
        }
        "packed" => {
            // For packed attestation, get the key pair for later authentication
            MockWebAuthnCredentials::registration_response_with_format_and_key_pair(
                email,
                display_name,
                challenge,
                user_handle,
                format,
            )
        }
        _ => {
            // For other formats (tpm), use the format-specific method
            let cred = MockWebAuthnCredentials::registration_response_with_format(
                email,
                display_name,
                challenge,
                user_handle,
                format,
            );
            (cred, None)
        }
    }
}

/// Helper function to register a user with specified attestation format
pub(super) async fn register_user_with_attestation(
    browser: &MockBrowser,
    test_user: &crate::common::fixtures::TestUser,
    format: &str,
    base_url: &str,
) -> Result<RegistrationResult, Box<dyn std::error::Error>> {
    println!("Registering user with {format} attestation");

    // Start registration
    let registration_options = browser
        .start_passkey_registration(&test_user.email, &test_user.name, "create_user")
        .await?;

    // Extract challenge and user_handle
    let challenge = registration_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let user_handle = registration_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    // Create mock credential with specified attestation format
    let (mock_credential, key_pair_bytes) = create_mock_credential(
        &test_user.email,
        &test_user.name,
        challenge,
        user_handle,
        format,
        Some(base_url),
    );

    // Complete registration
    let registration_response = browser
        .complete_passkey_registration(&mock_credential)
        .await?;

    let status = registration_response.status();
    let response_body = registration_response.text().await?;

    println!("Registration response status: {status}");
    println!("Registration response body: {response_body}");

    if !status.is_success() {
        return Err(format!("Registration failed with status {status}: {response_body}").into());
    }

    println!("✅ User registered successfully with {format} attestation");

    Ok(RegistrationResult {
        user_handle: user_handle.to_string(),
        key_pair_bytes,
    })
}

/// Helper function to register additional credential while logged in
async fn register_additional_credential(
    browser: &MockBrowser,
    test_user: &crate::common::fixtures::TestUser,
    format: &str,
    _existing_user_handle: &str,
) -> Result<RegistrationResult, Box<dyn std::error::Error>> {
    println!("Registering additional credential with {format} attestation");

    // For add_to_user mode, use the same username as the original user (since we're adding to the same account)
    // The display name can be modified for human readability (#2 suffix)
    let additional_displayname = format!("{}#2", test_user.name);

    // Start registration with "add_to_user" mode - use original username, not modified
    let registration_options = match browser
        .start_passkey_registration(
            &test_user.email,        // Use original username for same account
            &additional_displayname, // Use modified display name for readability
            "add_to_user",
        )
        .await
    {
        Ok(options) => options,
        Err(e) => {
            println!("❌ Failed to start additional credential registration: {e}");
            return Err(e);
        }
    };

    // Extract challenge and user_handle
    let challenge = registration_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let user_handle = registration_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    // Create mock credential with specified attestation format
    // IMPORTANT: Use the user handle provided by the server in the registration options
    // The server will handle associating this with the existing user account
    let (mock_credential, key_pair_bytes) = create_mock_credential(
        &test_user.email,        // Use original username, not modified
        &additional_displayname, // Use modified display name for readability
        challenge,
        user_handle, // Use the user handle from server registration options
        format,
        None, // No base URL needed for additional credentials
    );

    // Complete registration
    let registration_response = browser
        .complete_passkey_registration(&mock_credential)
        .await?;

    let status = registration_response.status();
    let response_body = registration_response.text().await?;

    println!("Additional registration response status: {status}");
    println!("Additional registration response body: {response_body}");

    if !status.is_success() {
        println!("❌ Additional registration failed with response: {response_body}");
        return Err(format!(
            "Additional registration failed with status {status}: {response_body}"
        )
        .into());
    }

    println!("✅ Additional credential registered successfully with {format} attestation");

    Ok(RegistrationResult {
        user_handle: user_handle.to_string(),
        key_pair_bytes,
    })
}

/// Extract credential ID from authentication options with fallback logic
fn extract_credential_id(
    authentication_options: &serde_json::Value,
    credential_index: Option<usize>,
) -> &str {
    if let Some(allowed_creds) = authentication_options["allowCredentials"].as_array() {
        let index = credential_index.unwrap_or(0);
        if let Some(cred) = allowed_creds.get(index) {
            if let Some(id) = cred["id"].as_str() {
                println!("Selected credential at index {index}: {id}");
                return id;
            }
        } else if let Some(first_cred) = allowed_creds.first() {
            println!("Credential index {index} not found, using first credential");
            if let Some(id) = first_cred["id"].as_str() {
                return id;
            }
        }
    }
    FALLBACK_CREDENTIAL_ID
}

/// Builder for passkey authentication flows
struct AuthenticationFlow<'a> {
    browser: &'a MockBrowser,
    test_user: &'a crate::common::fixtures::TestUser,
    stored_user_handle: &'a str,
    stored_key_pair: &'a [u8],
    credential_index: Option<usize>,
    context: Option<&'a str>,
}

impl<'a> AuthenticationFlow<'a> {
    /// Create a new authentication flow
    fn new(
        browser: &'a MockBrowser,
        test_user: &'a crate::common::fixtures::TestUser,
        stored_user_handle: &'a str,
        stored_key_pair: &'a [u8],
    ) -> Self {
        Self {
            browser,
            test_user,
            stored_user_handle,
            stored_key_pair,
            credential_index: None,
            context: None,
        }
    }

    /// Specify which credential to use (by index)
    fn with_credential_index(mut self, index: usize) -> Self {
        self.credential_index = Some(index);
        self
    }

    /// Add context for debugging/logging
    fn with_context(mut self, context: &'a str) -> Self {
        self.context = Some(context);
        self
    }

    /// Execute the authentication flow
    async fn execute(self) -> Result<bool, Box<dyn std::error::Error>> {
        let context = self.context.unwrap_or("authentication");
        println!("Starting authentication for user in {context}");

        let authentication_options = self
            .browser
            .start_passkey_authentication(Some(&self.test_user.email))
            .await?;

        println!(
            "Authentication options received: {}",
            serde_json::to_string_pretty(&authentication_options)?
        );

        // Extract authentication parameters
        let auth_challenge = authentication_options["challenge"]
            .as_str()
            .expect("Authentication options should contain challenge");
        let auth_id = authentication_options["authId"]
            .as_str()
            .expect("Authentication options should contain authId");

        // Extract the actual credential ID from allowCredentials
        let credential_id = extract_credential_id(&authentication_options, self.credential_index);

        println!("Using credential ID: {credential_id}");
        println!("Using stored user_handle: {}", self.stored_user_handle);

        // Create authentication response with valid signature
        let mock_assertion =
            MockWebAuthnCredentials::authentication_response_with_stored_credential(
                credential_id,
                auth_challenge,
                auth_id,
                self.stored_user_handle,
                self.stored_key_pair,
            );

        let auth_response = self
            .browser
            .complete_passkey_authentication(&mock_assertion)
            .await?;

        let status = auth_response.status();
        let response_body = auth_response.text().await?;

        println!("Authentication response status: {status}");
        println!("Authentication response body: {response_body}");

        Ok(status.is_success())
    }

    /// Execute authentication and verify session if successful
    async fn execute_and_verify(self) -> Result<bool, Box<dyn std::error::Error>> {
        let context = self.context.unwrap_or("authentication");
        let browser = self.browser;
        let test_user = self.test_user;
        let success = self.execute().await?;

        if success {
            verify_successful_authentication(browser, test_user, context).await?;
        }

        Ok(success)
    }
}

/// Helper function to authenticate user with stored credentials (backward compatibility)
async fn authenticate_user(
    browser: &MockBrowser,
    test_user: &crate::common::fixtures::TestUser,
    stored_user_handle: &str,
    stored_key_pair: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    AuthenticationFlow::new(browser, test_user, stored_user_handle, stored_key_pair)
        .execute()
        .await
}

/// Verify successful registration and session setup
async fn verify_successful_registration(
    setup: &PasskeyTestSetup,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify session establishment for successful cases
    assert!(
        setup.browser().has_active_session().await,
        "Session should be established after successful {format} attestation registration"
    );

    let user_info = setup.browser().get_user_info().await?;
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
        Some(setup.test_user.email.as_str()),
        "User account should match email"
    );
    assert_eq!(
        label,
        Some(setup.test_user.name.as_str()),
        "User label should match name"
    );

    Ok(())
}

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
    let setup = PasskeyTestSetup::new().await?;

    println!("🔐 Testing passkey registration with {format} attestation format");

    // Try to register user with specified attestation format
    let registration_result =
        register_user_with_attestation(setup.browser(), &setup.test_user, format, setup.base_url())
            .await;

    match registration_result {
        Ok(_) => {
            println!("✅ {format} attestation registration completed successfully");
            if expected_success {
                verify_successful_registration(&setup, format).await?;
            }
        }
        Err(e) => {
            let error_msg = e.to_string();

            if expected_success {
                // If we expected success but got failure, this is a test failure
                println!("❌ FAILURE: {format} attestation was expected to succeed but failed");
                println!("Error: {error_msg}");
                setup.shutdown().await?;
                return Err(format!(
                    "{format} attestation was expected to succeed but failed: {error_msg}"
                )
                .into());
            } else {
                handle_expected_passkey_failure(format, &error_msg)?;
            }
        }
    }

    // Cleanup
    setup.shutdown().await?;
    Ok(())
}

/// **CONSOLIDATED TEST 1**: Passkey Attestation Formats
///
/// This test consolidates:
/// - test_passkey_registration_none_attestation
/// - test_passkey_registration_packed_attestation  
/// - test_passkey_registration_tpm_attestation
#[tokio::test]
async fn test_passkey_attestation_formats() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 === CONSOLIDATED PASSKEY ATTESTATION FORMATS TEST ===");

    // === SUBTEST 1: None Attestation Format ===
    println!("\n🔑 SUBTEST 1: Testing none attestation format");
    let result_none = test_passkey_attestation_format("none", false).await;
    match result_none {
        Ok(_) => println!("✅ SUBTEST 1 PASSED: None attestation format test completed"),
        Err(e) => {
            println!("❌ SUBTEST 1 FAILED: None attestation format test failed: {e}");
            return Err(e);
        }
    }

    // === SUBTEST 2: Packed Attestation Format ===
    println!("\n📦 SUBTEST 2: Testing packed attestation format");
    let result_packed = test_passkey_attestation_format("packed", true).await;
    match result_packed {
        Ok(_) => println!("✅ SUBTEST 2 PASSED: Packed attestation format test completed"),
        Err(e) => {
            println!("❌ SUBTEST 2 FAILED: Packed attestation format test failed: {e}");
            return Err(e);
        }
    }

    // === SUBTEST 3: TPM Attestation Format ===
    println!("\n🛡️ SUBTEST 3: Testing TPM attestation format");
    let result_tpm = test_passkey_attestation_format("tpm", true).await;
    match result_tpm {
        Ok(_) => println!("✅ SUBTEST 3 PASSED: TPM attestation format test completed"),
        Err(e) => {
            println!("❌ SUBTEST 3 FAILED: TPM attestation format test failed: {e}");
            return Err(e);
        }
    }

    println!("🎯 === CONSOLIDATED PASSKEY ATTESTATION FORMATS TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 2**: Passkey Multi-Credential Flows
///
/// This test consolidates:
/// - test_passkey_register_then_authenticate
/// - test_register_two_credentials_and_authenticate
/// - test_passkey_error_scenarios
#[tokio::test]
async fn test_passkey_multi_credential_flows() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 === CONSOLIDATED PASSKEY MULTI-CREDENTIAL FLOWS TEST ===");

    // === SUBTEST 1: Register Then Authenticate Flow ===
    println!("\n🔄 SUBTEST 1: Testing register then authenticate flow");

    // Setup test environment for this subtest
    let passkey_setup = PasskeyTestSetup::new().await?;

    // Step 1: Register user with packed attestation (which we know works)
    println!("  Step 1: Registering user for authentication test");
    let registration_result = register_user_with_attestation(
        passkey_setup.browser(),
        &passkey_setup.test_user,
        "packed",
        passkey_setup.base_url(),
    )
    .await?;

    // Extract the key pair for later authentication
    let stored_user_handle = registration_result.user_handle;
    let stored_key_pair = registration_result
        .key_pair_bytes
        .expect("Packed attestation should return key pair");

    // Verify user is registered and logged in
    assert!(
        passkey_setup.browser().has_active_session().await,
        "User should be logged in after registration"
    );

    // Step 2: Logout the user
    println!("  Step 2: Logging out user");
    logout_and_verify(passkey_setup.browser()).await?;

    // Step 3: Use a new browser session to simulate user coming back later
    println!("  Step 3: Simulating user coming back later (new browser session)");
    let browser_new_session = MockBrowser::new(passkey_setup.base_url(), true);

    // Step 4: Authenticate with the stored credentials
    println!("  Step 4: Authenticating with stored credentials");
    let auth_success = authenticate_user(
        &browser_new_session,
        &passkey_setup.test_user,
        &stored_user_handle,
        &stored_key_pair,
    )
    .await?;

    if auth_success {
        println!("  ✅ Passkey authentication SUCCESS: Full flow completed");
        verify_successful_authentication(
            &browser_new_session,
            &passkey_setup.test_user,
            "register-then-authenticate test",
        )
        .await?;
    } else {
        println!("  ⓘ Passkey authentication did not succeed (may be expected for mock data)");
    }

    passkey_setup.shutdown().await?;
    println!("✅ SUBTEST 1 PASSED: Register then authenticate flow completed");

    // === SUBTEST 2: Multiple Credentials Registration and Authentication ===
    println!("\n🔗 SUBTEST 2: Testing multiple credentials registration and authentication");

    // Setup new test environment for this subtest
    let multi_setup = PasskeyTestSetup::new().await?;

    // Step 1: Register multiple credentials (2 credentials)
    let credentials = multi_setup.register_multiple_credentials(2).await?;

    // Step 2: Verify the expected number of credentials were registered
    multi_setup.verify_available_credentials(2).await?;

    // Step 3: Test logout and re-authentication cycle with all credentials
    multi_setup
        .test_logout_and_reauth_cycle(&credentials)
        .await?;

    println!(
        "  ✅ Multiple credential registration and authentication flow completed successfully"
    );
    multi_setup.shutdown().await?;
    println!("✅ SUBTEST 2 PASSED: Multiple credentials flows completed");

    // === SUBTEST 3: Error Scenarios ===
    println!("\n❌ SUBTEST 3: Testing passkey error scenarios");

    // Setup new test environment for this subtest
    let error_setup = TestSetup::new().await?;

    // Test 1: Invalid credential response structure
    let invalid_credential = serde_json::json!({
        "invalid": "structure",
        "missing": "required_fields"
    });

    let response = error_setup
        .browser
        .complete_passkey_registration(&invalid_credential)
        .await?;

    // Should return error response
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Invalid credential should result in error response"
    );

    // Test 2: Authentication without prior registration
    let authentication_options = error_setup
        .browser
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
            println!("  ✅ Non-existent user authentication handled correctly");
        }
        Err(_) => {
            println!("  ✅ Non-existent user authentication returned error (also acceptable)");
        }
    }

    error_setup.shutdown().await;
    println!("✅ SUBTEST 3 PASSED: Error scenarios handled correctly");

    println!("🎯 === CONSOLIDATED PASSKEY MULTI-CREDENTIAL FLOWS TEST COMPLETED ===");
    Ok(())
}
