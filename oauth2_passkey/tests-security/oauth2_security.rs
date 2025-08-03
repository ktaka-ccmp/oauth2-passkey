/// OAuth2 security tests - negative tests for OAuth2 authentication flows
///
/// These tests verify that OAuth2 security controls properly reject:
/// - Invalid/tampered state parameters
/// - CSRF token mismatches and missing tokens
/// - Nonce verification failures in ID tokens
/// - Invalid authorization codes
/// - PKCE code challenge verification failures
/// - Redirect URI validation failures
/// - Origin header validation failures
use crate::common::{
    MockBrowser, TestServer, attack_scenarios::oauth2_attacks::*, security_utils::*,
};
use serial_test::serial;

/// Test environment setup for OAuth2 security tests
struct OAuth2SecurityTestSetup {
    server: TestServer,
    browser: MockBrowser,
}

impl OAuth2SecurityTestSetup {
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

/// Test OAuth2 with empty state parameter - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_empty_state_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 empty state parameter rejection");

    // Create empty state (attack scenario)
    let empty_state = create_empty_state();
    let valid_code = "valid_auth_code_123";

    // Attempt OAuth2 callback with empty state
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", &empty_state)],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "empty state test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with malformed state parameter - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_malformed_state_rejection() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 malformed state parameter rejection");

    // Create malformed state (attack scenario)
    let malformed_state = create_malformed_state();
    let valid_code = "valid_auth_code_123";

    // Attempt OAuth2 callback with malformed state
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", &malformed_state)],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "malformed state test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with invalid JSON in state parameter - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_invalid_json_state_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 invalid JSON state parameter rejection");

    // Create state with invalid JSON (attack scenario)
    let invalid_json_state = create_invalid_json_state();
    let valid_code = "valid_auth_code_123";

    // Attempt OAuth2 callback with invalid JSON state
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", &invalid_json_state)],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "invalid JSON state test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with incomplete state parameter (missing required fields) - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_incomplete_state_rejection() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 incomplete state parameter rejection");

    // Create state with missing required fields (attack scenario)
    let incomplete_state = create_incomplete_state();
    let valid_code = "valid_auth_code_123";

    // Attempt OAuth2 callback with incomplete state
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", &incomplete_state)],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "incomplete state test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with expired state parameter tokens - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_expired_state_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 expired state parameter rejection");

    // Create state with expired token IDs (attack scenario)
    let expired_state = create_expired_state();
    let valid_code = "valid_auth_code_123";

    // Attempt OAuth2 callback with expired state
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", &expired_state)],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (likely 401 or 403 for expired tokens)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "expired state test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with invalid authorization code - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_invalid_auth_code_rejection() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 invalid authorization code rejection");

    // Create invalid authorization code (attack scenario)
    let invalid_code = create_invalid_auth_code();
    let valid_state = "dmFsaWRfc3RhdGVfcGFyYW1ldGVy"; // Valid base64 state for this test

    // Attempt OAuth2 callback with invalid auth code
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", &invalid_code), ("state", valid_state)],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "invalid auth code test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with malicious origin headers - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_malicious_origin_rejection() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 malicious origin header rejection");

    // Create malicious origin headers (attack scenario)
    let malicious_headers = create_malicious_origin_headers();
    let valid_code = "valid_auth_code_123";
    let valid_state = "dmFsaWRfc3RhdGVfcGFyYW1ldGVy"; // Valid base64 state

    // Attempt OAuth2 callback with malicious origin
    let response = setup
        .browser
        .post_form_with_headers_old(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", valid_state)],
            &malicious_headers,
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (origin validation should fail)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "malicious origin test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 with missing origin headers - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_missing_origin_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 missing origin header rejection");

    // Create headers without origin/referer (attack scenario)
    let missing_origin_headers = create_missing_origin_headers();
    let valid_code = "valid_auth_code_123";
    let valid_state = "dmFsaWRfc3RhdGVfcGFyYW1ldGVy"; // Valid base64 state

    // Attempt OAuth2 callback without origin headers
    let response = setup
        .browser
        .post_form_with_headers_old(
            "/auth/oauth2/authorized",
            &[("code", valid_code), ("state", valid_state)],
            &missing_origin_headers,
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (missing origin should fail validation)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "missing origin test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 GET request with form_post response mode - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_get_form_post_mode_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 GET request rejection in form_post mode");

    let valid_code = "valid_auth_code_123";
    let valid_state = "dmFsaWRfc3RhdGVfcGFyYW1ldGVy"; // Valid base64 state

    // Attempt OAuth2 callback with GET when form_post is configured
    // (This tests the HTTP method validation in authorized_core)
    let response = setup
        .browser
        .get(&format!(
            "/auth/oauth2/authorized?code={valid_code}&state={valid_state}"
        ))
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (wrong HTTP method for response mode)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "GET form_post mode test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test OAuth2 start endpoint with no existing session (for add_to_user mode) - should be rejected
#[tokio::test]
#[serial]
async fn test_security_oauth2_add_to_user_no_session_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = OAuth2SecurityTestSetup::new().await?;

    println!("🔒 Testing OAuth2 add_to_user mode without session rejection");

    // Attempt to start OAuth2 flow in add_to_user mode without existing session
    let response = setup
        .browser
        .get("/auth/oauth2/google?mode=add_to_user")
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (add_to_user requires existing session)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "add_to_user no session test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}
