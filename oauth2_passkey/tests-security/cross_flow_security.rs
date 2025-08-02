/// Cross-flow security tests - negative tests for interactions between auth flows
///
/// These tests verify that security controls properly prevent:
/// - Account linking without proper authentication
/// - Credential addition with invalid session context
/// - CSRF protection across different authentication methods
/// - Cross-user operation attempts during account linking
use crate::common::{
    MockBrowser, TestServer, TestUsers, attack_scenarios::admin_attacks::*,
    attack_scenarios::cross_flow_attacks::*, security_utils::*,
};
use serde_json::json;
use serial_test::serial;

/// Test environment setup for Cross-flow security tests
struct CrossFlowSecurityTestSetup {
    server: TestServer,
    browser: MockBrowser,
}

impl CrossFlowSecurityTestSetup {
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

/// Test unauthenticated account linking attempt - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_unauthenticated_linking() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing unauthenticated account linking rejection");

    // Create unauthenticated linking request (attack scenario)
    let linking_data = create_unauthenticated_linking_request();

    // Convert HashMap to form data
    let form_data: Vec<(&str, &str)> = linking_data
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Attempt to start OAuth2 linking without authenticated session
    let response = setup
        .browser
        .post_form("/auth/oauth2/google", &form_data)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::METHOD_NOT_ALLOWED, None),
        "unauthenticated linking test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test credential addition with invalid session context - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_invalid_context_credential_addition()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing credential addition with invalid context rejection");

    // Create invalid context credential request (attack scenario)
    let invalid_context_data = create_invalid_context_credential_request();

    // Attempt to add passkey credential with invalid context
    let request_json = json!(invalid_context_data);

    let response = setup
        .browser
        .post_json("/auth/passkey/register/start", &request_json)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "invalid context credential test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test cross-user credential addition attempt - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_cross_user_credential_addition()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing cross-user credential addition rejection");

    let victim_user_id = "victim_user_12345";

    // Create cross-user credential request (attack scenario)
    let cross_user_data = create_cross_user_credential_request(victim_user_id);

    // Attempt to add credential to another user's account
    let request_json = json!(cross_user_data);

    let response = setup
        .browser
        .post_json("/auth/passkey/register/start", &request_json)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::UNPROCESSABLE_ENTITY, None),
        "cross-user credential test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test CSRF protection across different authentication methods - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_csrf_protection_across_methods()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing CSRF protection across authentication methods");

    // Attempt OAuth2 callback without CSRF token
    let response = setup
        .browser
        .post_form(
            "/auth/oauth2/authorized",
            &[("code", "test_code"), ("state", "test_state")],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "CSRF across methods test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test privilege escalation attempt during account linking - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_privilege_escalation_during_linking()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing privilege escalation during account linking rejection");

    // Create privilege escalation data (attack scenario)
    let escalation_data = create_privilege_escalation_data();

    // Convert HashMap to form data
    let form_data: Vec<(&str, &str)> = escalation_data
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Attempt privilege escalation during OAuth2 flow
    let response = setup
        .browser
        .post_form("/auth/oauth2/google", &form_data)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::METHOD_NOT_ALLOWED, None),
        "privilege escalation test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test unauthorized admin operation during credential management - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_unauthorized_admin_during_credential_mgmt()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing unauthorized admin operation during credential management");

    // Create unauthorized admin request (attack scenario)
    let admin_data = create_unauthorized_admin_request();

    // Attempt admin operation during credential management
    let request_json = json!(admin_data);

    let response = setup
        .browser
        .post_json("/auth/admin/credentials", &request_json)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::NOT_FOUND, None),
        "unauthorized admin during credential mgmt test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test mixed authentication context confusion - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_mixed_auth_context_confusion()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing mixed authentication context confusion rejection");

    let test_user = TestUsers::passkey_user();

    // Attempt to start passkey registration but send OAuth2 parameters
    let mixed_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "add_to_user",
        // OAuth2 parameters that shouldn't be here
        "code": "oauth2_auth_code",
        "state": "oauth2_state_param",
        "scope": "openid email profile"
    });

    let response = setup
        .browser
        .post_json("/auth/passkey/register/start", &mixed_request)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "mixed auth context test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test account linking with session fixation attempt - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_session_fixation_during_linking()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing session fixation during account linking rejection");

    // Attempt to fixate session ID during OAuth2 linking
    let fixed_session_id = "attacker_controlled_session_id_12345";
    let session_cookie_name =
        std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "__Host-SessionId".to_string());

    let response = setup
        .browser
        .get_with_headers(
            "/auth/oauth2/google?mode=add_to_user",
            &[(
                "Cookie",
                &format!("{}={}", session_cookie_name, fixed_session_id),
            )],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::BadRequest,
        "session fixation test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test concurrent authentication flow interference - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_concurrent_auth_interference()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing concurrent authentication flow interference rejection");

    let test_user = TestUsers::passkey_user();

    // Start a passkey registration
    let passkey_request = json!({
        "username": test_user.email,
        "displayname": test_user.name,
        "mode": "create_user"
    });

    let _passkey_start = setup
        .browser
        .post_json("/auth/passkey/register/start", &passkey_request)
        .await?;

    // While passkey flow is ongoing, attempt OAuth2 flow (should be rejected due to state confusion)
    let response = setup
        .browser
        .get("/auth/oauth2/google?mode=create_user_or_login")
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (concurrent flows should not be allowed)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::SEE_OTHER, None),
        "concurrent auth interference test",
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test authentication bypass via flow switching - should be rejected
#[tokio::test]
#[serial]
async fn test_security_cross_flow_auth_bypass_via_flow_switching()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = CrossFlowSecurityTestSetup::new().await?;

    println!("🔒 Testing authentication bypass via flow switching rejection");

    // Attempt to start OAuth2 flow then switch to passkey completion endpoint
    let _oauth2_start = setup
        .browser
        .get("/auth/oauth2/google?mode=create_user_or_login")
        .await?;

    // Try to complete with passkey finish endpoint (wrong flow)
    let fake_passkey_response = json!({
        "id": "fake_credential_id",
        "rawId": "ZmFrZV9jcmVkZW50aWFsX2lk",
        "response": {
            "clientDataJSON": "fake_client_data",
            "attestationObject": "fake_attestation"
        },
        "type": "public-key"
    });

    let response = setup
        .browser
        .post_json("/auth/passkey/register/finish", &fake_passkey_response)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::UNPROCESSABLE_ENTITY, None),
        "auth bypass via flow switching test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}
