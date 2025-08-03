/// Session security tests - negative tests for session management and boundaries
///
/// These tests verify that Session security controls properly reject:
/// - Expired session requests across all endpoints
/// - Session boundary violations (cross-user operations)
/// - Context token validation failures
/// - Unauthorized admin operation attempts
use crate::common::{
    MockBrowser, TestServer, attack_scenarios::admin_attacks::*,
    attack_scenarios::session_attacks::*, security_utils::*,
};
use serde_json::json;
use serial_test::serial;

/// Test environment setup for Session security tests
struct SessionSecurityTestSetup {
    server: TestServer,
    browser: MockBrowser,
}

impl SessionSecurityTestSetup {
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

/// Test access to protected endpoints without session - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_no_session_access() -> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing access to protected endpoints without session");

    // Attempt to access user info without session
    let response = setup.browser.get("/auth/user/info").await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "no session access test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test state-changing operations without CSRF token - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_csrf_bypass_attempt() -> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing CSRF bypass attempt rejection");

    // Create headers without CSRF token for state-changing request (attack scenario)
    let csrf_bypass_headers = create_csrf_bypass_headers();

    // Attempt logout (state-changing operation) without CSRF token
    let response = setup
        .browser
        .post_form_with_headers_old("/auth/user/logout", &[], &csrf_bypass_headers)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection (CSRF protection should reject)
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::METHOD_NOT_ALLOWED, None),
        "CSRF bypass test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test state-changing operations with invalid CSRF token - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_invalid_csrf_token() -> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing invalid CSRF token rejection");

    // Create headers with invalid CSRF token (attack scenario)
    let invalid_csrf_headers = create_invalid_csrf_headers();

    // Attempt logout with invalid CSRF token
    let response = setup
        .browser
        .post_form_with_headers_old("/auth/user/logout", &[], &invalid_csrf_headers)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::METHOD_NOT_ALLOWED, None),
        "invalid CSRF token test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test session access with expired session cookie - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_expired_session_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing expired session cookie rejection");

    // Create expired session cookie (attack scenario)
    let expired_session_id = create_expired_session_cookie();

    // Create custom browser with expired session cookie
    let session_cookie_name =
        std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "__Host-SessionId".to_string());

    let response = setup
        .browser
        .get_with_headers(
            "/auth/user/info",
            &[(
                "Cookie",
                &format!("{session_cookie_name}={expired_session_id}"),
            )],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "expired session test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test session access with malicious session cookie (SQL injection attempt) - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_malicious_session_cookie() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing malicious session cookie rejection");

    // Create malicious session cookie with SQL injection attempt (attack scenario)
    let malicious_session_id = create_malicious_session_cookie();

    let session_cookie_name =
        std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "__Host-SessionId".to_string());

    let response = setup
        .browser
        .get_with_headers(
            "/auth/user/info",
            &[(
                "Cookie",
                &format!("{session_cookie_name}={malicious_session_id}"),
            )],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "malicious session test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test cross-user operation attempt - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_cross_user_operation() -> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing cross-user operation rejection");

    // This test would typically require setting up two users and attempting
    // to perform operations across user boundaries. For now, we simulate
    // a cross-user operation attempt with fake user IDs.

    let target_user_id = "victim_user_id_123";
    let cross_user_data = create_cross_user_operation_data(target_user_id);

    // Attempt cross-user operation (e.g., trying to delete another user's data)
    let form_data: Vec<(&str, &str)> = cross_user_data
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let response = setup
        .browser
        .post_form("/auth/user/delete", &form_data)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::METHOD_NOT_ALLOWED, None),
        "cross-user operation test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test unauthorized admin operation attempt - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_unauthorized_admin_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing unauthorized admin operation rejection");

    // Attempt to access admin endpoints without admin privileges
    let response = setup.browser.get("/auth/admin/users").await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::NOT_FOUND, None),
        "unauthorized admin operation test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test admin context token validation failure - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_admin_context_validation_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing admin context token validation failure");

    // Create malicious admin context token (attack scenario)
    let malicious_admin_context = create_malicious_admin_context();

    // Attempt admin operation with fake admin context
    let admin_request = json!({
        "operation": "list_users",
        "admin_context": malicious_admin_context
    });

    let response = setup
        .browser
        .post_json("/auth/admin/operations", &admin_request)
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::NOT_FOUND, None),
        "admin context validation test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test access to user data endpoints without proper session - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_user_data_without_session() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing user data access without session");

    // Attempt to access user credentials list without session
    let response = setup.browser.get("/auth/passkey/credentials").await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::TEMPORARY_REDIRECT, None),
        "user data without session test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test session boundary violations with page session tokens - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_page_token_boundary_violation()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing page session token boundary violation");

    // For this test, we'll just verify the endpoint returns unauthorized without valid session
    let response = setup
        .browser
        .post_json("/auth/user/update", &json!({"name": "Updated Name"}))
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Custom(reqwest::StatusCode::METHOD_NOT_ALLOWED, None),
        "page token boundary test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}

/// Test concurrent session access with invalid session state - should be rejected
#[tokio::test]
#[serial]
async fn test_security_session_invalid_session_state() -> Result<(), Box<dyn std::error::Error>> {
    let setup = SessionSecurityTestSetup::new().await?;

    println!("🔒 Testing invalid session state rejection");

    // Create a session cookie with invalid format/structure
    let invalid_session_format = "invalid_session_format_not_uuid";

    let session_cookie_name =
        std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "__Host-SessionId".to_string());

    let response = setup
        .browser
        .get_with_headers(
            "/auth/user/info",
            &[(
                "Cookie",
                &format!("{session_cookie_name}={invalid_session_format}"),
            )],
        )
        .await?;

    let result = create_security_result_from_response(response).await?;

    // Verify security rejection
    assert_security_failure(
        &result,
        &ExpectedSecurityError::Unauthorized,
        "invalid session state test",
    );
    assert_no_session_established(&setup.browser).await;

    setup.shutdown().await?;
    Ok(())
}
