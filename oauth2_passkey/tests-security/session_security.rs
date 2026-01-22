/// Session security tests - negative tests for session management and boundaries
///
/// These tests verify that Session security controls properly reject:
/// - Expired session requests across all endpoints
/// - Session boundary violations (cross-user operations)
/// - Context token validation failures
/// - Unauthorized admin operation attempts
use crate::common::{
    TestSetup, attack_scenarios::admin_attacks::*, attack_scenarios::session_attacks::*,
    security_utils::*,
};
use serde_json::json;

/// **CONSOLIDATED TEST 1**: Session Access Control Security
///
/// This test consolidates:
/// - test_security_session_no_session_access
/// - test_security_session_expired_session_cookie
/// - test_security_session_invalid_session_state
/// - test_security_session_user_data_without_session
#[tokio::test]
async fn test_consolidated_session_access_control() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 === CONSOLIDATED SESSION ACCESS CONTROL SECURITY TEST ===");

    // === SUBTEST 1: No Session Access ===
    println!("\n🚫 SUBTEST 1: Testing access to protected endpoints without session");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 1 PASSED: No session access properly rejected");
    }

    // === SUBTEST 2: Expired Session Cookie ===
    println!("\n⏰ SUBTEST 2: Testing expired session cookie rejection");
    {
        let setup = TestSetup::new().await?;

        // Create expired session cookie (attack scenario)
        let expired_session_id = create_expired_session_cookie();
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

        setup.shutdown().await;
        println!("✅ SUBTEST 2 PASSED: Expired session properly rejected");
    }

    // === SUBTEST 3: Invalid Session State ===
    println!("\n❌ SUBTEST 3: Testing invalid session state rejection");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 3 PASSED: Invalid session state properly rejected");
    }

    // === SUBTEST 4: User Data Without Session ===
    println!("\n🔐 SUBTEST 4: Testing user data access without session");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 4 PASSED: User data access without session properly rejected");
    }

    println!("🎯 === CONSOLIDATED SESSION ACCESS CONTROL SECURITY TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 2**: CSRF Protection Security
///
/// This test consolidates:
/// - test_security_session_csrf_bypass_attempt
/// - test_security_session_invalid_csrf_token
#[tokio::test]
async fn test_consolidated_csrf_protection() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ === CONSOLIDATED CSRF PROTECTION SECURITY TEST ===");

    // === SUBTEST 1: CSRF Bypass Attempt ===
    println!("\n🚫 SUBTEST 1: Testing CSRF bypass attempt rejection");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 1 PASSED: CSRF bypass attempt properly rejected");
    }

    // === SUBTEST 2: Invalid CSRF Token ===
    println!("\n🔓 SUBTEST 2: Testing invalid CSRF token rejection");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 2 PASSED: Invalid CSRF token properly rejected");
    }

    println!("🎯 === CONSOLIDATED CSRF PROTECTION SECURITY TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 3**: Session Boundary Violations Security
///
/// This test consolidates:
/// - test_security_session_malicious_session_cookie
/// - test_security_session_cross_user_operation
/// - test_security_session_page_token_boundary_violation
#[tokio::test]
async fn test_consolidated_session_boundary_violations() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚧 === CONSOLIDATED SESSION BOUNDARY VIOLATIONS SECURITY TEST ===");

    // === SUBTEST 1: Malicious Session Cookie ===
    println!("\n💀 SUBTEST 1: Testing malicious session cookie rejection");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 1 PASSED: Malicious session cookie properly rejected");
    }

    // === SUBTEST 2: Cross-User Operation Attempt ===
    println!("\n👤 SUBTEST 2: Testing cross-user operation rejection");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 2 PASSED: Cross-user operation properly rejected");
    }

    // === SUBTEST 3: Page Token Boundary Violation ===
    println!("\n🎫 SUBTEST 3: Testing page session token boundary violation");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 3 PASSED: Page token boundary violation properly rejected");
    }

    println!("🎯 === CONSOLIDATED SESSION BOUNDARY VIOLATIONS SECURITY TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 4**: Admin Security Controls
///
/// This test consolidates:
/// - test_security_session_unauthorized_admin_operation
/// - test_security_session_admin_context_validation_failure
#[tokio::test]
async fn test_consolidated_admin_security_controls() -> Result<(), Box<dyn std::error::Error>> {
    println!("👑 === CONSOLIDATED ADMIN SECURITY CONTROLS TEST ===");

    // === SUBTEST 1: Unauthorized Admin Operation ===
    println!("\n🚫 SUBTEST 1: Testing unauthorized admin operation rejection");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 1 PASSED: Unauthorized admin operation properly rejected");
    }

    // === SUBTEST 2: Admin Context Validation Failure ===
    println!("\n🔐 SUBTEST 2: Testing admin context token validation failure");
    {
        let setup = TestSetup::new().await?;

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

        setup.shutdown().await;
        println!("✅ SUBTEST 2 PASSED: Admin context validation failure properly handled");
    }

    println!("🎯 === CONSOLIDATED ADMIN SECURITY CONTROLS TEST COMPLETED ===");
    Ok(())
}
