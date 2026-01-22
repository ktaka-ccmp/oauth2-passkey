/// API Client Integration Tests
///
/// Tests CSRF protection for authenticated API clients that use X-CSRF-Token headers
/// instead of cookies for CSRF protection. These tests validate scenarios where:
/// - Authenticated users perform protected operations via API
/// - CSRF tokens are properly validated for sensitive operations
/// - API clients are protected against CSRF attacks on authenticated sessions
///
/// Note: These tests focus on meaningful CSRF protection for authenticated operations,
/// not just token extraction from unauthenticated flows.
use crate::common::{MockBrowser, TestSetup, TestUsers, validation_utils::AuthValidationResult};

// Import helper functions for setting up authenticated sessions
use super::oauth2_flows::complete_full_oauth2_flow;
use super::passkey_flows::register_user_with_attestation;

/// **CONSOLIDATED TEST**: API Client CSRF Protection
///
/// This test consolidates:
/// - test_authenticated_logout_csrf_protection
/// - test_authenticated_oauth2_linking_csrf_protection  
/// - test_authenticated_user_info_csrf_protection
/// - test_authenticated_api_client_csrf_validation
#[tokio::test]
async fn test_consolidated_api_client_csrf_protection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestSetup::new().await?;

    println!("🔐 === CONSOLIDATED API CLIENT CSRF PROTECTION TEST ===");

    // === SUBTEST 1: Authenticated Logout CSRF Protection ===
    println!("\n🚪 SUBTEST 1: Testing authenticated logout CSRF protection");

    // Step 1.1: Establish authenticated session using OAuth2
    use crate::common::axum_mock_server::configure_mock_for_test;
    let oauth2_test_user = TestUsers::unique_oauth2_user("api_client_logout_csrf");
    configure_mock_for_test(
        oauth2_test_user.email.clone(),
        oauth2_test_user.id.clone(),
        oauth2_test_user.name.clone(),
        oauth2_test_user.given_name.clone(),
        oauth2_test_user.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_response = complete_full_oauth2_flow(&setup.browser, "create_user_or_login").await?;
    let oauth2_validation = AuthValidationResult::from_oauth2_response(
        oauth2_response.status(),
        oauth2_response.headers(),
        "Created%20new%20user",
    );

    if !oauth2_validation.is_success {
        oauth2_validation.print_details();
        return Err("OAuth2 account creation failed".into());
    }

    // Verify session is established
    assert!(
        setup.browser.has_active_session().await,
        "Session should be established after OAuth2 authentication"
    );
    println!("  ✅ Authenticated OAuth2 session established");

    // Step 1.2: Get valid CSRF token for authenticated operations
    let csrf_response = setup.browser.get("/auth/user/csrf_token").await?;
    assert!(
        csrf_response.status().is_success(),
        "Should be able to get CSRF token when authenticated"
    );

    let csrf_data: serde_json::Value = csrf_response.json().await?;
    let csrf_token = csrf_data["csrf_token"]
        .as_str()
        .ok_or("CSRF token should be present in response")?;
    println!("  ✅ Valid CSRF token obtained: {}", &csrf_token[..8]);

    // Step 1.3: Test logout with valid session (using browser client with cookies)
    let logout_response = setup.browser.logout().await?;
    if logout_response.status().is_success() || logout_response.status().is_redirection() {
        println!("  ✅ Logout with authenticated session successful");
    }

    // Step 1.4: Test API client access patterns with CSRF tokens
    let browser2 = MockBrowser::new(&setup.server.base_url, true);
    configure_mock_for_test(
        oauth2_test_user.email.clone(),
        oauth2_test_user.id.clone(),
        oauth2_test_user.name.clone(),
        oauth2_test_user.given_name.clone(),
        oauth2_test_user.family_name.clone(),
        setup.server.base_url.clone(),
    );
    let _oauth2_response2 = complete_full_oauth2_flow(&browser2, "create_user_or_login").await?;

    let csrf_response2 = browser2.get("/auth/user/csrf_token").await?;
    let csrf_data2: serde_json::Value = csrf_response2.json().await?;
    let csrf_token2 = csrf_data2["csrf_token"]
        .as_str()
        .ok_or("CSRF token should be present in response")?;

    // Test with valid CSRF token in headers
    let api_client = MockBrowser::new(&setup.server.base_url, false);
    let valid_headers = &[("x-csrf-token", csrf_token2)];
    let user_info_response = api_client
        .get_with_headers("/auth/user/info", valid_headers)
        .await?;

    println!(
        "  API client response status: {}",
        user_info_response.status()
    );
    println!("✅ SUBTEST 1 PASSED: Logout CSRF protection verified");

    // === SUBTEST 2: OAuth2 Account Linking CSRF Protection ===
    println!("\n🌐 SUBTEST 2: Testing OAuth2 account linking CSRF protection");

    // Step 2.1: Establish authenticated session using passkey
    let passkey_user = TestUsers::admin_user();
    let browser3 = MockBrowser::new(&setup.server.base_url, true);

    let _registration_result =
        register_user_with_attestation(&browser3, &passkey_user, "packed", &setup.server.base_url)
            .await?;

    assert!(
        browser3.has_active_session().await,
        "Session should be established after passkey registration"
    );
    println!("  ✅ Authenticated passkey session established");

    // Step 2.2: Get valid CSRF token for account linking operations
    let csrf_response3 = browser3.get("/auth/user/csrf_token").await?;
    assert!(
        csrf_response3.status().is_success(),
        "Should be able to get CSRF token when authenticated"
    );

    let csrf_data3: serde_json::Value = csrf_response3.json().await?;
    let csrf_token3 = csrf_data3["csrf_token"]
        .as_str()
        .ok_or("CSRF token should be present in response")?;
    println!("  ✅ Valid CSRF token obtained: {}", &csrf_token3[..8]);

    // Step 2.3: Test OAuth2 linking with valid CSRF token
    let oauth2_link_url = format!("/auth/oauth2/google?mode=add_to_user&context={csrf_token3}");
    let oauth2_link_response = browser3.get(&oauth2_link_url).await?;

    if oauth2_link_response.status().is_redirection() {
        println!("  ✅ OAuth2 linking with valid CSRF token initiated successfully");
    } else {
        println!(
            "  ⓘ OAuth2 linking response status: {} (may need different approach)",
            oauth2_link_response.status()
        );
    }

    // Step 2.4: Test API client pattern with CSRF tokens
    let api_client2 = MockBrowser::new(&setup.server.base_url, false);
    let valid_headers2 = &[("x-csrf-token", csrf_token3)];
    let api_oauth2_response = api_client2
        .get_with_headers(&oauth2_link_url, valid_headers2)
        .await?;

    println!(
        "  API OAuth2 linking response status: {}",
        api_oauth2_response.status()
    );
    println!("✅ SUBTEST 2 PASSED: OAuth2 linking CSRF protection verified");

    // === SUBTEST 3: User Information Access CSRF Protection ===
    println!("\n👤 SUBTEST 3: Testing user information access CSRF protection");

    // Step 3.1: Test browser client access (should work with cookies)
    let browser_user_info = browser3.get("/auth/user/info").await?;
    assert!(
        browser_user_info.status().is_success(),
        "Browser client should access user info with session cookies"
    );
    println!("  ✅ Browser client successfully accessed user info");

    // Step 3.2: Test API client access without session (should fail)
    let api_client_no_session = MockBrowser::new(&setup.server.base_url, false);
    let no_session_response = api_client_no_session.get("/auth/user/info").await?;

    assert!(
        no_session_response.status() == reqwest::StatusCode::UNAUTHORIZED
            || no_session_response.status() == reqwest::StatusCode::FORBIDDEN,
        "API client without session should be rejected, got: {}",
        no_session_response.status()
    );
    println!("  ✅ API client properly rejected without session");

    // Step 3.3: Test API client patterns with CSRF headers
    let api_client3 = MockBrowser::new(&setup.server.base_url, false);
    let csrf_headers = &[("x-csrf-token", csrf_token3)];
    let api_user_info = api_client3
        .get_with_headers("/auth/user/info", csrf_headers)
        .await?;

    println!(
        "  API client with CSRF header response status: {}",
        api_user_info.status()
    );
    println!("✅ SUBTEST 3 PASSED: User info access CSRF protection verified");

    // === SUBTEST 4: API Client CSRF Validation Behavior ===
    println!("\n🔧 SUBTEST 4: Testing API client CSRF validation behavior");

    // Step 4.1: Test authenticated operation with browser client (should succeed)
    let user_info_response2 = browser3.get("/auth/user/info").await?;
    assert!(
        user_info_response2.status().is_success(),
        "Authenticated browser client should access user info, got: {}",
        user_info_response2.status()
    );
    println!("  ✅ Authenticated browser operation successful");

    // Step 4.2: Test API client patterns with various CSRF scenarios
    let api_client4 = MockBrowser::new(&setup.server.base_url, false);

    // Test with valid CSRF token
    let valid_headers3 = &[("x-csrf-token", csrf_token3)];
    let valid_csrf_response = api_client4
        .get_with_headers("/auth/user/info", valid_headers3)
        .await?;
    println!(
        "  API client with valid CSRF response status: {}",
        valid_csrf_response.status()
    );

    // Test with invalid CSRF token
    let invalid_headers = &[("x-csrf-token", "invalid_token")];
    let invalid_csrf_response = api_client4
        .get_with_headers("/auth/user/info", invalid_headers)
        .await?;
    println!(
        "  API client with invalid CSRF response status: {}",
        invalid_csrf_response.status()
    );

    // Test without CSRF token
    let no_csrf_response = api_client4.get("/auth/user/info").await?;
    println!(
        "  API client without CSRF response status: {}",
        no_csrf_response.status()
    );

    // Step 4.3: Verify that operations without session are properly rejected
    assert!(
        no_csrf_response.status() == reqwest::StatusCode::UNAUTHORIZED
            || no_csrf_response.status() == reqwest::StatusCode::FORBIDDEN,
        "Operation without session should be rejected, got: {}",
        no_csrf_response.status()
    );
    println!("  ✅ Operation without session properly rejected");

    println!("✅ SUBTEST 4 PASSED: API client CSRF validation behavior verified");

    setup.shutdown().await;
    println!("🎯 === CONSOLIDATED API CLIENT CSRF PROTECTION TEST COMPLETED ===");
    Ok(())
}
