use crate::common::{
    MockBrowser, TestSetup, TestUsers, constants::oauth2::*, validation_utils::AuthValidationResult,
};

/// Get the OAuth2 issuer URL from environment or use default
fn get_oauth2_issuer_url() -> String {
    std::env::var("OAUTH2_ISSUER_URL").unwrap_or_else(|_| DEFAULT_ISSUER_URL.to_string())
}

/// Get the response mode from environment or use default
fn get_oauth2_response_mode() -> String {
    std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or_else(|_| DEFAULT_RESPONSE_MODE.to_string())
}

/// Helper function to complete OAuth2 authorization flow
/// Returns (auth_code, received_state)
async fn complete_oauth2_authorization(
    auth_url: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let auth_response = client.get(auth_url).send().await?;

    // Extract location header before consuming response
    let location_header = auth_response
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("invalid").to_string());
    let body = auth_response.text().await?;

    // Extract auth code and state based on response mode
    let response_mode = get_oauth2_response_mode();

    let (auth_code, received_state) = match response_mode.as_str() {
        "query" => {
            // Query mode: extract from location header
            if let Some(location) = &location_header {
                let url = reqwest::Url::parse(location)
                    .map_err(|e| format!("Invalid redirect URL: {e}"))?;
                let mut code = None;
                let mut state = None;
                for (key, value) in url.query_pairs() {
                    match key.as_ref() {
                        "code" => code = Some(value.to_string()),
                        "state" => state = Some(value.to_string()),
                        _ => {}
                    }
                }
                (
                    code.ok_or("No auth code in redirect URL")?,
                    state.unwrap_or_default(),
                )
            } else {
                return Err("Expected location header for redirect response".into());
            }
        }
        _ => {
            // Form_post mode (default): extract from form body
            let code_regex =
                regex::Regex::new(r#"<input[^>]*name=['"]code['"][^>]*value=['"]([^'"]*)'"#)
                    .unwrap();
            let state_regex =
                regex::Regex::new(r#"<input[^>]*name=['"]state['"][^>]*value=['"]([^'"]*)'"#)
                    .unwrap();

            let code = code_regex
                .captures(&body)
                .and_then(|cap| cap.get(1))
                .map(|m| m.as_str().to_string())
                .ok_or("No auth code found in form body")?;

            let state = state_regex
                .captures(&body)
                .and_then(|cap| cap.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            (code, state)
        }
    };

    Ok((auth_code, received_state))
}

/// Helper function to complete OAuth2 callback
/// Returns the callback response
async fn complete_oauth2_callback(
    browser: &MockBrowser,
    auth_code: &str,
    received_state: &str,
    oauth2_issuer_url: &str,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let response_mode = get_oauth2_response_mode();

    let callback_response = match response_mode.as_str() {
        "query" => {
            // Query mode: GET request with query parameters and headers
            browser
                .get_with_headers(
                    &format!("/auth/oauth2/authorized?code={auth_code}&state={received_state}"),
                    &[
                        ("Origin", oauth2_issuer_url),
                        ("Referer", &format!("{oauth2_issuer_url}/oauth2/auth")),
                    ],
                )
                .await?
        }
        _ => {
            // Form_post mode: POST request with form data
            browser
                .post_form_with_headers_old(
                    "/auth/oauth2/authorized",
                    &[("code", auth_code), ("state", received_state)],
                    &[
                        ("Origin", oauth2_issuer_url),
                        ("Referer", &format!("{oauth2_issuer_url}/oauth2/auth")),
                    ],
                )
                .await?
        }
    };

    Ok(callback_response)
}

/// Helper function to generate a valid page session token for OAuth2 linking tests
///
/// This simulates what a real browser would do: use the established session to generate
/// a page session token from the session's CSRF token, just like the UserSummaryTemplate does.
pub(super) async fn get_page_session_token_for_oauth2_linking(
    browser: &MockBrowser,
) -> Result<String, Box<dyn std::error::Error>> {
    use oauth2_passkey::generate_page_session_token;

    // Verify we have an active session first
    let user_info_response = browser.get("/auth/user/info").await?;
    if !user_info_response.status().is_success() {
        return Err("No active session found".into());
    }

    // Get the CSRF token from the dedicated endpoint, just like a real browser would
    // when loading the user summary page
    let csrf_response = browser.get("/auth/user/csrf_token").await?;
    if !csrf_response.status().is_success() {
        return Err("Failed to get CSRF token".into());
    }

    let csrf_response_text = csrf_response.text().await?;

    // Parse JSON response to extract CSRF token
    let csrf_token =
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&csrf_response_text) {
            json_value["csrf_token"]
                .as_str()
                .ok_or("Missing csrf_token in JSON response")?
                .to_string()
        } else {
            // Fallback to trimming quotes (for backward compatibility)
            csrf_response_text.trim_matches('"').to_string()
        };

    // Generate page session token from CSRF token (same as UserSummaryTemplate)
    let page_session_token = generate_page_session_token(&csrf_token);

    Ok(page_session_token)
}

/// Internal implementation for OAuth2 flow completion
async fn complete_full_oauth2_flow_internal(
    browser: &MockBrowser,
    mode: &str,
    context_token: Option<String>,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let oauth2_issuer_url = get_oauth2_issuer_url();

    // Build the OAuth2 authorization URL
    let mut oauth2_url = format!("/auth/oauth2/google?mode={mode}");
    if let Some(token) = context_token {
        oauth2_url.push_str(&format!("&context={token}"));
    }

    println!("🌐 Step 1: Starting OAuth2 authorization request to {oauth2_url}");

    // Step 1: Start OAuth2 authorization
    let auth_start_response = browser.get(&oauth2_url).await?;
    println!("Auth start status: {}", auth_start_response.status());

    if !auth_start_response.status().is_redirection() {
        return Err(format!(
            "Expected redirect response, got: {}",
            auth_start_response.status()
        )
        .into());
    }

    // Extract redirect URL from the response
    let redirect_url = auth_start_response
        .headers()
        .get("location")
        .ok_or("Missing location header")?
        .to_str()
        .map_err(|_| "Invalid location header")?;

    println!("🔗 Step 2: Following redirect to {redirect_url}");

    // Step 2: Complete authorization at provider and get auth code
    let (auth_code, received_state) = complete_oauth2_authorization(redirect_url).await?;

    println!("✅ Step 3: Received authorization code: {auth_code}");

    // Step 3: Complete OAuth2 callback
    let callback_response =
        complete_oauth2_callback(browser, &auth_code, &received_state, &oauth2_issuer_url).await?;

    println!("🎯 Step 4: OAuth2 flow completed");

    Ok(callback_response)
}

/// Public wrapper for OAuth2 flow completion
pub async fn complete_full_oauth2_flow(
    browser: &MockBrowser,
    mode: &str,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    // For backward compatibility, handle context token generation internally
    let context_token = if mode == ADD_TO_USER_MODE {
        Some(get_page_session_token_for_oauth2_linking(browser).await?)
    } else {
        None
    };

    complete_full_oauth2_flow_internal(browser, mode, context_token).await
}

/// **CONSOLIDATED TEST 1**: OAuth2 Complete Flows
///
/// This test consolidates:
/// - test_oauth2_new_user_registration
/// - test_oauth2_new_user_register_then_logout  
/// - test_oauth2_existing_user_login
/// - test_oauth2_uses_oidc_discovery
#[tokio::test]
async fn test_oauth2_complete_flows() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestSetup::new().await?;

    println!("🚀 === CONSOLIDATED OAUTH2 COMPLETE FLOWS TEST ===");

    // === SUBTEST 1: New User Registration ===
    println!("\n📝 SUBTEST 1: OAuth2 New User Registration");
    let test_user1 = TestUsers::unique_oauth2_user("oauth2_consolidated_registration");

    // Configure mock server with unique test user data for this test
    use crate::common::axum_mock_server::configure_mock_for_test;
    configure_mock_for_test(
        test_user1.email.clone(),
        test_user1.id.clone(),
        test_user1.name.clone(),
        test_user1.given_name.clone(),
        test_user1.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_response1 =
        complete_full_oauth2_flow(&setup.browser, "create_user_or_login").await?;
    let oauth2_validation1 = AuthValidationResult::from_oauth2_response(
        oauth2_response1.status(),
        oauth2_response1.headers(),
        "Created%20new%20user",
    );
    assert!(
        oauth2_validation1.is_success,
        "OAuth2 registration should succeed"
    );
    println!("✅ SUBTEST 1 PASSED: OAuth2 new user registration successful");

    // === SUBTEST 2: User Registration + Logout Flow ===
    println!("\n🚪 SUBTEST 2: OAuth2 Register Then Logout");
    let test_user2 = TestUsers::unique_oauth2_user("oauth2_consolidated_logout");

    // Configure mock server for second user
    configure_mock_for_test(
        test_user2.email.clone(),
        test_user2.id.clone(),
        test_user2.name.clone(),
        test_user2.given_name.clone(),
        test_user2.family_name.clone(),
        setup.server.base_url.clone(),
    );

    // Create new browser for logout test
    let browser2 = MockBrowser::new(&setup.server.base_url, true);
    let oauth2_response2 = complete_full_oauth2_flow(&browser2, "create_user_or_login").await?;
    let oauth2_validation2 = AuthValidationResult::from_oauth2_response(
        oauth2_response2.status(),
        oauth2_response2.headers(),
        "Created%20new%20user",
    );
    assert!(
        oauth2_validation2.is_success,
        "OAuth2 registration should succeed"
    );

    // Perform logout with redirect parameter
    let logout_response = browser2.get("/auth/user/logout?redirect=/").await?;
    assert!(
        logout_response.status().is_redirection(),
        "Logout should redirect"
    );

    // Verify logout worked by checking if session is cleared
    let user_info_response = browser2.get("/auth/user/info").await?;
    assert!(
        user_info_response.status().is_client_error(),
        "Should be unauthorized after logout"
    );
    println!("✅ SUBTEST 2 PASSED: OAuth2 registration and logout successful");

    // === SUBTEST 3: Existing User Login ===
    println!("\n🔑 SUBTEST 3: OAuth2 Existing User Login");
    // Re-configure mock server with same user as subtest 2 to simulate existing user
    configure_mock_for_test(
        test_user2.email.clone(),
        test_user2.id.clone(),
        test_user2.name.clone(),
        test_user2.given_name.clone(),
        test_user2.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let browser3 = MockBrowser::new(&setup.server.base_url, true);
    let oauth2_response3 = complete_full_oauth2_flow(&browser3, "login").await?;
    let oauth2_validation3 = AuthValidationResult::from_oauth2_response(
        oauth2_response3.status(),
        oauth2_response3.headers(),
        "Signing%20in%20as",
    );
    assert!(
        oauth2_validation3.is_success,
        "OAuth2 existing user login should succeed"
    );
    println!("✅ SUBTEST 3 PASSED: OAuth2 existing user login successful");

    // === SUBTEST 4: OIDC Discovery Configuration ===
    println!("\n🔍 SUBTEST 4: OAuth2 OIDC Discovery");
    let test_user4 = TestUsers::unique_oauth2_user("oauth2_consolidated_oidc");

    configure_mock_for_test(
        test_user4.email.clone(),
        test_user4.id.clone(),
        test_user4.name.clone(),
        test_user4.given_name.clone(),
        test_user4.family_name.clone(),
        setup.server.base_url.clone(),
    );

    // Test OIDC Discovery endpoint
    let client = reqwest::Client::new();
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        get_oauth2_issuer_url()
    );
    let discovery_response = client.get(&discovery_url).send().await?;
    assert!(
        discovery_response.status().is_success(),
        "OIDC Discovery should work"
    );

    let discovery_doc: serde_json::Value = discovery_response.json().await?;
    assert!(
        discovery_doc["authorization_endpoint"].is_string(),
        "Should have authorization endpoint"
    );
    assert!(
        discovery_doc["token_endpoint"].is_string(),
        "Should have token endpoint"
    );

    // Complete OAuth2 flow to ensure discovery configuration works
    let browser4 = MockBrowser::new(&setup.server.base_url, true);
    let oauth2_response4 = complete_full_oauth2_flow(&browser4, "create_user_or_login").await?;
    let oauth2_validation4 = AuthValidationResult::from_oauth2_response(
        oauth2_response4.status(),
        oauth2_response4.headers(),
        "Created%20new%20user",
    );
    assert!(
        oauth2_validation4.is_success,
        "OAuth2 with OIDC discovery should succeed"
    );
    println!("✅ SUBTEST 4 PASSED: OAuth2 OIDC Discovery configuration successful");

    setup.shutdown().await;
    println!("🎯 === CONSOLIDATED OAUTH2 COMPLETE FLOWS TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 2**: OAuth2 Account Linking  
///
/// This test consolidates:
/// - test_link_two_oauth2_users
/// - test_link_three_oauth2_users
#[tokio::test]
async fn test_oauth2_account_linking() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestSetup::new().await?;

    println!("🔗 === CONSOLIDATED OAUTH2 ACCOUNT LINKING TEST ===");

    // === SUBTEST 1: Link Two OAuth2 Accounts ===
    println!("\n🔗 SUBTEST 1: Linking Two OAuth2 Accounts");

    // Step 1: Create first OAuth2 account
    let test_user_first = TestUsers::unique_oauth2_user("link_consolidated_first");
    use crate::common::axum_mock_server::configure_mock_for_test;
    configure_mock_for_test(
        test_user_first.email.clone(),
        test_user_first.id.clone(),
        test_user_first.name.clone(),
        test_user_first.given_name.clone(),
        test_user_first.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_response_first =
        complete_full_oauth2_flow(&setup.browser, "create_user_or_login").await?;
    let oauth2_validation_first = AuthValidationResult::from_oauth2_response(
        oauth2_response_first.status(),
        oauth2_response_first.headers(),
        "Created%20new%20user",
    );
    assert!(
        oauth2_validation_first.is_success,
        "First OAuth2 account creation should succeed"
    );

    // Step 2: Configure mock server and link second account
    let test_user_second = TestUsers::unique_oauth2_user("link_consolidated_second");
    configure_mock_for_test(
        test_user_second.email.clone(),
        test_user_second.id.clone(),
        test_user_second.name.clone(),
        test_user_second.given_name.clone(),
        test_user_second.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_linking_response =
        complete_full_oauth2_flow(&setup.browser, ADD_TO_USER_MODE).await?;
    let oauth2_linking_validation = AuthValidationResult::from_oauth2_response(
        oauth2_linking_response.status(),
        oauth2_linking_response.headers(),
        "Successfully%20linked%20to",
    );
    assert!(
        oauth2_linking_validation.is_success,
        "OAuth2 account linking should succeed"
    );
    println!("✅ SUBTEST 1 PASSED: Two OAuth2 accounts linked successfully");

    // === SUBTEST 2: Link Three OAuth2 Accounts ===
    println!("\n🔗🔗 SUBTEST 2: Linking Three OAuth2 Accounts");

    // Create new browser session for three-account test
    let browser3 = MockBrowser::new(&setup.server.base_url, true);

    // Step 1: Create first account for three-account test
    let test_user_three_first = TestUsers::unique_oauth2_user("link_three_consolidated_first");
    configure_mock_for_test(
        test_user_three_first.email.clone(),
        test_user_three_first.id.clone(),
        test_user_three_first.name.clone(),
        test_user_three_first.given_name.clone(),
        test_user_three_first.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_response_three_first =
        complete_full_oauth2_flow(&browser3, "create_user_or_login").await?;
    let oauth2_validation_three_first = AuthValidationResult::from_oauth2_response(
        oauth2_response_three_first.status(),
        oauth2_response_three_first.headers(),
        "Created%20new%20user",
    );
    assert!(
        oauth2_validation_three_first.is_success,
        "First account in three-account test should succeed"
    );

    // Step 2: Link second OAuth2 account
    let test_user_three_second = TestUsers::unique_oauth2_user("link_three_consolidated_second");
    configure_mock_for_test(
        test_user_three_second.email.clone(),
        test_user_three_second.id.clone(),
        test_user_three_second.name.clone(),
        test_user_three_second.given_name.clone(),
        test_user_three_second.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_linking_response_second =
        complete_full_oauth2_flow(&browser3, ADD_TO_USER_MODE).await?;
    let oauth2_linking_validation_second = AuthValidationResult::from_oauth2_response(
        oauth2_linking_response_second.status(),
        oauth2_linking_response_second.headers(),
        "Successfully%20linked%20to",
    );
    assert!(
        oauth2_linking_validation_second.is_success,
        "Second OAuth2 account linking should succeed"
    );

    // Step 3: Link third OAuth2 account
    let test_user_three_third = TestUsers::unique_oauth2_user("link_three_consolidated_third");
    configure_mock_for_test(
        test_user_three_third.email.clone(),
        test_user_three_third.id.clone(),
        test_user_three_third.name.clone(),
        test_user_three_third.given_name.clone(),
        test_user_three_third.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_linking_response_third =
        complete_full_oauth2_flow(&browser3, ADD_TO_USER_MODE).await?;
    let oauth2_linking_validation_third = AuthValidationResult::from_oauth2_response(
        oauth2_linking_response_third.status(),
        oauth2_linking_response_third.headers(),
        "Successfully%20linked%20to",
    );
    assert!(
        oauth2_linking_validation_third.is_success,
        "Third OAuth2 account linking should succeed"
    );

    println!("✅ SUBTEST 2 PASSED: Three OAuth2 accounts linked successfully");

    setup.shutdown().await;
    println!("🎯 === CONSOLIDATED OAUTH2 ACCOUNT LINKING TEST COMPLETED ===");
    Ok(())
}
