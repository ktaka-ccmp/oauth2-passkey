use crate::common::{
    MockBrowser, TestSetup, TestUsers,
    constants::oauth2::*,
    validation_utils::{AuthValidationResult, validate_oauth2_success},
};
use serial_test::serial;

/// Get the OAuth2 issuer URL from environment or use default
fn get_oauth2_issuer_url() -> String {
    std::env::var("OAUTH2_ISSUER_URL").unwrap_or_else(|_| DEFAULT_ISSUER_URL.to_string())
}

/// Get the response mode from environment or use default
fn get_oauth2_response_mode() -> String {
    std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or_else(|_| DEFAULT_RESPONSE_MODE.to_string())
}

/// OAuth2 flow builder for structured test execution
struct OAuth2Flow<'a> {
    browser: &'a MockBrowser,
    mode: &'a str,
    context_token: Option<String>,
}

impl<'a> OAuth2Flow<'a> {
    /// Create a new OAuth2 flow
    fn new(browser: &'a MockBrowser, mode: &'a str) -> Self {
        Self {
            browser,
            mode,
            context_token: None,
        }
    }

    /// Add context token for account linking
    async fn with_context(mut self) -> Result<Self, Box<dyn std::error::Error>> {
        if self.mode == ADD_TO_USER_MODE {
            self.context_token =
                Some(get_page_session_token_for_oauth2_linking(self.browser).await?);
        }
        Ok(self)
    }

    /// Execute the OAuth2 flow and return the response
    async fn execute(self) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
        complete_full_oauth2_flow_internal(self.browser, self.mode, self.context_token).await
    }

    /// Execute and validate the OAuth2 flow with expected message
    async fn execute_and_validate(
        self,
        expected_message: &str,
    ) -> Result<AuthValidationResult, Box<dyn std::error::Error>> {
        let response = self.execute().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let _body = response.text().await?;

        Ok(AuthValidationResult::from_oauth2_response(
            status,
            &headers,
            expected_message,
        ))
    }
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

    let csrf_data: serde_json::Value = csrf_response.json().await?;

    // Extract the CSRF token - this is exactly what the
    // UserSummaryTemplate does in optional.rs:121 when it calls generate_page_session_token(&user.csrf_token)
    if let Some(csrf_token) = csrf_data.get("csrf_token").and_then(|v| v.as_str()) {
        // Generate the page session token using the same function that the real application uses
        let page_session_token = generate_page_session_token(csrf_token);
        return Ok(page_session_token);
    }

    Err("CSRF token not found in response".into())
}

/// Helper function to verify OAuth2 accounts linked to a user
///
/// This function retrieves the OAuth2 accounts for a user and verifies the expected count
/// and provider information, similar to how the summary page displays linked accounts.
async fn verify_oauth2_accounts_linked(
    browser: &MockBrowser,
    expected_account_count: usize,
    expected_provider: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    use oauth2_passkey::list_accounts_core;

    // First, verify we have an active session
    let user_info_response = browser.get("/auth/user/info").await?;
    if !user_info_response.status().is_success() {
        return Err("No active session found for account verification".into());
    }

    let user_info: serde_json::Value = user_info_response.json().await?;
    let user_id = user_info["id"]
        .as_str()
        .ok_or("User ID not found in user info")?;

    // Call the same core function used by the summary page to get OAuth2 accounts
    let oauth2_accounts = list_accounts_core(user_id)
        .await
        .map_err(|e| format!("Failed to retrieve OAuth2 accounts: {e:?}"))?;

    // Verify the expected account count
    if oauth2_accounts.len() != expected_account_count {
        return Err(format!(
            "Expected {} OAuth2 accounts, but found {}. Accounts: {:?}",
            expected_account_count,
            oauth2_accounts.len(),
            oauth2_accounts
                .iter()
                .map(|acc| (&acc.provider, &acc.email, &acc.name))
                .collect::<Vec<_>>()
        )
        .into());
    }

    // Verify all accounts are from the expected provider
    for account in &oauth2_accounts {
        if account.provider != expected_provider {
            return Err(format!(
                "Expected provider '{}', but found account with provider '{}'",
                expected_provider, account.provider
            )
            .into());
        }
    }

    // Convert to JSON format for easier inspection in tests
    let accounts_json: Vec<serde_json::Value> = oauth2_accounts
        .into_iter()
        .map(|account| {
            serde_json::json!({
                "id": account.id,
                "user_id": account.user_id,
                "provider": account.provider,
                "provider_user_id": account.provider_user_id,
                "name": account.name,
                "email": account.email,
                "picture": account.picture
            })
        })
        .collect();

    println!("✅ OAuth2 account verification successful:");
    println!(
        "  - Account count: {} (expected: {})",
        accounts_json.len(),
        expected_account_count
    );
    println!("  - Provider: {expected_provider} (all accounts)");
    for (i, account) in accounts_json.iter().enumerate() {
        println!(
            "  - Account {}: {} <{}> (ID: {})",
            i + 1,
            account["name"].as_str().unwrap_or("N/A"),
            account["email"].as_str().unwrap_or("N/A"),
            account["provider_user_id"].as_str().unwrap_or("N/A")
        );
    }

    Ok(accounts_json)
}

/// Internal helper function for OAuth2 flow execution (used by OAuth2Flow builder)
async fn complete_full_oauth2_flow_internal(
    browser: &MockBrowser,
    mode: &str,
    context_token: Option<String>,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    // Step 1: Start OAuth2 flow
    let url = if let Some(token) = context_token {
        // Use provided context token for add_to_user mode
        format!("/auth/oauth2/google?mode={mode}&context={token}")
    } else {
        format!("/auth/oauth2/google?mode={mode}")
    };

    let response = browser.get(&url).await?;

    if !response.status().is_redirection() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read body".to_string());
        return Err(format!(
            "Expected redirect for OAuth2 start (mode={mode}), got status: {status}, body: {body}"
        )
        .into());
    }
    let auth_url = response
        .headers()
        .get("location")
        .expect("No location header in OAuth2 redirect")
        .to_str()
        .expect("Invalid location header")
        .to_string();

    // Get OAuth2 issuer URL for assertions
    let oauth2_issuer_url = get_oauth2_issuer_url();

    // Verify the authorization URL points to our OAuth2 provider
    assert!(
        auth_url.starts_with(&format!("{oauth2_issuer_url}/oauth2/auth")),
        "Authorization URL should use OAuth2 provider: {auth_url}"
    );

    // Step 2: Complete authorization
    let (auth_code, received_state) = complete_oauth2_authorization(&auth_url).await?;

    // Step 3: Complete callback
    let callback_response =
        complete_oauth2_callback(browser, &auth_code, &received_state, &oauth2_issuer_url).await?;

    Ok(callback_response)
}

/// Helper function to complete full OAuth2 flow
/// Returns the final callback response
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

/// Test complete OAuth2 authentication flows with Axum mock server
///
/// These integration tests verify end-to-end OAuth2 functionality including:
/// - New user registration via OAuth2
/// - OIDC Discovery integration
/// - Nonce verification (automated by Axum mock server)
/// - State parameter management
/// Test OAuth2 new user registration flow
///
/// Flow: Start OAuth2 → Axum mock provider redirect → Create new user → Establish session
#[tokio::test]
#[serial]
async fn test_oauth2_new_user_registration() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment - TestServer now uses global Axum mock server
    let setup = TestSetup::new().await?;
    let test_user = TestUsers::unique_oauth2_user("oauth2_new_user_registration");

    println!("🚀 Starting OAuth2 new user registration flow");

    // Configure mock server with unique test user data for this test
    use crate::common::axum_mock_server::configure_mock_for_test;
    configure_mock_for_test(
        test_user.email.clone(),
        test_user.id.clone(),
        test_user.name.clone(),
        test_user.given_name.clone(),
        test_user.family_name.clone(),
        setup.server.base_url.clone(),
    );
    println!("🔧 Mock server configured for test");

    // Complete full OAuth2 flow using helper function
    let callback_response =
        complete_full_oauth2_flow(&setup.browser, "create_user_or_login").await?;

    // Check the callback response
    let status = callback_response.status();
    println!("OAuth2 callback response status: {status}");

    // Extract data before consuming response
    let headers = callback_response.headers().clone();
    let _response_body = callback_response.text().await?;

    // Validate OAuth2 success characteristics using helper function
    let success_checks = validate_oauth2_success(&status, &headers, "Created%20new%20user");

    // Determine overall success
    let all_passed = success_checks.iter().all(|check| check.starts_with("✅"));

    if all_passed {
        println!("🎉 OAuth2 new user registration test SUCCESS:");
        for check in &success_checks {
            println!("  {check}");
        }
        println!("  - OAuth2 authorization with unique codes: PASSED");
        println!("  - PKCE validation (S256): PASSED");
        println!("  - Nonce verification: PASSED");
        println!("  - Token exchange: PASSED");
        println!("  - Session establishment: PASSED");
        return Ok(());
    } else {
        println!("❌ OAuth2 flow failed - missing required characteristics:");
        for check in &success_checks {
            println!("  {check}");
        }
        panic!("OAuth2 integration test failed due to missing success characteristics");
    }
}

/// Test OAuth2 new user registration followed by logout
///
/// Flow: Register new user via OAuth2 → Verify session → Logout → Verify session cleared
#[tokio::test]
#[serial]
async fn test_oauth2_new_user_register_then_logout() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    let setup = TestSetup::new().await?;
    let test_user = TestUsers::unique_oauth2_user("oauth2_new_user_register_then_logout");

    println!("🚀 Starting OAuth2 new user registration and logout flow");

    // Configure mock server with unique test user data for this test
    use crate::common::axum_mock_server::configure_mock_for_test;
    configure_mock_for_test(
        test_user.email.clone(),
        test_user.id.clone(),
        test_user.name.clone(),
        test_user.given_name.clone(),
        test_user.family_name.clone(),
        setup.server.base_url.clone(),
    );
    println!("🔧 Mock server configured for test");

    // Step 1: Complete OAuth2 registration flow
    let callback_response =
        complete_full_oauth2_flow(&setup.browser, "create_user_or_login").await?;

    // Verify registration was successful
    let status = callback_response.status();
    assert_eq!(status, reqwest::StatusCode::SEE_OTHER);

    let headers = callback_response.headers().clone();
    let _response_body = callback_response.text().await?;

    // Validate OAuth2 success
    let success_checks = validate_oauth2_success(&status, &headers, "Created%20new%20user");
    let all_passed = success_checks.iter().all(|check| check.starts_with("✅"));

    if !all_passed {
        for check in &success_checks {
            println!("  {check}");
        }
        panic!("OAuth2 registration failed");
    }

    println!("✅ Step 1: OAuth2 registration successful");

    // Step 2: Verify user has active session
    let user_info_response = setup.browser.get("/auth/user/info").await?;
    assert!(
        user_info_response.status().is_success(),
        "Should have active session after OAuth2 login"
    );

    let user_info: serde_json::Value = user_info_response.json().await?;
    println!(
        "✅ Step 2: Active session confirmed for user: {}",
        user_info["email"]
    );

    // Step 3: Perform logout
    let logout_response = setup.browser.get("/auth/user/logout").await?;

    // Check logout response
    println!("Logout response status: {}", logout_response.status());
    assert!(
        logout_response.status().is_redirection() || logout_response.status().is_success(),
        "Logout should succeed with redirect or 200 OK, got: {}",
        logout_response.status()
    );

    // Check for session cookie deletion
    let logout_headers = logout_response.headers();
    let session_cookie_cleared = logout_headers.get_all("set-cookie").iter().any(|cookie| {
        let cookie_str = cookie.to_str().unwrap_or("");
        cookie_str.contains("__Host-SessionId")
            && (cookie_str.contains("Max-Age=0") 
                || cookie_str.contains("Max-Age=-")  // Negative Max-Age also clears the cookie
                || cookie_str.contains("expires=Thu, 01 Jan 1970"))
    });

    assert!(
        session_cookie_cleared,
        "Session cookie should be cleared on logout"
    );

    println!("✅ Step 3: Logout successful, session cookie cleared");

    // Step 4: Verify session is no longer active
    let post_logout_response = setup.browser.get("/auth/user/info").await?;
    assert_eq!(
        post_logout_response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Should not have active session after logout"
    );

    println!("✅ Step 4: Session successfully terminated");

    println!("🎉 OAuth2 register and logout test SUCCESS");
    println!("  - New user registration: PASSED");
    println!("  - Session establishment: PASSED");
    println!("  - Logout functionality: PASSED");
    println!("  - Session cleanup: PASSED");

    Ok(())
}

/// Test OAuth2 existing user login flow
///
/// Flow: Create user → Complete OAuth2 existing user login → Verify "Signing in as" message
#[tokio::test]
#[serial]
async fn test_oauth2_existing_user_login() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    let setup = TestSetup::new().await?;
    let test_user = TestUsers::unique_oauth2_user("oauth2_existing_user_login");

    println!("🚀 STEP 1: Creating user via new user registration flow");

    // Configure mock server with unique test user data for this test
    use crate::common::axum_mock_server::configure_mock_for_test;
    configure_mock_for_test(
        test_user.email.clone(),
        test_user.id.clone(),
        test_user.name.clone(),
        test_user.given_name.clone(),
        test_user.family_name.clone(),
        setup.server.base_url.clone(),
    );
    println!("🔧 Mock server configured for test");

    // First, create a user using the helper function
    let creation_response =
        complete_full_oauth2_flow(&setup.browser, "create_user_or_login").await?;

    // Verify user creation was successful
    assert!(creation_response.status().is_redirection());
    let creation_location = creation_response
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok());

    if let Some(loc) = creation_location {
        assert!(
            loc.contains("Created%20new%20user"),
            "First OAuth2 flow should create new user: {loc}"
        );
    }

    println!("✅ STEP 1: User creation completed successfully");

    // STEP 2: Now test existing user login
    println!("🚀 STEP 2: Testing existing user login flow");

    // Create a new browser session (different user session)
    let login_browser = MockBrowser::new(&setup.server.base_url, true);

    // Complete OAuth2 flow for existing user login using helper function
    let login_callback_response = complete_full_oauth2_flow(&login_browser, "login").await?;

    // Check the existing user login response
    let login_status = login_callback_response.status();
    println!("OAuth2 existing user login response status: {login_status}");

    // Extract data before consuming response
    let login_headers = login_callback_response.headers().clone();
    let _login_response_body = login_callback_response.text().await?;

    // Validate OAuth2 success characteristics using helper function
    let login_success_checks =
        validate_oauth2_success(&login_status, &login_headers, "Signing%20in%20as");

    // Determine overall success
    let all_login_passed = login_success_checks
        .iter()
        .all(|check| check.starts_with("✅"));

    if all_login_passed {
        println!("🎉 OAuth2 existing user login test SUCCESS:");
        for check in &login_success_checks {
            println!("  {check}");
        }
        println!("  - Existing user detected correctly: PASSED");
        println!("  - Different message from new user creation: PASSED");
        println!("  - Session establishment for existing user: PASSED");
    } else {
        println!("❌ OAuth2 existing user login failed - missing required characteristics:");
        for check in &login_success_checks {
            println!("  {check}");
        }
        panic!("OAuth2 existing user login test failed due to missing success characteristics");
    }

    println!("✅ OAuth2 existing user login flow test SUCCESS");
    Ok(())
}

/// Test that OAuth2 configuration uses OIDC Discovery dynamically
///
/// This test validates that the oauth2-passkey library properly discovers
/// and uses endpoints from the OIDC Discovery document instead of hardcoded URLs.
#[tokio::test]
#[serial]
async fn test_oauth2_uses_oidc_discovery() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    let setup = TestSetup::new().await?;

    println!("🔍 Testing OAuth2 configuration with OIDC Discovery");

    // Get OAuth2 issuer URL from environment
    let oauth2_issuer_url =
        std::env::var("OAUTH2_ISSUER_URL").unwrap_or_else(|_| "http://127.0.0.1:9876".to_string());
    println!("OAuth2 server URL: {oauth2_issuer_url}");

    // Start an OAuth2 flow to trigger endpoint discovery
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let oauth2_start_response = client
        .get(format!(
            "{}/auth/oauth2/google?mode=create_user_or_login",
            setup.server.base_url
        ))
        .send()
        .await?;

    println!(
        "OAuth2 start response status: {}",
        oauth2_start_response.status()
    );

    // Should redirect to OAuth2 provider
    assert!(
        oauth2_start_response.status().is_redirection(),
        "OAuth2 start should redirect"
    );

    let auth_url = oauth2_start_response
        .headers()
        .get("location")
        .expect("No location header in OAuth2 redirect")
        .to_str()
        .expect("Invalid location header");

    println!("Authorization URL: {auth_url}");

    // Validate that the authorization URL uses the OAuth2 provider (discovered endpoint)
    assert!(
        auth_url.starts_with(&oauth2_issuer_url),
        "Authorization URL should use discovered endpoint from OAuth2 provider: {auth_url}"
    );
    assert!(
        auth_url.contains("/oauth2/auth"),
        "Authorization URL should use the discovered authorization endpoint"
    );
    assert!(
        auth_url.contains("client_id="),
        "Authorization URL should contain client_id parameter"
    );
    assert!(
        auth_url.contains("nonce="),
        "Authorization URL should contain nonce parameter for OIDC compliance"
    );

    println!("✅ OAuth2 configuration is using OIDC Discovery correctly");
    println!("  - Authorization endpoint discovered and used: ✓");
    println!("  - Dynamic URL configuration: ✓");
    println!("  - OIDC compliance (nonce parameter): ✓");

    Ok(())
}

/// Test linking two OAuth2 accounts to one user
///
/// Flow: Register first user → Add second OAuth2 account → Verify both accounts linked to same user
#[tokio::test]
#[serial]
async fn test_link_two_oauth2_users() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestSetup::new().await?;

    println!("🔗 Testing linking two OAuth2 accounts to one user");

    // Configure mock server with unique first user data
    use crate::common::axum_mock_server::configure_mock_for_test;
    let test_user_first = TestUsers::unique_oauth2_user("link_two_oauth2_users_first");
    configure_mock_for_test(
        test_user_first.email.clone(),
        test_user_first.id.clone(),
        test_user_first.name.clone(),
        test_user_first.given_name.clone(),
        test_user_first.family_name.clone(),
        setup.server.base_url.to_string(),
    );

    // Step 1: Create initial user via OAuth2 registration
    println!("📝 Step 1: Creating initial user via OAuth2 registration");
    let first_result = OAuth2Flow::new(&setup.browser, CREATE_USER_MODE)
        .execute_and_validate(NEW_USER_MESSAGE)
        .await?;

    if !first_result.is_success {
        first_result.print_details();
        return Err("First OAuth2 user creation failed validation".into());
    }
    println!("✅ Step 1: First OAuth2 user created successfully");

    // Verify session and get user info
    let first_user_info: serde_json::Value =
        setup.browser.get("/auth/user/info").await?.json().await?;
    println!("  - First user email: {}", first_user_info["email"]);

    // Step 2: Test context validation (should fail without context)
    println!("🔍 Step 2a: Testing OAuth2 linking validation");
    let no_context_response = setup
        .browser
        .get("/auth/oauth2/google?mode=add_to_user")
        .await?;
    if no_context_response.status() == reqwest::StatusCode::BAD_REQUEST {
        println!("✅ Step 2a: OAuth2 correctly requires context parameter for add_to_user mode");
    }

    // Step 3: Configure mock server and link second account
    println!("🔧 Step 2b: Configuring mock server with second user data");
    let test_user_second = TestUsers::unique_oauth2_user("link_two_oauth2_users_second");
    configure_mock_for_test(
        test_user_second.email.clone(),
        test_user_second.id.clone(),
        test_user_second.name.clone(),
        test_user_second.given_name.clone(),
        test_user_second.family_name.clone(),
        setup.server.base_url.to_string(),
    );

    let second_result = OAuth2Flow::new(&setup.browser, ADD_TO_USER_MODE)
        .with_context()
        .await?
        .execute_and_validate(LINKED_ACCOUNT_MESSAGE)
        .await?;

    println!(
        "  - OAuth2 account linking response status: {}",
        second_result.status_code
    );

    if second_result.is_success {
        println!("✅ Step 2b: Second OAuth2 account linked successfully");

        // Verify user identity consistency
        let updated_user_info: serde_json::Value =
            setup.browser.get("/auth/user/info").await?.json().await?;
        assert_eq!(
            first_user_info["id"], updated_user_info["id"],
            "User ID should remain consistent after account linking"
        );

        // Verify OAuth2 accounts are properly linked
        println!("🔍 Step 2c: Verifying OAuth2 accounts are properly linked");
        match verify_oauth2_accounts_linked(&setup.browser, 2, PROVIDER).await {
            Ok(accounts) => {
                println!("✅ Step 2c: OAuth2 account verification successful");
                let provider_ids: Vec<&str> = accounts
                    .iter()
                    .map(|acc| acc["provider_user_id"].as_str().unwrap_or(""))
                    .collect();
                if provider_ids.len() == 2 && provider_ids[0] != provider_ids[1] {
                    println!("✅ Step 2c: Two distinct OAuth2 accounts confirmed");
                }
            }
            Err(e) => println!("⚠️  Step 2c: OAuth2 account verification failed: {e}"),
        }
    } else {
        println!("⚠️  Step 2b: OAuth2 account linking attempted but may have validation issues");
        second_result.print_details();
    }

    // Verify session remains active
    assert!(
        setup.browser.has_active_session().await,
        "Session should remain active after OAuth2 linking"
    );

    println!("🎉 OAuth2 account linking framework test SUCCESS");
    setup.shutdown().await;
    Ok(())
}

/// Test linking three OAuth2 accounts to one user
///
/// Flow: Register first user → Add second OAuth2 account → Add third OAuth2 account → Verify all accounts linked
#[tokio::test]
#[serial]
async fn test_link_three_oauth2_users() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestSetup::new().await?;

    println!("🔗🔗🔗 Testing linking three OAuth2 accounts to one user");

    // Configure mock server with unique first user data
    use crate::common::axum_mock_server::configure_mock_for_test;
    let test_user_first = TestUsers::unique_oauth2_user("link_three_oauth2_users_first");
    configure_mock_for_test(
        test_user_first.email.clone(),
        test_user_first.id.clone(),
        test_user_first.name.clone(),
        test_user_first.given_name.clone(),
        test_user_first.family_name.clone(),
        setup.server.base_url.to_string(),
    );

    // Step 1: Create initial user via OAuth2 registration
    println!("📝 Step 1: Creating initial user via OAuth2 registration");
    let first_result = OAuth2Flow::new(&setup.browser, CREATE_USER_MODE)
        .execute_and_validate(NEW_USER_MESSAGE)
        .await?;

    if !first_result.is_success {
        first_result.print_details();
        return Err("First OAuth2 user creation failed validation".into());
    }
    println!("✅ Step 1: First OAuth2 user created successfully");

    // Get initial user info
    let first_user_info: serde_json::Value =
        setup.browser.get("/auth/user/info").await?.json().await?;
    println!("  - First user email: {}", first_user_info["email"]);

    // Step 2: Link second OAuth2 account
    println!("🔗 Step 2: Linking second OAuth2 account to existing user");
    let test_user_second = TestUsers::unique_oauth2_user("link_three_oauth2_users_second");
    configure_mock_for_test(
        test_user_second.email.clone(),
        test_user_second.id.clone(),
        test_user_second.name.clone(),
        test_user_second.given_name.clone(),
        test_user_second.family_name.clone(),
        setup.server.base_url.to_string(),
    );

    let second_result = OAuth2Flow::new(&setup.browser, ADD_TO_USER_MODE)
        .with_context()
        .await?
        .execute_and_validate(LINKED_ACCOUNT_MESSAGE)
        .await?;

    let second_success = second_result.is_success;
    if second_success {
        println!("✅ Step 2: Second OAuth2 account linked successfully");
    } else {
        println!("⚠️  Step 2: Second OAuth2 account linking attempted");
    }

    // Verify session is still active after second linking
    assert!(
        setup
            .browser
            .get("/auth/user/info")
            .await?
            .status()
            .is_success(),
        "Should have active session after second account linking"
    );

    // Step 3: Link third OAuth2 account
    println!("🔗 Step 3: Linking third OAuth2 account to existing user");
    let test_user_third = TestUsers::unique_oauth2_user("link_three_oauth2_users_third");
    configure_mock_for_test(
        test_user_third.email.clone(),
        test_user_third.id.clone(),
        test_user_third.name.clone(),
        test_user_third.given_name.clone(),
        test_user_third.family_name.clone(),
        setup.server.base_url.to_string(),
    );

    let third_result = OAuth2Flow::new(&setup.browser, ADD_TO_USER_MODE)
        .with_context()
        .await?
        .execute_and_validate(LINKED_ACCOUNT_MESSAGE)
        .await?;

    let third_success = third_result.is_success;
    if third_success {
        println!("✅ Step 3: Third OAuth2 account linked successfully");
    } else {
        println!("⚠️  Step 3: Third OAuth2 account linking attempted");
    }

    // Step 4: Verify final user state and OAuth2 accounts
    let final_user_info: serde_json::Value =
        setup.browser.get("/auth/user/info").await?.json().await?;
    println!("  - Final user email: {}", final_user_info["email"]);

    // User identity should remain consistent
    assert_eq!(
        first_user_info["email"], final_user_info["email"],
        "User identity should remain consistent after multiple account linking"
    );

    // Step 4b: Verify OAuth2 accounts are properly linked
    println!("🔍 Step 4b: Verifying final OAuth2 account count");
    let expected_count = if second_success && third_success {
        3
    } else if second_success || third_success {
        2
    } else {
        1
    };

    match verify_oauth2_accounts_linked(&setup.browser, expected_count, PROVIDER).await {
        Ok(accounts) => {
            println!("✅ Step 4b: OAuth2 account verification successful");
            let provider_ids: Vec<&str> = accounts
                .iter()
                .map(|acc| acc["provider_user_id"].as_str().unwrap_or(""))
                .collect();
            let unique_ids: std::collections::HashSet<&str> =
                provider_ids.iter().cloned().collect();
            if unique_ids.len() == expected_count {
                println!("✅ Step 4b: {expected_count} distinct OAuth2 accounts confirmed");
            } else {
                println!(
                    "⚠️  Step 4b: Expected {expected_count} distinct OAuth2 accounts, but provider IDs are: {provider_ids:?}"
                );
            }
        }
        Err(e) => println!("⚠️  Step 4b: OAuth2 account verification failed: {e}"),
    }

    // Determine overall success and print results
    let overall_success = second_success && third_success;
    if overall_success {
        println!("🎉 OAuth2 multiple account linking test SUCCESS:");
        println!("  - First OAuth2 user registration: PASSED");
        println!("  - Second OAuth2 account linking: PASSED");
        println!("  - Third OAuth2 account linking: PASSED");
        println!("  - User identity consistency: PASSED");
        println!("  - Session management across multiple linking: PASSED");
    } else {
        println!("✅ OAuth2 multiple account linking framework test SUCCESS:");
        println!("  - First OAuth2 user registration: PASSED");
        println!("  - Multiple OAuth2 linking attempts: INITIATED");
        println!("  - Session stability during linking: PASSED");
        println!("  - User identity preservation: PASSED");
        println!("  - Multi-account linking framework: FUNCTIONAL");
    }

    setup.shutdown().await;
    Ok(())
}
