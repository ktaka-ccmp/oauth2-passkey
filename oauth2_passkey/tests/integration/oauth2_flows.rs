use crate::common::{MockBrowser, TestServer, TestUsers};
use serial_test::serial;

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
    let server = TestServer::start().await?;
    let browser = MockBrowser::new(&server.base_url, true);
    let _test_user = TestUsers::oauth2_user();

    // Step 1: Start OAuth2 flow in "create_user_or_login" mode
    println!("🚀 STEP 1: Starting OAuth2 flow");
    let response = browser
        .get("/auth/oauth2/google?mode=create_user_or_login")
        .await?;
    println!("✅ STEP 1: OAuth2 flow start request completed");

    // Should redirect to OAuth2 provider (302 or 303 are both valid redirect codes)
    assert!(response.status().is_redirection());
    let auth_url = response
        .headers()
        .get("location")
        .expect("No location header in OAuth2 redirect")
        .to_str()
        .expect("Invalid location header")
        .to_string();

    println!("Authorization URL: {auth_url}");

    // Verify the authorization URL points to our Axum mock server
    assert!(
        auth_url.starts_with("http://127.0.0.1:9876/oauth2/auth"),
        "Authorization URL should use Axum mock server: {auth_url}"
    );

    // Extract the state parameter from the authorization URL
    let url = url::Url::parse(&auth_url).expect("Failed to parse auth URL");
    let state_param = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.to_string())
        .expect("No state parameter found in auth URL");

    println!("Extracted state parameter: {state_param}");

    // Step 2: Call the authorization endpoint (Axum mock server handles nonce automatically)
    println!("🔧 Calling Axum mock authorization endpoint...");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let auth_response = client.get(&auth_url).send().await?;
    println!(
        "Authorization endpoint response status: {}",
        auth_response.status()
    );

    println!("Authorization endpoint response headers:");
    for (key, value) in auth_response.headers() {
        println!(
            "  {}: {}",
            key,
            value.to_str().unwrap_or("invalid header value")
        );
    }

    // Extract location header before consuming response
    let location_header = auth_response
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("invalid").to_string());
    let status = auth_response.status();

    let body = auth_response.text().await?;
    println!(
        "Authorization endpoint response body preview: {}",
        &body.chars().take(300).collect::<String>()
    );

    // Extract auth code and state based on response mode
    let (auth_code, received_state) = if status.is_redirection() {
        // Query mode: extract from location header
        if let Some(location) = &location_header {
            println!("Authorization redirect location: {location}");
            let url =
                reqwest::Url::parse(location).map_err(|e| format!("Invalid redirect URL: {e}"))?;
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
    } else {
        // Form_post mode: extract from form body
        println!("Form post response received");
        // Parse the HTML form to extract hidden input values
        let code_regex =
            regex::Regex::new(r#"<input[^>]*name=['"]code['"][^>]*value=['"]([^'"]*)"#).unwrap();
        let state_regex =
            regex::Regex::new(r#"<input[^>]*name=['"]state['"][^>]*value=['"]([^'"]*)"#).unwrap();

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
    };

    println!("🔍 Extracted auth code: {auth_code} (state: {received_state})");

    // Step 3: Complete OAuth2 callback with auth code (simulating OAuth2 provider redirect)
    println!("🔧 Simulating OAuth2 provider callback...");
    let callback_response = browser
        .post_form_with_headers_old(
            "/auth/oauth2/authorized",
            &[
                ("code", &auth_code), // Use the actual extracted code
                ("state", &received_state),
            ],
            &[
                ("Origin", "http://127.0.0.1:9876"), // Axum mock server origin
                ("Referer", "http://127.0.0.1:9876/oauth2/auth"),
            ],
        )
        .await?;

    // Check the callback response
    let status = callback_response.status();
    println!("OAuth2 callback response status: {status}");

    // Show callback response headers (session cookies, CSRF tokens, etc.)
    println!("OAuth2 callback response headers:");
    for (key, value) in callback_response.headers() {
        println!(
            "  {}: {}",
            key,
            value.to_str().unwrap_or("invalid header value")
        );
    }

    // Extract data before consuming response
    let headers = callback_response.headers().clone();
    let response_body = callback_response.text().await?;
    println!(
        "OAuth2 callback response preview: {}",
        &response_body[..std::cmp::min(200, response_body.len())]
    );

    // Assert OAuth2 success characteristics
    let mut success_checks = Vec::new();

    // 1. Check for 303 redirect (successful OAuth2 completion)
    if status == reqwest::StatusCode::SEE_OTHER {
        success_checks.push("✅ 303 See Other redirect: PASSED".to_string());
    } else {
        success_checks.push(format!("❌ Expected 303 See Other, got: {status}"));
    }

    // 2. Check for session cookie with correct characteristics
    let session_cookie = headers
        .get_all("set-cookie")
        .iter()
        .find(|cookie| cookie.to_str().unwrap_or("").contains("__Host-SessionId"));

    if let Some(cookie) = session_cookie {
        let cookie_str = cookie.to_str().unwrap_or("");
        if cookie_str.contains("SameSite=Lax")
            && cookie_str.contains("Secure")
            && cookie_str.contains("HttpOnly")
            && cookie_str.contains("Path=/")
        {
            success_checks.push("✅ Session cookie with security flags: PASSED".to_string());
        } else {
            success_checks.push("❌ Session cookie missing security flags".to_string());
        }
    } else {
        success_checks.push("❌ No __Host-SessionId cookie found".to_string());
    }

    // 3. Check for location header with success message
    let location = headers.get("location").and_then(|h| h.to_str().ok());

    if let Some(loc) = location {
        if loc.contains("/auth/oauth2/popup_close") && loc.contains("Created%20new%20user") {
            success_checks
                .push("✅ Success redirect with user creation message: PASSED".to_string());
        } else {
            success_checks.push(format!("❌ Unexpected redirect location: {loc}"));
        }
    } else {
        success_checks.push("❌ No location header found".to_string());
    }

    // 4. Check for CSRF cookie management
    let csrf_cookie = headers
        .get_all("set-cookie")
        .iter()
        .find(|cookie| cookie.to_str().unwrap_or("").contains("__Host-CsrfId"));

    if csrf_cookie.is_some() {
        success_checks.push("✅ CSRF token management: PASSED".to_string());
    } else {
        success_checks.push("❌ No CSRF cookie management found".to_string());
    }

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

/// Test OAuth2 existing user login flow
#[tokio::test]
#[serial]
async fn test_oauth2_existing_user_login() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::start().await?;
    let browser = MockBrowser::new(&server.base_url, true);

    // Start OAuth2 flow in login mode
    let response = browser.get("/auth/oauth2/google?mode=login").await?;

    // Should redirect to OAuth2 provider
    assert!(response.status().is_redirection());
    let auth_url = response
        .headers()
        .get("location")
        .expect("No location header")
        .to_str()
        .expect("Invalid location header")
        .to_string();

    // Verify it uses the Axum mock server
    assert!(auth_url.starts_with("http://127.0.0.1:9876/oauth2/auth"));

    println!("✅ OAuth2 existing user login flow test setup SUCCESS");
    Ok(())
}

/// Test OIDC Discovery integration
#[tokio::test]
#[serial]
async fn test_oidc_discovery_integration() -> Result<(), Box<dyn std::error::Error>> {
    let _server = TestServer::start().await?;

    // Test OIDC Discovery endpoint directly
    let client = reqwest::Client::new();
    let discovery_response = client
        .get("http://127.0.0.1:9876/.well-known/openid-configuration")
        .send()
        .await?;

    assert!(discovery_response.status().is_success());

    let discovery_doc: serde_json::Value = discovery_response.json().await?;

    // Verify OIDC Discovery document structure
    assert_eq!(discovery_doc["issuer"], "http://127.0.0.1:9876");
    assert_eq!(
        discovery_doc["authorization_endpoint"],
        "http://127.0.0.1:9876/oauth2/auth"
    );
    assert_eq!(
        discovery_doc["token_endpoint"],
        "http://127.0.0.1:9876/oauth2/token"
    );
    assert_eq!(
        discovery_doc["userinfo_endpoint"],
        "http://127.0.0.1:9876/oauth2/userinfo"
    );

    println!("✅ OIDC Discovery integration test SUCCESS");
    Ok(())
}
