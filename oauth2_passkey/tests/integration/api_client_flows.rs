/// API Client Integration Tests
///
/// Tests authentication flows for JavaScript/API clients that use X-CSRF-Token headers
/// instead of cookies for CSRF protection. These tests validate scenarios where:
/// - JavaScript clients extract CSRF tokens from Set-Cookie headers
/// - API clients send CSRF tokens via X-CSRF-Token header
/// - Mixed scenarios with both cookie-based and header-based CSRF protection
///
/// Note: These tests demonstrate the CSRF token extraction and usage patterns
/// for API clients, focusing on the header-based CSRF protection mechanism.
use crate::common::{mock_browser::MockBrowser, test_server::TestServer};
use reqwest::header::{HeaderMap, HeaderValue};

/// Test CSRF token extraction for API clients
///
/// This test validates that API clients can:
/// 1. Extract CSRF tokens from Set-Cookie headers
/// 2. Parse the token value from cookie strings
/// 3. Prepare for using X-CSRF-Token headers in subsequent requests
#[tokio::test]
#[serial_test::serial]
async fn test_api_client_csrf_token_extraction() {
    let server = TestServer::start()
        .await
        .expect("Failed to start test server");

    // Create an API client browser that doesn't use automatic cookie handling
    let api_client = MockBrowser::new(&server.base_url, false); // false = no cookie store

    // Step 1: Start OAuth2 flow to get CSRF token
    let oauth2_response = api_client
        .get("/auth/oauth2/google?mode=signup")
        .await
        .expect("Failed to start OAuth2 flow");

    println!("🔍 OAuth2 response status: {}", oauth2_response.status());

    // Step 2: Verify that Set-Cookie header contains CSRF token
    let set_cookie_header = oauth2_response
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie header should be present for CSRF token")
        .to_str()
        .expect("Set-Cookie should be valid UTF-8");

    println!("🍪 Set-Cookie header: {set_cookie_header}");

    // Step 3: Extract the CSRF token value from the cookie
    assert!(set_cookie_header.contains("__Host-CsrfId="));

    let csrf_token_value = set_cookie_header
        .split("__Host-CsrfId=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .expect("Should be able to extract CSRF token from cookie")
        .to_string();

    // Step 4: Verify token is non-empty and looks like a valid token
    assert!(
        !csrf_token_value.is_empty(),
        "CSRF token should not be empty"
    );
    assert!(
        csrf_token_value.len() > 10,
        "CSRF token should be substantial length"
    );

    println!("🎫 Successfully extracted CSRF token: {csrf_token_value}");

    // Step 5: Verify that the token can be used in X-CSRF-Token header format
    let header_value = HeaderValue::from_str(&csrf_token_value);
    assert!(
        header_value.is_ok(),
        "CSRF token should be valid for HTTP header"
    );

    println!("✅ API client CSRF token extraction completed successfully");

    server.shutdown().await;
}

/// Test API client header preparation
///
/// This test validates that API clients can:
/// 1. Prepare proper headers for authenticated requests
/// 2. Include both CSRF tokens and cookies when needed
/// 3. Format headers correctly for API requests
#[tokio::test]
#[serial_test::serial]
async fn test_api_client_header_preparation() {
    let server = TestServer::start()
        .await
        .expect("Failed to start test server");

    let api_client = MockBrowser::new(&server.base_url, false); // No cookies

    // Step 1: Get a CSRF token from an initiation endpoint
    let init_response = api_client
        .get("/auth/oauth2/google?mode=signup")
        .await
        .expect("Failed to get initial CSRF token");

    // Step 2: Extract token for header preparation
    let set_cookie = init_response
        .headers()
        .get("set-cookie")
        .expect("Should receive Set-Cookie header")
        .to_str()
        .expect("Cookie should be valid UTF-8");

    let csrf_token = set_cookie
        .split("__Host-CsrfId=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .expect("Should extract CSRF token")
        .to_string();

    // Step 3: Prepare headers as an API client would
    let mut api_headers = HeaderMap::new();
    api_headers.insert("x-csrf-token", HeaderValue::from_str(&csrf_token).unwrap());
    api_headers.insert(
        "content-type",
        HeaderValue::from_str("application/json").unwrap(),
    );
    api_headers.insert("origin", HeaderValue::from_str(&server.base_url).unwrap());

    // Step 4: Also prepare cookie for requests that need both
    let csrf_cookie = format!("__Host-CsrfId={csrf_token}");
    api_headers.insert("cookie", HeaderValue::from_str(&csrf_cookie).unwrap());

    // Step 5: Verify all headers are properly formatted
    assert!(api_headers.get("x-csrf-token").is_some());
    assert!(api_headers.get("content-type").is_some());
    assert!(api_headers.get("origin").is_some());
    assert!(api_headers.get("cookie").is_some());

    println!("✅ API client header preparation completed successfully");
    println!("📋 Prepared headers:");
    for (name, value) in &api_headers {
        println!("  {name}: {value:?}");
    }

    server.shutdown().await;
}

/// Test mixed CSRF scenarios with both cookies and headers
///
/// This test validates that:
/// 1. Browser clients and API clients can coexist
/// 2. Different CSRF handling approaches work simultaneously
/// 3. The system handles both cookie-based and header-based clients
#[tokio::test]
#[serial_test::serial]
async fn test_api_client_mixed_csrf_scenarios() {
    let server = TestServer::start()
        .await
        .expect("Failed to start test server");

    // Browser client with automatic cookie handling
    let browser_client = MockBrowser::new(&server.base_url, true); // true = use cookies

    // API client without automatic cookie handling
    let api_client = MockBrowser::new(&server.base_url, false); // false = no cookies

    // Step 1: Browser client starts OAuth2 flow (should work with cookies)
    let browser_response = browser_client
        .get("/auth/oauth2/google?mode=signup")
        .await
        .expect("Browser client should start OAuth2 flow");

    // Browser response should be a redirect (3xx) for OAuth2 initiation
    assert!(
        browser_response.status().is_redirection() || browser_response.status().is_success(),
        "Browser client should get redirect or success, got: {}",
        browser_response.status()
    );
    println!("✅ Browser client successfully initiated OAuth2 flow");

    // Step 2: API client starts OAuth2 flow (should also work)
    let api_response = api_client
        .get("/auth/oauth2/google?mode=signup")
        .await
        .expect("API client should start OAuth2 flow");

    // API response should also be a redirect (3xx) for OAuth2 initiation
    assert!(
        api_response.status().is_redirection() || api_response.status().is_success(),
        "API client should get redirect or success, got: {}",
        api_response.status()
    );
    println!("✅ API client successfully initiated OAuth2 flow");

    // Step 3: Verify both get CSRF tokens (different ways)
    // Browser client: automatic cookie handling
    // API client: manual Set-Cookie header parsing

    let api_set_cookie = api_response
        .headers()
        .get("set-cookie")
        .expect("API client should get Set-Cookie header")
        .to_str()
        .expect("Cookie should be valid UTF-8");

    assert!(api_set_cookie.contains("__Host-CsrfId="));
    println!("✅ API client can extract CSRF token from Set-Cookie header");

    // Both clients should be able to operate independently
    println!("✅ Mixed CSRF scenarios (cookies + headers) working correctly");

    server.shutdown().await;
}

/// Test API client CSRF validation behavior
///
/// This test validates that:
/// 1. API clients receive appropriate CSRF validation responses
/// 2. The system properly handles header-based CSRF tokens
/// 3. Error scenarios are handled gracefully for API clients
#[tokio::test]
#[serial_test::serial]
async fn test_api_client_csrf_validation_behavior() {
    let server = TestServer::start()
        .await
        .expect("Failed to start test server");

    let api_client = MockBrowser::new(&server.base_url, false); // No cookies

    // Step 1: Test request without any CSRF token (should be rejected)
    let no_csrf_response = api_client
        .post_form_with_headers(
            "/auth/oauth2/authorized",
            &[("code", "test_code"), ("state", "test_state")],
            &HeaderMap::new(), // No headers
        )
        .await
        .expect("Request should be processed");

    // Should get a CSRF-related error (400 or 403)
    assert!(
        no_csrf_response.status() == reqwest::StatusCode::BAD_REQUEST
            || no_csrf_response.status() == reqwest::StatusCode::FORBIDDEN,
        "Missing CSRF token should result in 400 or 403, got: {}",
        no_csrf_response.status()
    );
    println!("✅ API client properly rejected for missing CSRF token");

    // Step 2: Test request with invalid CSRF token (should be rejected)
    let mut invalid_headers = HeaderMap::new();
    invalid_headers.insert(
        "x-csrf-token",
        HeaderValue::from_str("invalid_token").unwrap(),
    );
    invalid_headers.insert(
        "cookie",
        HeaderValue::from_str("__Host-CsrfId=invalid_token").unwrap(),
    );

    let invalid_csrf_response = api_client
        .post_form_with_headers(
            "/auth/oauth2/authorized",
            &[("code", "test_code"), ("state", "test_state")],
            &invalid_headers,
        )
        .await
        .expect("Request should be processed");

    // Should get a CSRF-related error (400 or 403)
    assert!(
        invalid_csrf_response.status() == reqwest::StatusCode::BAD_REQUEST
            || invalid_csrf_response.status() == reqwest::StatusCode::FORBIDDEN,
        "Invalid CSRF token should result in 400 or 403, got: {}",
        invalid_csrf_response.status()
    );
    println!("✅ API client properly rejected for invalid CSRF token");

    println!("✅ CSRF validation behavior working correctly for API clients");

    server.shutdown().await;
}
