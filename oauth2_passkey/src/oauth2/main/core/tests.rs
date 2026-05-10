use super::*;
use crate::oauth2::provider::ProviderConfig;
use crate::test_utils::init_test_environment;
use std::collections::HashMap;

/// Test OAuth2 request preparation with an authenticated session
///
/// This test verifies that OAuth2 authorization request generation works correctly
/// when a user session exists, including proper state encoding and URL construction.
///
#[tokio::test]
async fn test_oauth2_request_preparation_with_session() {
    init_test_environment().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("test-user-agent"),
    );
    headers.insert(
        http::header::COOKIE,
        http::HeaderValue::from_static("session_id=test_session_123"),
    );

    let test_auth_url = "https://test.example.com/oauth/authorize";
    let ctx = ProviderConfig::for_test(test_auth_url, "query");
    let result = prepare_oauth2_auth_request_inner(&ctx, headers, Some("signup")).await;

    assert!(result.is_ok());
    let (auth_url, response_headers) = result.unwrap();

    let parsed_url = url::Url::parse(&auth_url).expect("Should generate valid URL");

    assert!(
        auth_url.starts_with(test_auth_url),
        "Should use provided auth URL"
    );

    let params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
    assert!(params.contains_key("client_id"), "Should include client_id");
    assert!(
        params.contains_key("redirect_uri"),
        "Should include redirect_uri"
    );
    assert!(
        params.contains_key("state"),
        "Should include state parameter"
    );
    assert!(
        params.contains_key("nonce"),
        "Should include nonce for OIDC"
    );
    assert!(
        params.contains_key("code_challenge"),
        "Should include PKCE challenge"
    );
    assert_eq!(
        params.get("code_challenge_method"),
        Some(&"S256".to_string()),
        "Should use S256 PKCE method"
    );
    assert_eq!(
        params.get("response_type"),
        Some(&"code".to_string()),
        "Should use authorization code flow"
    );

    let set_cookie_headers: Vec<_> = response_headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(!set_cookie_headers.is_empty());
    let csrf_cookie = set_cookie_headers
        .iter()
        .find(|cookie| cookie.contains(&*OAUTH2_CSRF_COOKIE_NAME))
        .expect("CSRF cookie should be set");

    println!("Actual cookie: {csrf_cookie}");

    assert!(csrf_cookie.contains("HttpOnly"));

    // "query" mode → SameSite=Lax
    assert!(
        csrf_cookie.contains("SameSite=Lax"),
        "Expected SameSite=Lax in cookie: {csrf_cookie}"
    );
}

/// Test OAuth2 request preparation without an authenticated session
///
/// This test verifies that OAuth2 authorization request generation works correctly
/// when no user session exists, handling the anonymous case.
///
#[tokio::test]
async fn test_oauth2_request_preparation_without_session() {
    init_test_environment().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("test-user-agent"),
    );

    let test_auth_url = "https://test.example.com/oauth/authorize";
    let ctx = ProviderConfig::for_test(test_auth_url, "query");
    let result = prepare_oauth2_auth_request_inner(&ctx, headers, None).await;

    assert!(result.is_ok());
    let (auth_url, response_headers) = result.unwrap();

    let parsed_url = url::Url::parse(&auth_url).expect("Should generate valid URL");

    assert!(
        auth_url.starts_with(test_auth_url),
        "Should use provided auth URL"
    );

    let params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
    assert!(params.contains_key("client_id"), "Should include client_id");
    assert!(
        params.contains_key("redirect_uri"),
        "Should include redirect_uri"
    );
    assert!(
        params.contains_key("state"),
        "Should include state parameter"
    );
    assert!(
        params.contains_key("nonce"),
        "Should include nonce for OIDC"
    );
    assert!(
        params.contains_key("code_challenge"),
        "Should include PKCE challenge"
    );
    assert_eq!(
        params.get("code_challenge_method"),
        Some(&"S256".to_string()),
        "Should use S256 PKCE method"
    );
    assert_eq!(
        params.get("response_type"),
        Some(&"code".to_string()),
        "Should use authorization code flow"
    );

    assert!(
        response_headers.contains_key("set-cookie"),
        "Should set CSRF cookie"
    );
}

/// Test state encoding and decoding roundtrip
///
/// This test verifies that StateParams can be encoded to base64 and decoded back
/// to the original values, ensuring the serialization roundtrip maintains data integrity.
///
#[tokio::test]
async fn test_state_encoding_decoding_roundtrip() {
    let original_state = StateParams {
        csrf_id: "test_csrf_id".to_string(),
        nonce_id: "test_nonce_id".to_string(),
        pkce_id: "test_pkce_id".to_string(),
        misc_id: Some("test_misc_id".to_string()),
        mode_id: Some("signup".to_string()),
        provider: "google".to_string(),
    };

    let encoded = encode_state(original_state.clone()).unwrap();
    let decoded = decode_state(&encoded).unwrap();

    assert_eq!(original_state.csrf_id, decoded.csrf_id);
    assert_eq!(original_state.nonce_id, decoded.nonce_id);
    assert_eq!(original_state.pkce_id, decoded.pkce_id);
    assert_eq!(original_state.misc_id, decoded.misc_id);
    assert_eq!(original_state.mode_id, decoded.mode_id);
    assert_eq!(original_state.provider, decoded.provider);
}

/// Test OAuth2State validation with invalid base64 input
///
/// This test verifies that `OAuth2State::new` returns an appropriate error when given
/// invalid base64 input that cannot be decoded. This tests the validation boundary
/// where external data is converted to a type-safe OAuth2State.
///
#[tokio::test]
async fn test_state_validation_invalid_base64() {
    let result = crate::OAuth2State::new("invalid_base64_@#$%".to_string());

    assert!(result.is_err());
    match result {
        Err(OAuth2Error::DecodeState(_)) => {}
        Ok(_) => {
            unreachable!("Unexpectedly got Ok");
        }
        Err(err) => {
            unreachable!("Expected DecodeState error, got {:?}", err);
        }
    }
}

/// Test OAuth2State validation with invalid JSON payload
///
/// This test verifies that `OAuth2State::new` returns an appropriate error when given
/// valid base64 that contains invalid JSON that cannot be parsed. This tests the validation
/// boundary where external data is converted to a type-safe OAuth2State.
///
#[tokio::test]
async fn test_state_validation_invalid_json() {
    let invalid_json = base64url_encode(b"not valid json".to_vec()).unwrap();
    let result = crate::OAuth2State::new(invalid_json);

    assert!(result.is_err());
    match result {
        Err(OAuth2Error::DecodeState(_)) => {}
        Ok(_) => {
            unreachable!("Unexpectedly got Ok");
        }
        Err(err) => {
            unreachable!("Expected DecodeState error, got {:?}", err);
        }
    }
}

/// Test CSRF cookie SameSite attribute for form_post response mode
///
/// This test verifies that form_post mode uses SameSite=None to allow cross-origin POST requests.
///
#[tokio::test]
async fn test_oauth2_csrf_cookie_samesite_form_post_mode() {
    init_test_environment().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("test-user-agent"),
    );

    let test_auth_url = "https://test.example.com/oauth/authorize";
    let ctx = ProviderConfig::for_test(test_auth_url, "form_post");
    let result = prepare_oauth2_auth_request_inner(&ctx, headers, None).await;

    assert!(result.is_ok());
    let (_, response_headers) = result.unwrap();

    let csrf_cookie = extract_csrf_cookie(&response_headers);

    assert!(
        csrf_cookie.contains("HttpOnly"),
        "Cookie should be HttpOnly"
    );
    assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
    assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

    assert!(
        csrf_cookie.contains("SameSite=None"),
        "form_post mode should use SameSite=None for cross-origin POST requests. Cookie: {csrf_cookie}"
    );
}

/// Test CSRF cookie SameSite attribute for query response mode
///
/// This test verifies that query mode uses SameSite=Lax for redirect-based flows.
///
#[tokio::test]
async fn test_oauth2_csrf_cookie_samesite_query_mode() {
    init_test_environment().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("test-user-agent"),
    );

    let test_auth_url = "https://test.example.com/oauth/authorize";
    let ctx = ProviderConfig::for_test(test_auth_url, "query");
    let result = prepare_oauth2_auth_request_inner(&ctx, headers, None).await;

    assert!(result.is_ok());
    let (_, response_headers) = result.unwrap();

    let csrf_cookie = extract_csrf_cookie(&response_headers);

    assert!(
        csrf_cookie.contains("HttpOnly"),
        "Cookie should be HttpOnly"
    );
    assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
    assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

    assert!(
        csrf_cookie.contains("SameSite=Lax"),
        "query mode should use SameSite=Lax for redirect-based flows. Cookie: {csrf_cookie}"
    );
}

/// Test CSRF cookie SameSite attribute for unknown response mode
///
/// This test verifies that unknown response modes default to SameSite=Lax for security.
///
#[tokio::test]
async fn test_oauth2_csrf_cookie_samesite_unknown_mode() {
    init_test_environment().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("test-user-agent"),
    );

    let test_auth_url = "https://test.example.com/oauth/authorize";
    let ctx = ProviderConfig::for_test(test_auth_url, "unknown_mode");
    let result = prepare_oauth2_auth_request_inner(&ctx, headers, None).await;

    assert!(result.is_ok());
    let (_, response_headers) = result.unwrap();

    let csrf_cookie = extract_csrf_cookie(&response_headers);

    assert!(
        csrf_cookie.contains("HttpOnly"),
        "Cookie should be HttpOnly"
    );
    assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
    assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

    assert!(
        csrf_cookie.contains("SameSite=Lax"),
        "Unknown response mode should default to SameSite=Lax. Cookie: {csrf_cookie}"
    );
}

/// Test CSRF cookie SameSite attribute configuration based on current config
///
/// This integration test verifies that CSRF cookies are configured with appropriate SameSite
/// attributes based on the OAuth2 response mode set to "query" (matching .env_test).
///
#[tokio::test]
async fn test_oauth2_csrf_cookie_samesite_based_on_response_mode() {
    init_test_environment().await;

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("test-user-agent"),
    );

    let test_auth_url = "https://test.example.com/oauth/authorize";
    // .env_test sets OAUTH2_RESPONSE_MODE=query
    let ctx = ProviderConfig::for_test(test_auth_url, "query");
    let result = prepare_oauth2_auth_request_inner(&ctx, headers, None).await;

    assert!(result.is_ok());
    let (_, response_headers) = result.unwrap();

    let csrf_cookie = extract_csrf_cookie(&response_headers);

    assert!(
        csrf_cookie.contains("HttpOnly"),
        "Cookie should be HttpOnly"
    );
    assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
    assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

    // "query" mode → SameSite=Lax
    assert!(
        csrf_cookie.contains("SameSite=Lax"),
        "query mode should use SameSite=Lax for redirect-based flows. Cookie: {csrf_cookie}"
    );
}

/// Helper function to extract CSRF cookie from response headers
fn extract_csrf_cookie(response_headers: &HeaderMap) -> String {
    let set_cookie_headers: Vec<_> = response_headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();

    assert!(
        !set_cookie_headers.is_empty(),
        "Should have set-cookie headers"
    );

    set_cookie_headers
        .iter()
        .find(|cookie| cookie.contains(&*OAUTH2_CSRF_COOKIE_NAME))
        .expect("CSRF cookie should be set")
        .to_string()
}
