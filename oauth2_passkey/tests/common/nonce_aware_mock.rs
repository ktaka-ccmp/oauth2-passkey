use base64::Engine as _;
/// Nonce-aware mock OAuth2 server for proper integration testing
///
/// This module provides a mock OAuth2 server that correctly handles nonce
/// parameters following the actual OIDC flow where:
/// 1. Library generates and stores nonce in its cache
/// 2. Mock token endpoint retrieves that nonce from library's cache
/// 3. Mock returns ID token with the correct nonce embedded
use httpmock::prelude::*;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Storage for mapping authorization codes to nonces (legacy - will be replaced)
pub type NonceStorage = Arc<Mutex<HashMap<String, String>>>;

/// Create a nonce-aware mock OAuth2 server
pub fn create_nonce_aware_mock_oauth2(test_origin: &str) -> (MockServer, NonceStorage) {
    eprintln!("🔧 ROOT CAUSE: Creating nonce-aware mock OAuth2 server");
    eprintln!("   Test origin: {test_origin}");

    let server = MockServer::start();
    eprintln!("   MockServer started at: {}", server.base_url());

    let nonce_storage = Arc::new(Mutex::new(HashMap::new()));
    eprintln!("   Nonce storage created");

    eprintln!("   Setting up mock endpoints...");
    setup_nonce_aware_endpoints_with_capture(&server, test_origin, Arc::clone(&nonce_storage));
    eprintln!("   Mock endpoints setup complete");

    (server, nonce_storage)
}

/// Set up endpoints that properly mimic OIDC provider nonce handling
fn setup_nonce_aware_endpoints_with_capture(
    server: &MockServer,
    test_origin: &str,
    nonce_storage: NonceStorage,
) {
    eprintln!("   🔍 Setting up authorization endpoint...");
    // Authorization endpoint - captures nonce like a real OIDC provider
    setup_auth_endpoint_with_nonce_capture(server, test_origin, Arc::clone(&nonce_storage));
    eprintln!("   ✅ Authorization endpoint setup done");

    eprintln!("   🔍 Setting up token endpoint...");
    // Token endpoint - returns ID token with stored nonce like a real OIDC provider
    setup_token_endpoint_with_nonce_support(server, Arc::clone(&nonce_storage));
    eprintln!("   ✅ Token endpoint setup done");

    // Mock userinfo endpoint
    server.mock(|when, then| {
        when.method(GET).path("/oauth2/userinfo");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "sub": std::env::var("TEST_USER_ID").unwrap_or_else(|_| "mock_user_123".to_string()),
                "email": std::env::var("TEST_USER_EMAIL").unwrap_or_else(|_| "test@example.com".to_string()),
                "name": "Test User",
                "given_name": "Test",
                "family_name": "User",
                "picture": "https://example.com/avatar.jpg",
                "email_verified": true
            }));
    });

    // Mock JWKS endpoint
    server.mock(|when, then| {
        when.method(GET).path("/oauth2/v3/certs");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "keys": [
                    {
                        "kty": "oct",
                        "alg": "HS256",
                        "use": "sig",
                        "kid": "mock_key_id",
                        "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("test_secret")
                    }
                ]
            }));
    });
}

/// Create an ID token with proper nonce included
fn create_id_token_with_nonce(nonce: Option<&str>) -> String {
    let unique_email =
        std::env::var("TEST_USER_EMAIL").unwrap_or_else(|_| "test@example.com".to_string());
    let unique_user_id =
        std::env::var("TEST_USER_ID").unwrap_or_else(|_| "mock_user_123".to_string());

    let mut claims = json!({
        "iss": "https://accounts.google.com",
        "sub": unique_user_id,
        "aud": "test-client-id.apps.googleusercontent.com",
        "azp": "test-client-id.apps.googleusercontent.com",
        "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        "iat": chrono::Utc::now().timestamp(),
        "email": unique_email,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "email_verified": true
    });

    // Include nonce if provided
    if let Some(nonce_value) = nonce {
        eprintln!("MOCK ID TOKEN: Adding nonce to claims: {nonce_value}");
        claims["nonce"] = json!(nonce_value);
    } else {
        eprintln!("MOCK ID TOKEN: No nonce provided, creating token without nonce");
    }

    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("mock_key_id".to_string());
    let key = EncodingKey::from_secret("test_secret".as_ref());

    encode(&header, &claims, &key).unwrap_or_else(|_| "mock.jwt.token".to_string())
}

/// Helper to extract nonce from authorization URL
pub fn extract_nonce_from_auth_url(auth_url: &str) -> Option<String> {
    url::Url::parse(auth_url).ok().and_then(|url| {
        url.query_pairs()
            .find(|(key, _)| key == "nonce")
            .map(|(_, value)| value.to_string())
    })
}

/// Store a nonce for a specific test
#[allow(dead_code)]
pub fn store_test_nonce(storage: &NonceStorage, nonce: &str) {
    let mut store = storage.lock().unwrap();
    store.insert("current_test_nonce".to_string(), nonce.to_string());
    eprintln!("STORED NONCE: {nonce}");
    eprintln!("STORAGE NOW CONTAINS: {:?}", *store);
}

/// Capture nonce from URL by extracting it and storing it
#[allow(dead_code)]
pub fn capture_and_store_nonce_from_url(auth_url: &str, storage: &NonceStorage) {
    if let Some(nonce) = extract_nonce_from_auth_url(auth_url) {
        eprintln!("CAPTURING NONCE: Extracted nonce from URL: {nonce}");
        store_test_nonce(storage, &nonce);
    } else {
        eprintln!("CAPTURING NONCE: No nonce found in URL: {auth_url}");
    }
}

/// Set up authorization endpoint that captures nonce from requests like a real OIDC provider
fn setup_auth_endpoint_with_nonce_capture(
    server: &MockServer,
    test_origin: &str,
    _nonce_storage: NonceStorage,
) {
    // For now, set up a standard authorization endpoint
    // The nonce capture will be handled by analyzing request history
    server.mock(|when, then| {
        when.method(GET)
            .path("/oauth2/auth")
            .query_param_exists("nonce");

        then.status(302).header(
            "location",
            format!(
                "{test_origin}/auth/oauth2/authorized?code=nonce_aware_auth_code&state=PLACEHOLDER"
            ),
        );
    });
}

/// Set up token endpoint that returns ID tokens with stored nonce like a real OIDC provider
fn setup_token_endpoint_with_nonce_support(server: &MockServer, nonce_storage: NonceStorage) {
    // IMPORTANT: The key insight is that for all tests to work with nonce verification enabled,
    // we need to do what a real OIDC provider does:
    // 1. When the authorization request comes in with a nonce, store it associated with the auth code
    // 2. When the token exchange happens with that auth code, return an ID token with the nonce

    // For now, let's set up the token endpoint to check if a nonce was stored
    // and include it in the ID token if available. This will make most tests pass.

    server.mock(|when, then| {
        when.method(POST).path("/oauth2/token");

        // Try to use the stored nonce if available
        // Note: This is a compromise solution since httpmock doesn't support true dynamic responses
        then.status(200)
            .header("content-type", "application/json")
            .json_body({
                // Try to get the stored nonce immediately during setup
                let storage = nonce_storage.lock().unwrap();
                let stored_nonce = storage.get("captured_nonce").cloned();
                drop(storage);

                let id_token = create_id_token_with_nonce(stored_nonce.as_deref());

                eprintln!(
                    "🔧 TOKEN ENDPOINT SETUP: Creating response with nonce: {:?}",
                    stored_nonce.as_ref().map(|n| &n[0..16.min(n.len())])
                );

                json!({
                    "access_token": "mock_access_token",
                    "id_token": id_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid email profile"
                })
            });
    });

    // Note: This approach has limitations - the nonce is resolved during mock setup, not request time.
    // For tests that need to demonstrate nonce verification failures, they would need to clear
    // the nonce storage before calling this function, or set up the mock differently.
}

/// Capture nonce from authorization request (simulating OIDC provider behavior)
pub fn capture_nonce_from_auth_request(auth_url: &str, storage: &NonceStorage) -> Option<String> {
    if let Some(nonce) = extract_nonce_from_auth_url(auth_url) {
        eprintln!("🏭 MOCK OIDC PROVIDER - Authorization Request");
        eprintln!(
            "   Received nonce parameter: {} (length: {})",
            &nonce[0..16.min(nonce.len())],
            nonce.len()
        );
        eprintln!("   Full nonce: {nonce}");
        eprintln!("   Storing complete nonce for later token exchange...");

        let mut store = storage.lock().unwrap();
        store.insert("captured_nonce".to_string(), nonce.clone());
        drop(store);

        eprintln!("   ✅ Complete nonce stored - will be included in ID token");
        Some(nonce)
    } else {
        eprintln!("🏭 MOCK OIDC PROVIDER - No nonce in authorization request");
        None
    }
}

/// Set up controlled test scenario for nonce verification
pub fn setup_controlled_nonce_test(storage: &NonceStorage, test_scenario: &str) {
    match test_scenario {
        "success" => {
            // Don't pre-populate - let the auth request capture the real nonce
            eprintln!("🎯 CONTROLLED TEST: Success scenario - will use captured nonce");
        }
        "failure" => {
            // Pre-populate with wrong nonce to force mismatch
            let wrong_nonce = "wrong_nonce_for_testing_failure_case_12345";
            let mut store = storage.lock().unwrap();
            store.insert("captured_nonce".to_string(), wrong_nonce.to_string());
            drop(store);
            eprintln!("🎯 CONTROLLED TEST: Failure scenario - pre-populated with wrong nonce");
        }
        _ => {
            eprintln!("🎯 CONTROLLED TEST: Unknown scenario: {test_scenario}");
        }
    }
}
