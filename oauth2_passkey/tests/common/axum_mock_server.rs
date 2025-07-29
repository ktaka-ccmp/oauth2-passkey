//! Axum-based mock OAuth2 server for consistent testing
//!
//! This module provides a single Axum server that runs on a fixed port,
//! eliminating LazyLock initialization conflicts between tests.

use axum::{
    Router,
    extract::{Form, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, LazyLock, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

/// Fixed port for the mock OAuth2 server
pub const MOCK_OAUTH2_PORT: u16 = 9876;
pub const MOCK_OAUTH2_URL: &str = "http://127.0.0.1:9876";

/// Test server context that manages the lifecycle
pub struct TestServerContext {
    pub base_url: String,
    pub state: MockServerState,
    #[allow(dead_code)]
    shutdown: Arc<AtomicBool>,
    _thread_handle: thread::JoinHandle<()>,
}

impl TestServerContext {
    fn new() -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let base_url = MOCK_OAUTH2_URL.to_string();

        // Create shared state
        let state = MockServerState::default();
        let state_clone = state.clone();

        println!("🔧 Starting persistent mock OAuth2 server on port {MOCK_OAUTH2_PORT}...");

        // Start cleanup task for expired codes
        let cleanup_state = state.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_secs(60)); // Clean every minute
                cleanup_expired_codes(&cleanup_state);
            }
        });

        // Start server in background thread (persistent across all tests)
        let thread_handle = thread::spawn(move || {
            // Create a new tokio runtime for this thread
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                start_persistent_mock_server(state_clone, shutdown_clone).await;
            });
        });

        // Wait for server to be ready
        wait_for_server_ready(&base_url);

        println!("✅ Persistent mock OAuth2 server is ready and will stay alive for all tests");

        TestServerContext {
            base_url,
            state,
            shutdown,
            _thread_handle: thread_handle,
        }
    }
}

// Global test server context (initialized once, lives for entire test run)
static TEST_SERVER: LazyLock<TestServerContext> = LazyLock::new(TestServerContext::new);

/// Authorization request data stored during OAuth2 flow
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub redirect_uri: String,
    /// OAuth2 state parameter - returned to client but not validated during token exchange
    #[allow(dead_code)]
    pub state: String,
    pub scope: Option<String>,
    pub response_type: String,
    #[allow(dead_code)]
    pub response_mode: String,
    pub client_id: String,
    pub created_at: u64,
}

/// Shared state for the mock server
#[derive(Clone, Default)]
pub struct MockServerState {
    /// Current test user data
    pub test_user_email: Arc<Mutex<String>>,
    pub test_user_id: Arc<Mutex<String>>,
    /// Authorization codes with their associated request data
    pub authorization_codes: Arc<Mutex<HashMap<String, AuthorizationRequest>>>,
    /// Current test configuration
    pub test_config: Arc<Mutex<TestConfig>>,
}

#[derive(Clone, Default)]
pub struct TestConfig {
    pub origin_url: String,
    pub client_id: String,
    pub client_secret: String,
}

/// Get the global test server context
pub fn get_oidc_mock_server() -> &'static TestServerContext {
    &TEST_SERVER
}

/// Wait for server to be ready by attempting to connect
fn wait_for_server_ready(_base_url: &str) {
    use std::time::Duration;

    println!("🔧 Waiting for mock server to be ready...");
    for attempt in 0..50 {
        match std::net::TcpStream::connect(format!("127.0.0.1:{MOCK_OAUTH2_PORT}")) {
            Ok(_) => {
                println!("✅ Mock server is ready after {} attempts", attempt + 1);
                return;
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    panic!("❌ Mock server failed to start within timeout");
}

/// Start the persistent mock server (runs in its own thread with dedicated runtime)
async fn start_persistent_mock_server(state: MockServerState, shutdown: Arc<AtomicBool>) {
    println!("🔧 Mock OAuth2 server starting in dedicated thread...");

    let app = create_mock_app(state);

    let listener =
        match tokio::net::TcpListener::bind(format!("127.0.0.1:{MOCK_OAUTH2_PORT}")).await {
            Ok(listener) => {
                println!("🔧 Mock OAuth2 server bound to port {MOCK_OAUTH2_PORT}");
                listener
            }
            Err(e) => {
                println!("❌ Failed to bind mock server to port {MOCK_OAUTH2_PORT}: {e}");
                return;
            }
        };

    println!("🔧 Mock OAuth2 server starting serve loop...");

    // Create a server that can be gracefully shut down
    let server = axum::serve(listener, app);

    // Run server until shutdown signal
    tokio::select! {
        result = server => {
            match result {
                Ok(_) => println!("🔧 Mock server exited normally"),
                Err(e) => println!("❌ Mock server error: {e}"),
            }
        }
        _ = wait_for_shutdown(shutdown) => {
            println!("🔧 Mock server received shutdown signal");
        }
    }

    println!("🔧 Mock server thread exiting");
}

/// Wait for shutdown signal
async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

/// Create the Axum application with OAuth2 endpoints
fn create_mock_app(state: MockServerState) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth2/auth", get(oauth2_auth))
        .route("/oauth2/token", post(oauth2_token))
        .route("/oauth2/userinfo", get(oauth2_userinfo))
        .route("/oauth2/v3/certs", get(oauth2_jwks))
        .with_state(state)
}

/// OIDC Discovery endpoint
async fn oidc_discovery(State(state): State<MockServerState>) -> Json<Value> {
    let _config = state.test_config.lock().unwrap();

    Json(json!({
        "issuer": MOCK_OAUTH2_URL,
        "authorization_endpoint": format!("{}/oauth2/auth", MOCK_OAUTH2_URL),
        "token_endpoint": format!("{}/oauth2/token", MOCK_OAUTH2_URL),
        "userinfo_endpoint": format!("{}/oauth2/userinfo", MOCK_OAUTH2_URL),
        "jwks_uri": format!("{}/oauth2/v3/certs", MOCK_OAUTH2_URL),
        "scopes_supported": ["openid", "email", "profile"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"]
    }))
}

/// OAuth2 authorization endpoint
async fn oauth2_auth(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<MockServerState>,
) -> Result<axum::response::Response, StatusCode> {
    let config = state.test_config.lock().unwrap();
    let redirect_uri = params.get("redirect_uri").unwrap_or(&config.origin_url);
    let state_param = params.get("state").map_or("mock_state", |s| s.as_str());
    let nonce = params.get("nonce");
    let code_challenge = params.get("code_challenge");
    let code_challenge_method = params.get("code_challenge_method");
    let scope = params.get("scope");
    let response_type = params.get("response_type").map_or("code", |v| v);
    let client_id = params.get("client_id").unwrap_or(&config.client_id);
    let response_mode = params
        .get("response_mode")
        .map_or("form_post", |v| v.as_str());

    // Generate unique authorization code
    let auth_code = Uuid::new_v4().to_string();

    // Get current timestamp
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create authorization request record
    let auth_request = AuthorizationRequest {
        nonce: nonce.cloned(),
        code_challenge: code_challenge.cloned(),
        code_challenge_method: code_challenge_method.cloned(),
        redirect_uri: redirect_uri.clone(),
        state: state_param.to_string(),
        scope: scope.cloned(),
        response_type: response_type.to_string(),
        response_mode: response_mode.to_string(),
        client_id: client_id.clone(),
        created_at,
    };

    // Store the authorization code and its associated data
    {
        let mut auth_codes = state.authorization_codes.lock().unwrap();
        auth_codes.insert(auth_code.clone(), auth_request.clone());
        println!(
            "🔧 Mock server generated auth code: {} with PKCE: {:?}, nonce: {:?}",
            auth_code,
            code_challenge.is_some(),
            nonce.is_some()
        );
    }

    match response_mode {
        "form_post" => {
            // For form_post, we return a 200 OK with a form that will auto-submit
            let form = format!(
                "<html><body><form id='auth_form' action='{redirect_uri}' method='POST'>\
                 <input type='hidden' name='code' value='{auth_code}'>\
                 <input type='hidden' name='state' value='{state_param}'>\
                 </form><script>document.getElementById('auth_form').submit();</script></body></html>"
            );
            use axum::response::{Html, IntoResponse};
            Ok(Html(form).into_response())
        }
        "query" => {
            // For query, we redirect with code and state in the URL
            let redirect_url = format!("{redirect_uri}?code={auth_code}&state={state_param}");
            use axum::response::{IntoResponse, Redirect};
            Ok(Redirect::to(&redirect_url).into_response())
        }
        _ => {
            // Default to query mode
            let redirect_url = format!("{redirect_uri}?code={auth_code}&state={state_param}");
            use axum::response::{IntoResponse, Redirect};
            Ok(Redirect::to(&redirect_url).into_response())
        }
    }
}

/// OAuth2 token endpoint
async fn oauth2_token(
    State(state): State<MockServerState>,
    Form(params): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let code = params.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let grant_type = params.get("grant_type").map_or("authorization_code", |v| v);
    let code_verifier = params.get("code_verifier");
    let redirect_uri = params.get("redirect_uri");
    let client_id = params.get("client_id");

    // Validate grant type
    if grant_type != "authorization_code" {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Look up the authorization code
    let auth_request = {
        let mut auth_codes = state.authorization_codes.lock().unwrap();
        auth_codes.remove(code).ok_or(StatusCode::BAD_REQUEST)?
    };

    // Validate redirect_uri matches original request
    if let Some(provided_redirect_uri) = redirect_uri {
        if provided_redirect_uri != &auth_request.redirect_uri {
            println!(
                "❌ Redirect URI mismatch: expected {}, got {}",
                auth_request.redirect_uri, provided_redirect_uri
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Validate client_id matches original request
    if let Some(provided_client_id) = client_id {
        if provided_client_id != &auth_request.client_id {
            println!(
                "❌ Client ID mismatch: expected {}, got {}",
                auth_request.client_id, provided_client_id
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Validate response_type was "code" (OAuth2 security requirement)
    if auth_request.response_type != "code" {
        println!("❌ Invalid response_type: {}", auth_request.response_type);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate PKCE if code_challenge was provided in the original request
    if let Some(challenge) = &auth_request.code_challenge {
        let verifier = code_verifier.ok_or(StatusCode::BAD_REQUEST)?;

        // Validate PKCE challenge
        let method = auth_request
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");
        let computed_challenge = match method {
            "S256" => {
                use base64::Engine as _;
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(verifier.as_bytes());
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
            }
            "plain" => verifier.clone(),
            _ => return Err(StatusCode::BAD_REQUEST),
        };

        if computed_challenge != *challenge {
            println!("❌ PKCE validation failed: expected {challenge}, got {computed_challenge}");
            return Err(StatusCode::BAD_REQUEST);
        }

        println!("✅ PKCE validation successful for method: {method}");
    }

    // Check code expiration (10 minutes)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now - auth_request.created_at > 600 {
        println!("❌ Authorization code expired");
        return Err(StatusCode::BAD_REQUEST);
    }

    let user_email = state.test_user_email.lock().unwrap().clone();
    let user_id = state.test_user_id.lock().unwrap().clone();

    // Create mock ID token with the stored nonce
    let id_token = create_mock_id_token(&user_email, &user_id, auth_request.nonce.as_deref());

    println!("✅ Token exchange successful for code: {code}");

    Ok(Json(json!({
        "access_token": "mock_access_token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": auth_request.scope.unwrap_or_else(|| "openid email profile".to_string())
    })))
}

/// OAuth2 userinfo endpoint
async fn oauth2_userinfo(State(state): State<MockServerState>) -> Json<Value> {
    let user_email = state.test_user_email.lock().unwrap().clone();
    let user_id = state.test_user_id.lock().unwrap().clone();

    Json(json!({
        "sub": user_id,
        "email": user_email,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "picture": "https://example.com/photo.jpg",
        "email_verified": true
    }))
}

/// JWKS endpoint
async fn oauth2_jwks() -> Json<Value> {
    use base64::Engine as _;

    Json(json!({
        "keys": [{
            "kty": "oct",
            "kid": "mock_key_id",
            "use": "sig",
            "alg": "HS256",
            "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("test_secret")
        }]
    }))
}

/// Create a mock JWT ID token
fn create_mock_id_token(email: &str, user_id: &str, nonce: Option<&str>) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut claims = json!({
        "iss": MOCK_OAUTH2_URL,
        "sub": user_id,
        "aud": "test-client-id.apps.googleusercontent.com",
        "azp": "test-client-id.apps.googleusercontent.com",
        "exp": now + 3600,
        "iat": now,
        "email": email,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "email_verified": true
    });

    // Add nonce if provided
    if let Some(nonce_value) = nonce {
        claims["nonce"] = json!(nonce_value);
        println!("🔧 Mock JWT includes nonce: {nonce_value}");
    }

    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("mock_key_id".to_string());
    let key = EncodingKey::from_secret("test_secret".as_ref());

    encode(&header, &claims, &key).unwrap_or_else(|_| "mock.jwt.token".to_string())
}

/// Clean up expired authorization codes
fn cleanup_expired_codes(state: &MockServerState) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut auth_codes = state.authorization_codes.lock().unwrap();
    let initial_count = auth_codes.len();

    // Remove codes older than 10 minutes
    auth_codes.retain(|code, request| {
        let is_valid = now - request.created_at <= 600;
        if !is_valid {
            println!("🗑️ Cleaned up expired auth code: {code}");
        }
        is_valid
    });

    let cleaned_count = initial_count - auth_codes.len();
    if cleaned_count > 0 {
        println!("🗑️ Cleaned up {cleaned_count} expired authorization codes");
    }
}

/// Configure the mock server for a specific test
pub fn configure_mock_for_test(user_email: String, user_id: String, origin_url: String) {
    let server = get_oidc_mock_server();

    // The server is guaranteed to be running (persistent thread approach)
    println!("✅ Using persistent mock server at {}", server.base_url);

    // Update test configuration
    *server.state.test_user_email.lock().unwrap() = user_email;
    *server.state.test_user_id.lock().unwrap() = user_id;

    let mut config = server.state.test_config.lock().unwrap();
    config.origin_url = origin_url;
    config.client_id = "test-client-id.apps.googleusercontent.com".to_string();
    config.client_secret = "test-client-secret".to_string();

    println!("🔧 Mock server configured for test");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the mock server's OIDC Discovery endpoint works correctly
    ///
    /// This test validates the mock OAuth2 provider infrastructure, not the oauth2-passkey library.
    /// Useful for debugging when OAuth2 flows fail and you need to isolate mock server issues.
    #[tokio::test]
    async fn test_mock_oidc_discovery_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        // Get the mock server (starts automatically if not running)
        let _server = get_oidc_mock_server();

        // Test OIDC Discovery endpoint directly
        let client = reqwest::Client::new();
        let discovery_url = format!("{MOCK_OAUTH2_URL}/.well-known/openid-configuration");
        println!("🔍 Testing mock OIDC Discovery endpoint at: {discovery_url}");

        let discovery_response = client.get(discovery_url).send().await?;

        println!(
            "OIDC Discovery response status: {}",
            discovery_response.status()
        );
        assert!(
            discovery_response.status().is_success(),
            "OIDC Discovery endpoint should return 200"
        );

        let discovery_doc: serde_json::Value = discovery_response.json().await?;
        println!(
            "OIDC Discovery document: {}",
            serde_json::to_string_pretty(&discovery_doc)?
        );

        // Validate all required OIDC Discovery fields are present as strings
        assert!(
            discovery_doc["issuer"].is_string(),
            "issuer field should be present"
        );
        assert!(
            discovery_doc["authorization_endpoint"].is_string(),
            "authorization_endpoint should be present"
        );
        assert!(
            discovery_doc["token_endpoint"].is_string(),
            "token_endpoint should be present"
        );
        assert!(
            discovery_doc["userinfo_endpoint"].is_string(),
            "userinfo_endpoint should be present"
        );
        assert!(
            discovery_doc["jwks_uri"].is_string(),
            "jwks_uri should be present"
        );

        // Verify exact endpoint URLs
        assert_eq!(discovery_doc["issuer"], MOCK_OAUTH2_URL);
        assert_eq!(
            discovery_doc["authorization_endpoint"],
            format!("{MOCK_OAUTH2_URL}/oauth2/auth")
        );
        assert_eq!(
            discovery_doc["token_endpoint"],
            format!("{MOCK_OAUTH2_URL}/oauth2/token")
        );
        assert_eq!(
            discovery_doc["userinfo_endpoint"],
            format!("{MOCK_OAUTH2_URL}/oauth2/userinfo")
        );
        assert_eq!(
            discovery_doc["jwks_uri"],
            format!("{MOCK_OAUTH2_URL}/oauth2/v3/certs")
        );

        // Verify supported features arrays
        assert!(
            discovery_doc["scopes_supported"].is_array(),
            "scopes_supported should be an array"
        );
        assert!(
            discovery_doc["response_types_supported"].is_array(),
            "response_types_supported should be an array"
        );
        assert!(
            discovery_doc["grant_types_supported"].is_array(),
            "grant_types_supported should be an array"
        );
        assert!(
            discovery_doc["subject_types_supported"].is_array(),
            "subject_types_supported should be an array"
        );
        assert!(
            discovery_doc["id_token_signing_alg_values_supported"].is_array(),
            "id_token_signing_alg_values_supported should be an array"
        );

        println!("✅ Mock OIDC Discovery endpoint validation PASSED");
        println!("  - Issuer URL: {}", discovery_doc["issuer"]);
        println!(
            "  - Authorization endpoint: {}",
            discovery_doc["authorization_endpoint"]
        );
        println!("  - Token endpoint: {}", discovery_doc["token_endpoint"]);
        println!(
            "  - Userinfo endpoint: {}",
            discovery_doc["userinfo_endpoint"]
        );
        println!("  - JWKS URI: {}", discovery_doc["jwks_uri"]);

        Ok(())
    }
}
