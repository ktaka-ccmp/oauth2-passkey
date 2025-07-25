//! Axum-based mock OAuth2 server for consistent testing
//!
//! This module provides a single Axum server that runs on a fixed port,
//! eliminating LazyLock initialization conflicts between tests.

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
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

/// Shared state for the mock server
#[derive(Clone, Default)]
pub struct MockServerState {
    /// Current test user data
    pub test_user_email: Arc<Mutex<String>>,
    pub test_user_id: Arc<Mutex<String>>,
    /// Nonce storage for current test
    pub nonces: Arc<Mutex<HashMap<String, String>>>,
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
pub fn get_test_server() -> &'static TestServerContext {
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
) -> Result<(StatusCode, HeaderMap), StatusCode> {
    let config = state.test_config.lock().unwrap();
    let redirect_uri = params.get("redirect_uri").unwrap_or(&config.origin_url);
    let state_param = params.get("state").map_or("mock_state", |s| s.as_str());
    let nonce = params.get("nonce");

    // Store nonce if provided
    if let Some(nonce_value) = nonce {
        let mut nonces = state.nonces.lock().unwrap();
        nonces.insert("current_nonce".to_string(), nonce_value.clone());
        println!("🔧 Mock server stored nonce: {nonce_value}");
    }

    let mut headers = HeaderMap::new();
    let redirect_url = format!("{redirect_uri}?code=mock_auth_code&state={state_param}");
    headers.insert("location", redirect_url.parse().unwrap());

    Ok((StatusCode::FOUND, headers))
}

/// OAuth2 token endpoint
async fn oauth2_token(State(state): State<MockServerState>) -> Json<Value> {
    let user_email = state.test_user_email.lock().unwrap().clone();
    let user_id = state.test_user_id.lock().unwrap().clone();
    let nonces = state.nonces.lock().unwrap();
    let current_nonce = nonces.get("current_nonce").cloned();

    // Create mock ID token with nonce
    let id_token = create_mock_id_token(&user_email, &user_id, current_nonce.as_deref());

    Json(json!({
        "access_token": "mock_access_token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile"
    }))
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

/// Configure the mock server for a specific test
pub fn configure_mock_for_test(user_email: String, user_id: String, origin_url: String) {
    let server = get_test_server();

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
