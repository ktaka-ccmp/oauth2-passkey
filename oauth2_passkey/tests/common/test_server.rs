use crate::common::nonce_aware_mock::{NonceStorage, create_nonce_aware_mock_oauth2};
use httpmock::MockServer;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Global flag to track if oauth2_passkey has been initialized
static OAUTH2_PASSKEY_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Get the current test origin URL (always consistent across all tests)
pub fn get_test_origin() -> String {
    "http://127.0.0.1:3000".to_string()
}

/// Check if oauth2_passkey library has been initialized
fn should_initialize_oauth2_passkey() -> bool {
    // Since LazyLock values are set once and never change, we only initialize once
    let was_already_initialized =
        OAUTH2_PASSKEY_INITIALIZED.load(std::sync::atomic::Ordering::Acquire);

    if !was_already_initialized {
        println!("🔧 First test run - will initialize oauth2_passkey library");
        true
    } else {
        println!("⏭️  oauth2_passkey already initialized - skipping re-initialization");
        false
    }
}

/// Load test environment configuration
fn load_test_environment() {
    // Load .env_test file - this sets all configuration before LazyLock initialization
    if let Err(e) = dotenvy::from_filename(".env_test") {
        println!("Warning: Could not load .env_test file: {e}");
        println!("This may cause test failures due to missing configuration");
    } else {
        println!("✅ Loaded test configuration from .env_test");
    }

    // Use unique table prefix to isolate test data (the only runtime setting that works)
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique_prefix = format!("test_{unique_id}_");
    unsafe {
        std::env::set_var("DB_TABLE_PREFIX", &unique_prefix);
    }
    println!("🗄️  Using unique table prefix: {unique_prefix}");
}

/// Test server for integration testing
///
/// Provides a minimal HTTP server with oauth2-passkey integration for testing
/// complete authentication flows in an isolated environment.
pub struct TestServer {
    /// Handle to the running server task
    server_handle: JoinHandle<()>,
    /// Base URL of the test server
    pub base_url: String,
    /// Mock OAuth2 server for simulating external providers
    pub mock_oauth2: MockServer,
    /// Storage for nonces to enable proper testing
    pub nonce_storage: NonceStorage,
}

impl TestServer {
    /// Start a new test server instance
    ///
    /// Creates a test server with:
    /// - Random available port
    /// - In-memory database and cache
    /// - Mock OAuth2 server for external provider simulation
    /// - Clean state for each test
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        // Try to bind to the consistent test port (3000) with retries
        let listener = {
            let mut attempts = 0;
            let max_attempts = 20;

            loop {
                match tokio::net::TcpListener::bind("127.0.0.1:3000").await {
                    Ok(listener) => {
                        println!("✅ Test server bound to preferred port 3000");
                        break listener;
                    }
                    Err(_) if attempts < max_attempts => {
                        attempts += 1;
                        println!(
                            "⏳ Port 3000 unavailable, waiting... (attempt {attempts}/{max_attempts})"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                    Err(_) => {
                        println!(
                            "⚠️  Port 3000 unavailable after {max_attempts} attempts, using random port"
                        );
                        break tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    }
                }
            }
        };

        let addr = listener.local_addr()?;
        let base_url = format!("http://127.0.0.1:{}", addr.port());

        // Load test environment configuration and check if we should initialize
        load_test_environment();
        let should_initialize = should_initialize_oauth2_passkey();

        // Set up nonce-aware mock OAuth2 server BEFORE library initialization
        let (mock_oauth2, nonce_storage) = create_nonce_aware_mock_oauth2(&base_url);

        // Generate and set unique user data for this test
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let process_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        let uuid = Uuid::new_v4().to_string().replace("-", "");
        let unique_id = format!("{}_{}_{}_{}", timestamp, process_id, thread_id, &uuid[..8]);
        let unique_email = format!("test_{unique_id}@example.com");
        let unique_user_id = format!("mock_user_{unique_id}");
        println!("🆔 Using unique test user: {unique_email} (ID: {unique_user_id})");

        // Store test user data for mock JWT token generation
        unsafe {
            std::env::set_var("TEST_USER_EMAIL", &unique_email);
            std::env::set_var("TEST_USER_ID", &unique_user_id);
        }

        // Initialize test environment with in-memory stores (only once per test process)
        if should_initialize {
            println!("🚀 Initializing oauth2_passkey library...");
            oauth2_passkey::init().await?;
            OAUTH2_PASSKEY_INITIALIZED.store(true, std::sync::atomic::Ordering::Release);

            println!("✅ oauth2_passkey library initialized successfully");
        } else {
            println!("⏭️  Skipping oauth2_passkey::init() - already initialized");
        }

        // Create minimal test application
        let app = create_test_app(&mock_oauth2.base_url()).await;

        // Start server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        Ok(Self {
            server_handle,
            base_url,
            mock_oauth2,
            nonce_storage,
        })
    }

    /// Shutdown the test server and clean up resources
    pub async fn shutdown(self) {
        self.server_handle.abort();
        // Mock server will automatically clean up when dropped
    }
}

// Note: OAuth2 URL configuration is now handled by httpmock interception.
// Setting environment variables at runtime has no effect due to LazyLock initialization.
// The oauth2_passkey library uses URLs from .env_test loaded before initialization.

/// Create a minimal test application with oauth2-passkey integration  
async fn create_test_app(_oauth2_base_url: &str) -> axum::Router {
    use axum::{Router, response::Json, routing::get};
    use serde_json::json;

    Router::new()
        // Basic health check endpoint
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        // Mount the actual oauth2-passkey routes
        .nest("/auth", oauth2_passkey_axum::oauth2_passkey_router())
}

/// Set up mock Google OAuth2 server
#[allow(dead_code)]
async fn setup_mock_google_oauth2(_test_server_base_url: &str) -> MockServer {
    use httpmock::prelude::*;
    use serde_json::json;

    let server = MockServer::start();
    println!("Mock OAuth2 server started at: {}", server.base_url());

    // Generate unique user data for this test to avoid database conflicts
    // Store it globally so JWT token generation can use the same values
    // Use UUID + timestamp + process ID for maximum uniqueness
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let process_id = std::process::id();
    let thread_id = format!("{:?}", std::thread::current().id());
    let uuid = Uuid::new_v4().to_string().replace("-", "");
    let unique_id = format!("{}_{}_{}_{}", timestamp, process_id, thread_id, &uuid[..8]);
    let unique_email = format!("test_{unique_id}@example.com");
    let unique_user_id = format!("mock_user_{unique_id}");

    println!("🆔 Using unique test user: {unique_email} (ID: {unique_user_id})");

    // Store the user data for JWT token generation
    unsafe {
        std::env::set_var("TEST_USER_EMAIL", &unique_email);
        std::env::set_var("TEST_USER_ID", &unique_user_id);
    }

    // Mock JWKS endpoint for JWT verification
    server.mock(|when, then| {
        when.method(GET).path("/oauth2/v3/certs");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(create_mock_jwks());
    });

    // Mock authorization endpoint
    server.mock(|when, then| {
        when.method(GET)
            .path("/oauth2/auth")
            .query_param_exists("client_id")
            .query_param_exists("redirect_uri")
            .query_param_exists("state");
        then.status(302).header(
            "location",
            format!(
                "{}/auth/oauth2/authorized?code=mock_auth_code&state=PLACEHOLDER",
                get_test_origin()
            ),
        );
    });

    // Mock token endpoint - OAuth2 token exchange requires Basic Auth with client credentials
    server.mock(|when, then| {
        when.method(POST).path("/oauth2/token").header(
            "authorization",
            "Basic dGVzdF9jbGllbnRfaWQ6dGVzdF9jbGllbnRfc2VjcmV0",
        ); // base64(test_client_id:test_client_secret)
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "mock_access_token",
                "id_token": create_mock_id_token(None), // No nonce needed since we skip verification
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid email profile"
            }));
    });

    // Fallback token endpoint without auth header for debugging
    server.mock(|when, then| {
        when.method(POST).path("/oauth2/token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "access_token": "mock_access_token_fallback",
                "id_token": create_mock_id_token(None), // No nonce needed since we skip verification
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid email profile"
            }));
    });

    // Mock userinfo endpoint - with specific access token
    server.mock(|when, then| {
        when.method(GET)
            .path("/oauth2/userinfo")
            .header("authorization", "Bearer mock_access_token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": unique_user_id.clone(),
                "email": unique_email.clone(),
                "name": "Test User",
                "given_name": "Test",
                "family_name": "User",
                "picture": "https://example.com/photo.jpg",
                "verified_email": true
            }));
    });

    // Mock userinfo endpoint - fallback for any access token
    server.mock(|when, then| {
        when.method(GET).path("/oauth2/userinfo");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": unique_user_id.clone(),
                "email": unique_email.clone(),
                "name": "Test User",
                "given_name": "Test",
                "family_name": "User",
                "picture": "https://example.com/photo.jpg",
                "verified_email": true
            }));
    });

    server
}

/// Create a mock JWKS response for JWT verification
#[allow(dead_code)]
fn create_mock_jwks() -> serde_json::Value {
    use serde_json::json;

    // Create a JWKS with an HMAC key that matches our test JWT signing
    // This allows the JWT verification to succeed in test environment
    json!({
        "keys": [
            {
                "kty": "oct",
                "kid": "mock_key_id",
                "use": "sig",
                "alg": "HS256",
                "k": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b"test_secret")
            }
        ]
    })
}

/// Create a mock JWT ID token for testing
#[allow(dead_code)]
fn create_mock_id_token(nonce: Option<String>) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    // Use the same user data that was set by the mock server setup
    let unique_email =
        std::env::var("TEST_USER_EMAIL").unwrap_or_else(|_| "test@example.com".to_string());
    let unique_user_id =
        std::env::var("TEST_USER_ID").unwrap_or_else(|_| "mock_user_123".to_string());

    let mut claims = json!({
        "iss": "https://accounts.google.com",
        "sub": unique_user_id,
        "aud": "test-client-id.apps.googleusercontent.com", // Use the same client_id as in .env_test
        "azp": "test-client-id.apps.googleusercontent.com", // Authorized party - required by OAuth2 library
        "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        "iat": chrono::Utc::now().timestamp(),
        "email": unique_email,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "email_verified": true
    });

    // Add nonce if provided
    if let Some(nonce_value) = nonce {
        claims["nonce"] = json!(nonce_value);
    }

    // Create a header with kid (key ID) as required by the OAuth2 library
    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("mock_key_id".to_string());

    // Use a dummy key for testing - in real integration tests,
    // you would set up proper JWT verification
    let key = EncodingKey::from_secret("test_secret".as_ref());
    encode(&header, &claims, &key).unwrap_or_else(|_| "mock.jwt.token".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_server_startup_and_shutdown() {
        let server = TestServer::start()
            .await
            .expect("Failed to start test server");

        // Verify server is running
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/health", server.base_url))
            .send()
            .await
            .expect("Failed to connect to test server");

        assert!(response.status().is_success());

        // Clean shutdown
        server.shutdown().await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_mock_oauth2_server() {
        let server = TestServer::start()
            .await
            .expect("Failed to start test server");

        // Test OAuth2 authorization endpoint
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects
            .build()
            .unwrap();
        let auth_response = client
            .get(format!("{}/oauth2/auth", server.mock_oauth2.base_url()))
            .query(&[
                ("client_id", "test_client"),
                ("redirect_uri", &format!("{}/callback", server.base_url)),
                ("state", "test_state"),
                ("nonce", "test_nonce"), // Required by nonce-aware mock server
            ])
            .send()
            .await
            .expect("Failed to call mock OAuth2 auth endpoint");

        assert_eq!(auth_response.status(), 302);

        server.shutdown().await;
    }
}
