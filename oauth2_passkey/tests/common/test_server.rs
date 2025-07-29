use crate::common::axum_mock_server::{configure_mock_for_test, get_oidc_mock_server};
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Global flag to track if oauth2_passkey has been initialized
static OAUTH2_PASSKEY_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Get the current test origin URL (always consistent across all tests)
pub fn get_test_origin() -> String {
    std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
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

/// Initialize tracing for tests with trace level
fn init_test_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init()
            .ok(); // Ignore errors if already initialized
        println!("🔍 Initialized tracing with TRACE level for tests");
    });
}

/// Load test environment configuration
fn load_test_environment() {
    // Initialize tracing first
    init_test_tracing();

    // Load .env_test file - this sets all configuration before LazyLock initialization
    if let Err(e) = dotenvy::from_filename(".env_test") {
        println!("Warning: Could not load .env_test file: {e}");
        println!("This may cause test failures due to missing configuration");
    } else {
        println!("✅ Loaded test configuration from .env_test");
    }
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
}

impl TestServer {
    /// Start a new test server instance
    ///
    /// Creates a test server with:
    /// - Port specified by ORIGIN environment variable (default: http://127.0.0.1:3000)
    /// - In-memory database and cache
    /// - Global Axum mock server for external provider simulation
    /// - Clean state for each test
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        // Load test environment first to get ORIGIN
        load_test_environment();

        // Parse ORIGIN to get host and port
        let origin =
            std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());

        let url = url::Url::parse(&origin).map_err(|e| format!("Invalid ORIGIN URL: {e}"))?;

        let host = url.host_str().ok_or("ORIGIN must have a host")?;
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });

        let bind_addr = format!("{host}:{port}");
        println!("🔧 Binding test server to {bind_addr} (from ORIGIN={origin})");

        // Bind to the exact address specified in ORIGIN with retry logic
        let listener = {
            let mut attempts = 0;
            const MAX_RETRIES: u8 = 100;
            const RETRY_DELAY_MS: u64 = 100;

            loop {
                match tokio::net::TcpListener::bind(&bind_addr).await {
                    Ok(listener) => break listener,
                    Err(e) => {
                        attempts += 1;
                        if attempts >= MAX_RETRIES {
                            return Err(format!(
                                "Failed to bind to {bind_addr} after {MAX_RETRIES} attempts: {e}. Make sure the port is available."
                            ).into());
                        }
                        println!(
                            "⚠️  Failed to bind to {bind_addr} (attempt {}/{}): {e}. Retrying in {}ms...",
                            attempts, MAX_RETRIES, RETRY_DELAY_MS
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS))
                            .await;
                    }
                }
            }
        };

        println!("✅ Test server bound to {bind_addr}");

        let addr = listener.local_addr()?;
        let base_url = origin.clone();

        // Check if we should initialize
        let should_initialize = should_initialize_oauth2_passkey();

        // Generate unique user data for this test
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

        // Get the persistent mock server (automatically starts if needed)
        let _server = get_oidc_mock_server();

        // Configure the Axum mock server for this test
        configure_mock_for_test(unique_email, unique_user_id, base_url.clone());

        // Initialize test environment with in-memory stores (only once per test process)
        if should_initialize {
            println!("🚀 Initializing oauth2_passkey library...");
            oauth2_passkey::init().await?;
            OAUTH2_PASSKEY_INITIALIZED.store(true, std::sync::atomic::Ordering::Release);

            println!("✅ oauth2_passkey library initialized successfully");
        } else {
            println!("⏭️  Skipping oauth2_passkey::init() - already initialized");
        }

        // OAuth2 issuer URL is configured via .env_test file
        println!("🔧 OAuth2 issuer configured from environment variables");

        // Create minimal test application
        let app = create_test_app().await;

        // Start server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        Ok(Self {
            server_handle,
            base_url,
        })
    }

    /// Shutdown the test server and clean up resources
    pub async fn shutdown(self) {
        self.server_handle.abort();
        // Axum mock server continues running as a global instance
    }
}

/// Create a minimal test application with oauth2-passkey integration
/// OAuth2 configuration is handled by the global Axum mock server on fixed port 9876
async fn create_test_app() -> axum::Router {
    use axum::{Router, response::Json, routing::get};
    use serde_json::json;

    Router::new()
        // Basic health check endpoint
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        // Mount the actual oauth2-passkey routes
        .nest("/auth", oauth2_passkey_axum::oauth2_passkey_router())
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
    async fn test_axum_mock_oauth2_server() {
        let server = TestServer::start()
            .await
            .expect("Failed to start test server");

        // Get OAuth2 issuer URL from environment
        let oauth2_issuer_url = std::env::var("OAUTH2_ISSUER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9876".to_string());

        // Test OAuth2 OIDC Discovery endpoint
        let client = reqwest::Client::new();
        let discovery_response = client
            .get(format!(
                "{oauth2_issuer_url}/.well-known/openid-configuration"
            ))
            .send()
            .await
            .expect("Failed to call OAuth2 OIDC Discovery endpoint");

        assert!(discovery_response.status().is_success());

        let discovery_doc: serde_json::Value = discovery_response
            .json()
            .await
            .expect("Failed to parse OIDC Discovery response");

        // Verify it's properly configured
        assert_eq!(discovery_doc["issuer"], oauth2_issuer_url);
        assert_eq!(
            discovery_doc["authorization_endpoint"],
            format!("{oauth2_issuer_url}/oauth2/auth")
        );

        server.shutdown().await;
    }
}
