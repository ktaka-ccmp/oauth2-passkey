use crate::common::axum_mock_server::{configure_mock_for_test, get_test_server};
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
}

impl TestServer {
    /// Start a new test server instance
    ///
    /// Creates a test server with:
    /// - Random available port
    /// - In-memory database and cache
    /// - Global Axum mock server for external provider simulation
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
        let _server = get_test_server();

        // Configure the Axum mock server for this test
        configure_mock_for_test(unique_email, unique_user_id, base_url.clone());

        // Set OAUTH2_ISSUER_URL to use the fixed Axum mock server for OIDC Discovery
        unsafe {
            std::env::set_var("OAUTH2_ISSUER_URL", "http://127.0.0.1:9876");
        }
        println!("🔧 Using Axum mock server for OAuth2: http://127.0.0.1:9876");

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

        // Test OAuth2 OIDC Discovery endpoint using the global Axum mock server
        let client = reqwest::Client::new();
        let discovery_response = client
            .get("http://127.0.0.1:9876/.well-known/openid-configuration")
            .send()
            .await
            .expect("Failed to call Axum mock OIDC Discovery endpoint");

        assert!(discovery_response.status().is_success());

        let discovery_doc: serde_json::Value = discovery_response
            .json()
            .await
            .expect("Failed to parse OIDC Discovery response");

        // Verify it's properly configured
        assert_eq!(discovery_doc["issuer"], "http://127.0.0.1:9876");
        assert_eq!(
            discovery_doc["authorization_endpoint"],
            "http://127.0.0.1:9876/oauth2/auth"
        );

        server.shutdown().await;
    }
}
