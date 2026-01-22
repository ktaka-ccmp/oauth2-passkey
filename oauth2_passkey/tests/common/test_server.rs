use crate::common::axum_mock_server::{configure_mock_for_test, get_oidc_mock_server};
use tokio::task::JoinHandle;

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
    /// - Port from ORIGIN environment variable (default: http://127.0.0.1:3000)
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

        // Bind to the exact address specified in ORIGIN with highly aggressive retry logic and jitter
        let listener = {
            let mut attempts = 0;
            const MAX_RETRIES: u16 = 3000; // Very high retry count
            const BASE_DELAY_MS: u64 = 1; // Start with 1ms
            const MAX_DELAY_MS: u64 = 50; // Cap at 50ms to allow more cleanup time

            loop {
                match tokio::net::TcpListener::bind(&bind_addr).await {
                    Ok(listener) => {
                        if attempts > 0 {
                            println!(
                                "✅ Successfully bound to {bind_addr} after {attempts} attempts"
                            );
                        }
                        break listener;
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts >= MAX_RETRIES {
                            return Err(format!(
                                "Failed to bind to {bind_addr} after {MAX_RETRIES} attempts: {e}. Make sure the port is available."
                            ).into());
                        }

                        // Exponential backoff with significant jitter for better contention handling
                        let base_delay = BASE_DELAY_MS * (1 << std::cmp::min(attempts / 300, 3)); // Exponential every 300 attempts
                        let jitter = (attempts as u64 * 7919) % 8; // Pseudo-random jitter 0-7ms
                        let delay_ms = std::cmp::min(base_delay + jitter, MAX_DELAY_MS);

                        // Only show progress every 200 attempts to reduce noise
                        if attempts % 200 == 0 || attempts <= 5 {
                            println!(
                                "⚠️  Failed to bind to {bind_addr} (attempt {attempts}/{MAX_RETRIES}): {e}. Retrying in {delay_ms}ms..."
                            );
                        }

                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        };

        let base_url = origin.clone();

        // Check if we should initialize
        let should_initialize = should_initialize_oauth2_passkey();

        // Always use first user credentials for admin authentication tests
        // NOTE: OAuth2 system automatically adds "google_" prefix, so mock server provides base ID
        let first_user_email = "first-user@example.com".to_string();
        let first_user_provider_id = "first-user-test-google-id".to_string();
        println!(
            "🆔 Using first user credentials: {first_user_email} (Provider ID: {first_user_provider_id})"
        );

        // Get the persistent mock server (automatically starts if needed)
        let _server = get_oidc_mock_server();

        // Configure mock server to use first user credentials for admin authentication
        configure_mock_for_test(
            first_user_email,
            first_user_provider_id,
            "First User".to_string(),
            "First".to_string(),
            "User".to_string(),
            base_url.clone(),
        );

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
        // Ensure the server task is fully terminated and port is released
        // Increased delay significantly for more reliable cleanup under high contention
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        // Force multiple yields to allow all cleanup to complete
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
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

// Tests moved to consolidated mock infrastructure test in mock_browser.rs
