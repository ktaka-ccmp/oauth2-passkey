//! In-process mock OAuth2 server for HTTP integration tests.
//!
//! Wraps the shared `mock-oidc` library router in a background thread with
//! a `LazyLock`, so a single mock instance is reused across all tests in a
//! run. The same library also backs the `mock-oidc` standalone binary used
//! by the Playwright E2E suite, keeping a single source of truth for
//! handler behaviour.

use mock_oidc::{AppState, TestUser, build_router};
use std::{
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

/// Fixed port for the mock OAuth2 server
pub const MOCK_OAUTH2_PORT: u16 = 9876;
pub const MOCK_OAUTH2_URL: &str = "http://127.0.0.1:9876";

/// Test server context that manages the lifecycle
pub struct TestServerContext {
    pub base_url: String,
    pub state: AppState,
    /// Origin URL stashed by `configure_mock_for_test` for tests that need
    /// to know which RP they were configured against. Mock-oidc-core itself
    /// does not consume this; callers that always pass `redirect_uri` on the
    /// authorize request never hit the fallback path.
    #[allow(dead_code)]
    pub origin_url: Arc<Mutex<String>>,
    #[allow(dead_code)]
    shutdown: Arc<AtomicBool>,
    _thread_handle: thread::JoinHandle<()>,
}

impl TestServerContext {
    fn new() -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let base_url = MOCK_OAUTH2_URL.to_string();

        let state = AppState::new(
            MOCK_OAUTH2_URL,
            "test-client-id.apps.googleusercontent.com",
            TestUser::default_first_user(),
        );
        let state_clone = state.clone();

        println!("🔧 Starting persistent mock OAuth2 server on port {MOCK_OAUTH2_PORT}...");

        // Periodic cleanup of expired authorization codes
        let cleanup_state = state.clone();
        let cleanup_shutdown = shutdown.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_millis(1000));
                if cleanup_shutdown.load(Ordering::Acquire) {
                    break;
                }
                cleanup_state.cleanup_expired_codes();
            }
        });

        let thread_handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("Failed to create optimized tokio runtime");

            rt.block_on(async move {
                let app = build_router(state_clone);
                let listener =
                    match tokio::net::TcpListener::bind(format!("127.0.0.1:{MOCK_OAUTH2_PORT}"))
                        .await
                    {
                        Ok(l) => l,
                        Err(e) => {
                            println!("❌ Failed to bind mock server: {e}");
                            return;
                        }
                    };
                let server = axum::serve(listener, app);
                tokio::select! {
                    result = server => {
                        if let Err(e) = result {
                            println!("❌ Mock server error: {e}");
                        }
                    }
                    _ = wait_for_shutdown(shutdown_clone) => {}
                }
            });
        });

        wait_for_server_ready();

        println!("✅ Persistent mock OAuth2 server is ready and will stay alive for all tests");

        TestServerContext {
            base_url,
            state,
            origin_url: Arc::new(Mutex::new(String::new())),
            shutdown,
            _thread_handle: thread_handle,
        }
    }
}

/// Global test server context (initialised once, lives for entire test run)
static TEST_SERVER: LazyLock<TestServerContext> = LazyLock::new(TestServerContext::new);

/// Get the global test server context
pub fn get_oidc_mock_server() -> &'static TestServerContext {
    &TEST_SERVER
}

fn wait_for_server_ready() {
    use std::time::Duration;
    for attempt in 0..50 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{MOCK_OAUTH2_PORT}")).is_ok() {
            println!("✅ Mock server is ready after {} attempts", attempt + 1);
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("❌ Mock server failed to start within timeout");
}

async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

/// Configure the mock server for a specific test.
///
/// Updates the active user identity. The `origin_url` parameter is retained
/// for signature compatibility with existing callers; it is recorded on the
/// context but not consumed by mock-oidc-core (which uses the issuer URL as
/// the fallback when an authorize request omits `redirect_uri`, and all
/// callers pass it explicitly).
pub fn configure_mock_for_test(
    user_email: String,
    user_id: String,
    user_name: String,
    user_given_name: String,
    user_family_name: String,
    origin_url: String,
) {
    let server = get_oidc_mock_server();
    {
        let mut user = server.state.user.lock().unwrap();
        user.email = user_email;
        user.sub = user_id;
        user.name = user_name;
        user.given_name = user_given_name;
        user.family_name = user_family_name;
    }
    *server.origin_url.lock().unwrap() = origin_url;
    println!("🔧 Mock server configured for test");
}
