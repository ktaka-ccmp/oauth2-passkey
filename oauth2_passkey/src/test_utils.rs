//! Test utilities module for shared test initialization and helpers
//!
//! This module provides centralized test setup functionality that can be used
//! across all test modules in the crate to ensure consistent environment
//! configuration and database initialization.
//!
//! ## Simplified Approach
//! Since SQLite functions now ensure tables exist at the point of use,
//! test utilities only need basic initialization without complex retry logic.

use std::sync::Once;

/// Centralized test initialization for all tests across the entire crate
///
/// This function ensures that:
/// 1. Test environment variables are loaded from .env_test (with fallback to .env) - **ONCE**
/// 2. All database stores are initialized - **SIMPLE**
///
/// ## Simple Database Initialization
/// SQLite functions now ensure tables exist when called, so we only need basic store setup.
///
/// ## Usage
/// ```rust
/// use crate::test_utils::init_test_environment;
///
/// #[tokio::test]
/// async fn my_test() {
///     init_test_environment().await;
///     // ... test code that requires database access
/// }
/// ```
pub async fn init_test_environment() {
    // Environment setup (synchronous, runs once)
    static ENV_INIT: Once = Once::new();
    ENV_INIT.call_once(|| {
        // All tests now use .env_test - unit tests inject URLs directly to avoid HTTP requests
        println!("🧪 Loading test environment (.env_test)");
        if dotenvy::from_filename(".env_test").is_err() {
            dotenvy::dotenv().ok();
        }

        // Clean up any existing test database file
        if let Err(_) = std::fs::remove_file("/tmp/test_oauth2_passkey.db") {
            // File doesn't exist or can't be removed - that's okay
        }
    });

    // Simple database initialization
    ensure_database_initialized().await;
}

/// Ensures database is properly initialized and creates a first user if none exists
async fn ensure_database_initialized() {
    use crate::oauth2::OAuth2Store;
    use crate::passkey::PasskeyStore;
    use crate::userdb::UserStore;

    // Initialize stores - log errors but don't panic in tests
    if let Err(e) = UserStore::init().await {
        eprintln!("Warning: Failed to initialize UserStore: {e}");
    }
    if let Err(e) = OAuth2Store::init().await {
        eprintln!("Warning: Failed to initialize OAuth2Store: {e}");
    }
    if let Err(e) = PasskeyStore::init().await {
        eprintln!("Warning: Failed to initialize PasskeyStore: {e}");
    }

    // Create a first user if no users exist
    create_first_user_if_needed().await;
}

/// Creates a first test user if no users exist in the database
/// Uses proper race-condition handling to ensure only one first user is created
async fn create_first_user_if_needed() {
    use crate::userdb::{User, UserStore};
    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    // Use a mutex to prevent race conditions when creating the first user
    static FIRST_USER_CREATION_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    let _guard = FIRST_USER_CREATION_MUTEX.lock().await;

    // Double-check pattern: check again after acquiring the mutex
    match UserStore::get_all_users().await {
        Ok(users) if users.is_empty() => {
            // No users exist, create a first test user
            let first_user = User::new(
                "first-user".to_string(),
                "first-user@example.com".to_string(),
                "First User".to_string(),
            );

            if let Err(e) = UserStore::upsert_user(first_user).await {
                eprintln!("Warning: Failed to create first test user: {e}");
            } else {
                println!("✅ Created first test user with sequence_number = 1");
            }
        }
        Ok(users) => {
            // Users already exist, log the first user for debugging
            if let Some(first) = users.iter().find(|u| u.sequence_number == Some(1)) {
                println!("✅ First user already exists: {}", first.id);
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to check existing users: {e}");
        }
    }
}

/// Get the test origin from environment variables, with fallback to default test value
///
/// This function retrieves the ORIGIN environment variable which should be set in .env_test
/// for consistent test environment configuration. Falls back to localhost if not set.
pub fn get_test_origin() -> String {
    std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}
