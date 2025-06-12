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
        // Try to load .env_test first, fallback to .env if it doesn't exist
        if dotenv::from_filename(".env_test").is_err() {
            dotenv::dotenv().ok();
        }
    });

    // Simple database initialization
    ensure_database_initialized().await;
}

/// Ensures database is properly initialized - simplified since SQLite functions handle table creation
async fn ensure_database_initialized() {
    use crate::oauth2::OAuth2Store;
    use crate::passkey::PasskeyStore;
    use crate::userdb::UserStore;

    // Initialize stores - log errors but don't panic in tests
    if let Err(e) = UserStore::init().await {
        eprintln!("Warning: Failed to initialize UserStore: {}", e);
    }
    if let Err(e) = OAuth2Store::init().await {
        eprintln!("Warning: Failed to initialize OAuth2Store: {}", e);
    }
    if let Err(e) = PasskeyStore::init().await {
        eprintln!("Warning: Failed to initialize PasskeyStore: {}", e);
    }
}

// /// Enhanced test initialization that ensures database tables exist for the current connection
// ///
// /// **Note**: This function is now identical to `init_test_environment()` since we simplified
// /// the approach. SQLite functions handle table initialization directly.
// /// This function is kept for backward compatibility and clarity of intent.
// pub async fn init_test_environment_with_db() {
//     init_test_environment().await;
// }
