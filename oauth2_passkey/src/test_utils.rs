//! Test utilities module for shared test initialization and helpers
//!
//! This module provides centralized test setup functionality that can be used
//! across all test modules in the crate to ensure consistent environment
//! configuration and database initialization.

use std::sync::Once;
use tokio::sync::OnceCell;

/// Centralized test initialization - runs once before all tests across the entire crate
///
/// This function ensures that:
/// 1. Test environment variables are loaded from .env_test (with fallback to .env)
/// 2. All database schemas are initialized exactly once
///
/// # Usage
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

    // Database initialization (async, runs once)
    static DB_INIT: OnceCell<()> = OnceCell::const_new();
    DB_INIT
        .get_or_init(|| async {
            use crate::oauth2::OAuth2Store;
            use crate::passkey::PasskeyStore;
            use crate::userdb::UserStore;

            // Initialize all database tables
            UserStore::init()
                .await
                .expect("Failed to initialize UserStore");
            OAuth2Store::init()
                .await
                .expect("Failed to initialize OAuth2Store");
            PasskeyStore::init()
                .await
                .expect("Failed to initialize PasskeyStore");
        })
        .await;
}
