//! Test utilities module for shared test initialization and helpers
//!
//! This module provides centralized test setup functionality that can be used
//! across all test modules in the crate to ensure consistent environment
//! configuration and database initialization.
//!
//! ## Simplified Approach
//! Since SQLite functions now ensure tables exist at the point of use,
//! test utilities only need basic initialization without complex retry logic.
//!
//! ## Test Isolation
//! For tests that need complete isolation, use `init_isolated_test_environment`
//! which creates a unique in-memory database for each test.

use crate::storage::DataStore;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};

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

    // Since SQLite functions now ensure tables exist at point of use,
    // we just need basic store initialization
    let _ = UserStore::init().await;
    let _ = OAuth2Store::init().await;
    let _ = PasskeyStore::init().await;
}

// Use LazyLock for static initialization of isolated test database connections
use std::sync::LazyLock;
static CONNECTIONS: LazyLock<Mutex<HashMap<String, Arc<SqlitePool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Initialize an isolated test environment with a unique in-memory SQLite database
///
/// This function creates a completely isolated database for each test,
/// preventing state leakage between tests. Each test gets its own
/// in-memory SQLite database with unique tables.
///
/// ## Usage
/// ```rust
/// use crate::test_utils::init_isolated_test_environment;
///
/// #[tokio::test]
/// async fn my_isolated_test() {
///     // Create a unique test ID - can use test name or random UUID
///     let test_id = "test_my_function";
///     init_isolated_test_environment(test_id).await;
///     // Test code runs with its own isolated database
/// }
/// ```
pub async fn init_isolated_test_environment(test_id: &str) {
    // Environment setup (synchronous, runs once)
    static ENV_INIT: Once = Once::new();
    ENV_INIT.call_once(|| {
        // Try to load .env_test first, fallback to .env if it doesn't exist
        if dotenv::from_filename(".env_test").is_err() {
            dotenv::dotenv().ok();
        }
    });

    // Check if we already have a connection for this test
    {
        let connections = CONNECTIONS.lock().unwrap();
        if connections.contains_key(test_id) {
            // We already have a connection for this test, reuse it
            let pool = connections.get(test_id).unwrap().clone();

            // Create a new data store with the existing connection
            use crate::storage::data_store::SqliteDataStore;
            let store = Box::new(SqliteDataStore {
                pool: (*pool).clone(),
            }) as Box<dyn DataStore>;

            // Set the data store for this test
            crate::storage::set_data_store_for_test(store).await;
            return;
        }
    }

    // Create a unique in-memory SQLite database for this test
    // Using a unique database name for each test ensures isolation
    // SQLite doesn't support custom parameters in URLs, so we use the database name itself
    // to create isolation between tests
    let db_url = format!("sqlite:file:{}?mode=memory&cache=shared", test_id);
    let pool = Pool::<Sqlite>::connect(&db_url)
        .await
        .expect("Failed to create isolated test database");

    // Store the connection to prevent it from being dropped
    {
        let mut connections = CONNECTIONS.lock().unwrap();
        connections.insert(test_id.to_string(), Arc::new(pool.clone()));
    }

    // Create a new data store with the isolated connection
    use crate::storage::data_store::SqliteDataStore;
    let store = Box::new(SqliteDataStore { pool }) as Box<dyn DataStore>;

    // Set the data store for this test and initialize tables
    crate::storage::set_data_store_for_test(store).await;

    // Initialize all stores in the isolated environment
    use crate::oauth2::OAuth2Store;
    use crate::passkey::PasskeyStore;
    use crate::userdb::UserStore;

    let _ = UserStore::init().await;
    let _ = OAuth2Store::init().await;
    let _ = PasskeyStore::init().await;
}

// Function removed - functionality integrated into init_isolated_test_environment

// /// Enhanced test initialization that ensures database tables exist for the current connection
// ///
// /// **Note**: This function is now identical to `init_test_environment()` since we simplified
// /// the approach. SQLite functions handle table initialization directly.
// /// This function is kept for backward compatibility and clarity of intent.
// pub async fn init_test_environment_with_db() {
//     init_test_environment().await;
// }
