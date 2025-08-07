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

        // Clean up any existing test database file based on GENERIC_DATA_STORE_URL
        if let Some(db_path) = extract_sqlite_file_path() {
            if std::fs::remove_file(&db_path).is_err() {
                // File doesn't exist or can't be removed - that's okay
            }
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

/// Extract SQLite database file path from a database URL string
///
/// Parses a database URL to extract the file path for SQLite databases.
/// Supports formats like:
/// - `sqlite:/path/to/file.db`
/// - `sqlite:./relative/path.db`
/// - `sqlite:/tmp/test.db`
///
/// Returns None for non-SQLite URLs or if the URL cannot be parsed.
fn extract_sqlite_file_path_from_url(url: &str) -> Option<String> {
    if url.starts_with("sqlite:") {
        let path = url.strip_prefix("sqlite:")?;

        // Handle different SQLite URL formats
        if path.starts_with("file:") {
            // Handle sqlite:file:path?options format
            let file_path = path.strip_prefix("file:")?;
            // Extract path before any query parameters
            let path_only = file_path.split('?').next()?;
            // Skip special in-memory databases
            if path_only.contains(":memory:") {
                return None;
            }
            Some(path_only.to_string())
        } else {
            // Handle sqlite:path format
            let path = path.strip_prefix("//").unwrap_or(path);
            // Skip special in-memory databases
            if path.contains(":memory:") {
                return None;
            }
            Some(path.to_string())
        }
    } else {
        None
    }
}

/// Extract SQLite database file path from GENERIC_DATA_STORE_URL environment variable
///
/// Parses the GENERIC_DATA_STORE_URL to extract the file path for SQLite databases.
/// Supports formats like:
/// - `sqlite:/path/to/file.db`
/// - `sqlite:./relative/path.db`
/// - `sqlite:/tmp/test.db`
///
/// Returns None for non-SQLite URLs or if the URL cannot be parsed.
fn extract_sqlite_file_path() -> Option<String> {
    if let Ok(url) = std::env::var("GENERIC_DATA_STORE_URL") {
        extract_sqlite_file_path_from_url(&url)
    } else {
        None
    }
}

/// Get the test origin from environment variables, with fallback to default test value
///
/// This function retrieves the ORIGIN environment variable which should be set in .env_test
/// for consistent test environment configuration. Falls back to localhost if not set.
pub fn get_test_origin() -> String {
    std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sqlite_file_path_from_url() {
        // Test sqlite: with absolute path
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:/tmp/test.db"),
            Some("/tmp/test.db".to_string())
        );

        // Test sqlite: with relative path
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:./test.db"),
            Some("./test.db".to_string())
        );

        // Test sqlite:file: format
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:file:/tmp/test.db"),
            Some("/tmp/test.db".to_string())
        );

        // Test sqlite:file: with query parameters
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:file:/tmp/test.db?mode=rwc&cache=shared"),
            Some("/tmp/test.db".to_string())
        );

        // Test in-memory database with query parameter (should still extract path)
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:file:test?mode=memory&cache=shared"),
            Some("test".to_string())
        );

        // Test :memory: database (should return None)
        assert_eq!(extract_sqlite_file_path_from_url("sqlite::memory:"), None);

        // Test file:memory: database (should return None)
        assert_eq!(
            extract_sqlite_file_path_from_url(
                "sqlite:file:test_integrated?mode=memory&cache=shared"
            ),
            Some("test_integrated".to_string())
        );

        // Test actual :memory: in path (should return None)
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:file::memory:?cache=shared"),
            None
        );

        // Test non-SQLite URL (should return None)
        assert_eq!(
            extract_sqlite_file_path_from_url("postgresql://localhost/test"),
            None
        );

        // Test empty string (should return None)
        assert_eq!(extract_sqlite_file_path_from_url(""), None);

        // Test sqlite with double slash format
        assert_eq!(
            extract_sqlite_file_path_from_url("sqlite:///tmp/test.db"),
            Some("/tmp/test.db".to_string())
        );
    }
}
