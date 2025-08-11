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

    // Create a first user if no users exist (with both OAuth2 and Passkey credentials)
    create_first_user_if_needed().await;
}

/// Creates a first test user with passkey credential if no users exist in the database
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
            // No users exist, create a first test user with passkey credential
            let mut first_user = User::new(
                "first-user".to_string(),
                "first-user@example.com".to_string(),
                "First User".to_string(),
            );
            first_user.is_admin = true; // First user should be admin

            match UserStore::upsert_user(first_user).await {
                Ok(created_user) => {
                    println!("✅ Created first test user with sequence_number = 1");

                    // Create OAuth2 account for authentication testing
                    create_first_user_oauth2_account(&created_user.id).await;

                    // Create Passkey credential for authentication testing
                    create_first_user_passkey_credential(&created_user.id).await;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to create first test user: {e}");
                }
            }
        }
        Ok(users) => {
            // Users already exist, log the first user for debugging
            if let Some(first) = users.iter().find(|u| u.sequence_number == Some(1)) {
                println!("✅ First user already exists: {}", first.id);

                // Ensure first user has admin privileges (update if needed)
                if !first.is_admin {
                    println!("🔧 Updating first user to have admin privileges...");
                    let mut updated_user = first.clone();
                    updated_user.is_admin = true;
                    if let Err(e) = UserStore::upsert_user(updated_user).await {
                        eprintln!("Warning: Failed to update first user admin status: {e}");
                    } else {
                        println!("✅ First user now has admin privileges");
                    }
                }

                // Ensure first user has OAuth2 account for authentic testing
                ensure_first_user_has_oauth2_account(&first.id).await;

                // Ensure first user has Passkey credential for authentic testing
                ensure_first_user_has_passkey_credential(&first.id).await;
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to check existing users: {e}");
        }
    }
}

/// Creates a test OAuth2 account for the first user to enable authentic authentication testing
async fn create_first_user_oauth2_account(user_id: &str) {
    use crate::oauth2::{OAuth2Account, OAuth2Store};
    use chrono::Utc;

    let now = Utc::now();
    let provider = "google";
    let provider_user_id = format!("{provider}_first-user-test-google-id");
    let test_oauth2_account = OAuth2Account {
        id: "first-user-oauth2-account".to_string(),
        user_id: user_id.to_string(),
        provider: provider.to_string(),
        provider_user_id: provider_user_id.to_string(),
        name: "First User".to_string(),
        email: "first-user@example.com".to_string(),
        picture: Some("https://example.com/avatar/first-user.jpg".to_string()),
        metadata: serde_json::json!({"test_account": true, "created_by": "test_utils"}),
        created_at: now,
        updated_at: now,
    };

    match OAuth2Store::upsert_oauth2_account(test_oauth2_account).await {
        Ok(_account) => {
            println!("✅ Created first user OAuth2 account for testing");
        }
        Err(e) => {
            eprintln!("Warning: Failed to create first user OAuth2 account: {e}");
        }
    }
}

/// Ensures the first user has an OAuth2 account (for cases where user exists but OAuth2 account doesn't)  
async fn ensure_first_user_has_oauth2_account(user_id: &str) {
    use crate::oauth2::OAuth2Store;

    // Check if first user already has OAuth2 accounts
    match OAuth2Store::get_oauth2_accounts(user_id).await {
        Ok(accounts) if accounts.is_empty() => {
            // No OAuth2 accounts exist for first user, create one
            println!("ℹ️ First user exists but has no OAuth2 account, creating one...");
            create_first_user_oauth2_account(user_id).await;
        }
        Ok(accounts) => {
            println!("✅ First user has {} OAuth2 account(s)", accounts.len());
        }
        Err(e) => {
            eprintln!("Warning: Failed to check first user OAuth2 accounts: {e}");
        }
    }
}

/// Creates a test Passkey credential for the first user to enable authentic authentication testing
///
/// This creates a WebAuthn credential with a fixed public key that corresponds to the private key
/// used in mock authentication. This ensures signature verification works correctly in integration tests.
///
/// **Credential Flow**: Store public key → Mock auth signs with private key → Verification succeeds
async fn create_first_user_passkey_credential(user_id: &str) {
    // Use the internal passkey module imports since this is test utility code
    use crate::passkey::{PasskeyCredential, PasskeyStore};
    use chrono::Utc;

    let now = Utc::now();

    // Get the fixed public key that corresponds to FIRST_USER_PRIVATE_KEY in integration tests
    // This mathematical relationship enables proper WebAuthn signature verification
    let public_key = generate_first_user_public_key();

    // Create a test passkey credential with consistent key for testing
    // Note: We construct the user entity directly here since it's internal test code
    let test_passkey_credential = PasskeyCredential {
        credential_id: "first-user-test-passkey-credential".to_string(),
        user_id: user_id.to_string(),
        public_key,
        aaguid: "00000000-0000-0000-0000-000000000000".to_string(), // Test AAGUID
        counter: 0,
        user: serde_json::from_value(serde_json::json!({
            "user_handle": "first-user-handle",
            "name": "first-user@example.com",
            "displayName": "First User"
        }))
        .expect("Valid user entity JSON"),
        created_at: now,
        updated_at: now,
        last_used_at: now,
    };

    match PasskeyStore::store_credential(
        "first-user-test-passkey-credential".to_string(),
        test_passkey_credential,
    )
    .await
    {
        Ok(_) => {
            println!("✅ Created first user Passkey credential for testing");
        }
        Err(e) => {
            eprintln!("Warning: Failed to create first user Passkey credential: {e}");
        }
    }
}

/// Get the fixed ECDSA P-256 public key for the first user credentials
///
/// This public key is mathematically derived from the private key stored in `fixtures.rs`.
/// Both are part of the same cryptographic key pair used for WebAuthn signature verification.
///
/// **Key Derivation**: This public key = FIRST_USER_PRIVATE_KEY × Generator Point (P-256 curve)
/// **Format**: Base64url-encoded uncompressed point coordinates (64 bytes: 32-byte X + 32-byte Y)
/// **Usage**: Stored in database credential → verifies signatures created by corresponding private key
///
/// 🔗 **Related**: See `fixtures.rs::first_user_key_pair()` for the matching private key
fn generate_first_user_public_key() -> String {
    // Fixed ECDSA P-256 public key in WebAuthn format (base64url-encoded coordinates)
    // Corresponds to private key in FIRST_USER_PRIVATE_KEY (fixtures.rs)
    // Coordinate breakdown: BB...Ps = X(32 bytes) + Y(32 bytes) in base64url
    "BBtOg4PEjnY2yQkrPjL832Obw0qJxiR-vIoUjjMmkKbyNjO4tT3blJAlPI5Y39nDiNkn7UnkCFZIS39cYp9nLPs"
        .to_string()
}

/// Ensures the first user has a Passkey credential (for cases where user exists but credential doesn't)
async fn ensure_first_user_has_passkey_credential(user_id: &str) {
    use crate::passkey::{CredentialSearchField, PasskeyStore};

    // Check if first user already has Passkey credentials
    match PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_string())).await
    {
        Ok(credentials) if credentials.is_empty() => {
            // No Passkey credentials exist for first user, create one
            println!("ℹ️ First user exists but has no Passkey credential, creating one...");
            create_first_user_passkey_credential(user_id).await;
        }
        Ok(credentials) => {
            println!(
                "✅ First user has {} Passkey credential(s)",
                credentials.len()
            );
        }
        Err(e) => {
            eprintln!("Warning: Failed to check first user Passkey credentials: {e}");
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
