//! Test utilities module for shared test initialization and helpers
//!
//! This module provides centralized test setup functionality that can be used
//! across all test modules in the crate to ensure consistent environment
//! configuration and database initialization.
//!
//! It leverages the in-memory stores from oauth2_passkey for efficient and isolated testing.

// No need for Once or LazyLock in the root module as they're used in the env submodule
use crate::AuthUser;
use chrono::Utc;
use oauth2_passkey::{PasskeyCredential, SessionUser};
use serde_json;

/// Centralized test environment setup
///
/// This module handles loading environment variables from .env_test and setting up
/// required test environment variables in a thread-safe way using LazyLock.
pub mod env {
    use std::sync::LazyLock;

    /// Initialize test environment variables
    /// This is called automatically when accessing any of the static variables below
    static ENV_INIT: LazyLock<()> = LazyLock::new(|| {
        // Load environment variables from .env_test (required for testing)
        // We explicitly don't fall back to .env to ensure test isolation
        if let Err(e) = dotenv::from_filename(".env_test") {
            eprintln!("ERROR: .env_test file not found. This file is required for testing.");
            eprintln!("Please create a .env_test file with test-specific environment variables.");
            eprintln!("Error: {}", e);
            panic!("Missing .env_test file required for testing");
        }
    });

    /// Get the origin for tests
    pub fn origin() -> String {
        // This will trigger ENV_INIT if it hasn't been called yet
        let _ = *ENV_INIT;
        std::env::var("ORIGIN").unwrap()
    }
}


/// Mock implementations for external dependencies
pub mod mocks {
    use super::*;

    /// Create a mock AuthUser for testing
    pub fn mock_auth_user(id: &str, account: &str) -> AuthUser {
        let now = Utc::now();
        AuthUser {
            id: id.to_string(),
            account: account.to_string(),
            label: format!("Test User {}", id),
            is_admin: false,
            sequence_number: 1,
            created_at: now,
            updated_at: now,
            csrf_token: "test-csrf-token".to_string(),
            csrf_via_header_verified: true,
        }
    }

    /// Create a mock admin AuthUser for testing
    ///
    /// Note: Currently not used in tests but kept for future test expansion
    #[allow(dead_code)]
    pub fn mock_admin_user(id: &str, account: &str) -> AuthUser {
        let mut user = mock_auth_user(id, account);
        user.is_admin = true;
        user
    }

    /// Create a mock SessionUser for testing
    ///
    /// Note: Currently not used in tests but kept for future test expansion
    #[allow(dead_code)]
    pub fn mock_session_user(id: &str, account: &str) -> SessionUser {
        SessionUser {
            id: id.to_string(),
            account: account.to_string(),
            label: format!("Test User {}", id),
            is_admin: false,
            sequence_number: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Core function mocks for testing without external dependencies
pub mod core_mocks {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    static MOCK_LIST_CREDENTIALS_CALLED: AtomicBool = AtomicBool::new(false);

    /// Helper function to create a mock PasskeyCredential for testing
    fn create_mock_credential(
        user_id: &str,
        credential_id: &str,
        public_key: &str,
    ) -> PasskeyCredential {
        // Since we can't directly access PublicKeyCredentialUserEntity, we'll use serde_json
        // to create a valid PasskeyCredential with the required user field
        let now = Utc::now();
        let json = format!(
            r#"{{
            "credential_id": "{}",
            "user_id": "{}",
            "public_key": "{}",
            "aaguid": "00000000-0000-0000-0000-000000000000",
            "counter": 0,
            "user": {{
                "user_handle": "user-handle-{}",
                "name": "user_{}",
                "displayName": "Test User {}"
            }},
            "created_at": "{}",
            "updated_at": "{}",
            "last_used_at": "{}"
        }}"#,
            credential_id,
            user_id,
            public_key,
            user_id,
            user_id,
            user_id,
            now.to_rfc3339(),
            now.to_rfc3339(),
            now.to_rfc3339()
        );

        serde_json::from_str(&json).expect("Failed to create mock PasskeyCredential")
    }

    /// Mock implementation of list_credentials_core
    pub async fn mock_list_credentials_core(
        user_id: &str,
        _include_transports: bool,
    ) -> Result<Vec<PasskeyCredential>, oauth2_passkey::CoordinationError> {
        MOCK_LIST_CREDENTIALS_CALLED.store(true, Ordering::SeqCst);

        // Create a mock credential
        let credential = create_mock_credential(user_id, "test-credential-id", "test-public-key");

        Ok(vec![credential])
    }

    /// Mock implementation for update_passkey_credential_core
    pub async fn mock_update_passkey_credential_core(
        user_id: &str,
        credential_id: &str,
        _name: &str,
        _display_name: &str,
    ) -> Result<serde_json::Value, oauth2_passkey::CoordinationError> {
        // Create an updated mock credential
        let credential = create_mock_credential(user_id, credential_id, "test-public-key");

        // Return a JSON object with the credential
        Ok(serde_json::json!({
            "credential": credential,
            "userVerification": "required"
        }))
    }

    /// Check if mock_list_credentials_core was called
    pub fn was_list_credentials_called() -> bool {
        MOCK_LIST_CREDENTIALS_CALLED.load(Ordering::SeqCst)
    }

    /// Reset mock call tracking
    pub fn reset_mock_calls() {
        MOCK_LIST_CREDENTIALS_CALLED.store(false, Ordering::SeqCst);
    }

    // The mock_update_passkey_credential_core function is already defined above
}
