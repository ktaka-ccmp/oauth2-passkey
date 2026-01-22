//! WebAuthn test helpers for creating mock client data and credentials
//!
//! This module provides consolidated helper functions for WebAuthn testing
//! that can be used across both unit tests and integration tests.

/// Create properly formatted WebAuthn client data JSON
///
/// This helper creates a JSON string representing WebAuthn client data
/// with the specified type, challenge, and origin.
pub fn create_test_client_data_json(type_: &str, challenge: &str, origin: &str) -> String {
    serde_json::json!({
        "type": type_,
        "challenge": challenge,
        "origin": origin
    })
    .to_string()
}

/// Create test environment with proper origin configuration
///
/// This helper ensures that tests use the correct origin from the test environment
/// configuration, avoiding hardcoded values that can cause origin mismatch errors.
pub fn get_test_environment_origin() -> String {
    std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}

// Tests moved to consolidated fixtures test in fixtures.rs
