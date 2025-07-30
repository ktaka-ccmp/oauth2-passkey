//! WebAuthn test helpers for creating mock client data and credentials
//!
//! This module provides consolidated helper functions for WebAuthn testing
//! that can be used across both unit tests and integration tests.

use serde_json::Value;

use crate::common::MockWebAuthnCredentials;

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

/// Create mock WebAuthn credential for registration with specified format
///
/// This helper creates a mock credential response suitable for testing
/// WebAuthn registration flows with different attestation formats.
///
/// Returns a tuple of (credential_json, optional_key_pair_bytes)
pub fn create_mock_registration_credential(
    email: &str,
    display_name: &str,
    challenge: &str,
    user_handle: &str,
    format: &str,
    origin: Option<&str>,
) -> (Value, Option<Vec<u8>>) {
    let origin_str = match origin {
        Some(o) => o.to_string(),
        None => std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string()),
    };

    match format {
        "none" => {
            // For none attestation, use the original method for backward compatibility
            let cred = MockWebAuthnCredentials::registration_response_with_challenge_user_handle_and_origin(
                email,
                display_name,
                challenge,
                user_handle,
                &origin_str,
            );
            (cred, None)
        }
        "packed" => {
            // For packed attestation, get the key pair for later authentication
            MockWebAuthnCredentials::registration_response_with_format_and_key_pair(
                email,
                display_name,
                challenge,
                user_handle,
                format,
            )
        }
        _ => {
            // For other formats (tpm), use the format-specific method
            let cred = MockWebAuthnCredentials::registration_response_with_format(
                email,
                display_name,
                challenge,
                user_handle,
                format,
            );
            (cred, None)
        }
    }
}

/// Create test environment with proper origin configuration
///
/// This helper ensures that tests use the correct origin from the test environment
/// configuration, avoiding hardcoded values that can cause origin mismatch errors.
pub fn get_test_environment_origin() -> String {
    std::env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_helpers_use_correct_environment() {
        // Test that helpers use environment-aware values
        let origin = get_test_environment_origin();
        assert!(
            origin.starts_with("http://127.0.0.1:3000") || origin.starts_with("http://localhost")
        );

        // Test client data creation
        let client_data_json =
            create_test_client_data_json("webauthn.get", "test-challenge", &origin);
        assert!(client_data_json.contains(&origin));
    }
}
