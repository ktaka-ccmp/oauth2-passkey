/// Attack scenario generators for security testing
///
/// This module provides utilities for creating malicious or invalid inputs
/// to test security boundaries across OAuth2, Passkey, and Session flows.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::collections::HashMap;

/// OAuth2 state parameter tampering utilities
pub mod oauth2_attacks {
    use super::*;

    /// Create an invalid/empty state parameter
    pub fn create_empty_state() -> String {
        String::new()
    }

    /// Create a malformed base64 state parameter
    pub fn create_malformed_state() -> String {
        "invalid-base64-!@#$".to_string()
    }

    /// Create a state parameter with invalid JSON
    pub fn create_invalid_json_state() -> String {
        // Valid base64 but invalid JSON
        URL_SAFE_NO_PAD.encode(b"{invalid:json:structure}")
    }

    /// Create a state parameter with missing required fields
    pub fn create_incomplete_state() -> String {
        let incomplete_state = json!({
            "csrf_id": "valid_csrf_id",
            // Missing required fields: nonce_id, pkce_id
        });
        URL_SAFE_NO_PAD.encode(incomplete_state.to_string().as_bytes())
    }

    /// Create a state parameter with expired/invalid IDs
    pub fn create_expired_state() -> String {
        let expired_state = json!({
            "csrf_id": "expired_csrf_id_12345",
            "nonce_id": "expired_nonce_id_12345",
            "pkce_id": "expired_pkce_id_12345",
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(expired_state.to_string().as_bytes())
    }

    /// Create an authorization code that doesn't exist
    pub fn create_invalid_auth_code() -> String {
        "invalid_authorization_code_12345".to_string()
    }

    /// Create headers with wrong origin for CSRF attack
    pub fn create_malicious_origin_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Origin", "https://malicious-site.com"),
            ("Referer", "https://malicious-site.com/evil"),
        ]
    }

    /// Create headers with no origin (missing security headers)
    pub fn create_missing_origin_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            // Missing Origin and Referer headers entirely
            ("User-Agent", "AttackerBot/1.0"),
        ]
    }
}

/// Passkey/WebAuthn attack scenarios
pub mod passkey_attacks {
    use super::*;

    /// Create an invalid WebAuthn registration response
    pub fn create_invalid_registration_response() -> serde_json::Value {
        json!({
            "invalid_structure": true,
            "missing_required_fields": "yes"
        })
    }

    /// Create a WebAuthn response with invalid CBOR data
    pub fn create_invalid_cbor_response() -> serde_json::Value {
        json!({
            "id": "valid_credential_id",
            "rawId": "dmFsaWRfY3JlZGVudGlhbF9pZA",
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaW52YWxpZCJ9",
                "attestationObject": "invalid_cbor_data_not_base64"
            },
            "type": "public-key"
        })
    }

    /// Create a WebAuthn response with tampered challenge
    pub fn create_tampered_challenge_response(valid_challenge: &str) -> serde_json::Value {
        let tampered_challenge = format!("{valid_challenge}_tampered");
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": tampered_challenge,
            "origin": "http://127.0.0.1:3000"
        });

        json!({
            "id": "valid_credential_id",
            "rawId": "dmFsaWRfY3JlZGVudGlhbF9pZA",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "attestationObject": "valid_attestation_object_base64"
            },
            "type": "public-key"
        })
    }

    /// Create a WebAuthn response with wrong origin
    pub fn create_wrong_origin_response(valid_challenge: &str) -> serde_json::Value {
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": valid_challenge,
            "origin": "https://malicious-site.com"
        });

        json!({
            "id": "valid_credential_id",
            "rawId": "dmFsaWRfY3JlZGVudGlhbF9pZA",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "attestationObject": "valid_attestation_object_base64"
            },
            "type": "public-key"
        })
    }

    /// Create an authentication response with expired challenge ID
    pub fn create_expired_auth_response() -> serde_json::Value {
        json!({
            "id": "valid_credential_id",
            "rawId": "dmFsaWRfY3JlZGVudGlhbF9pZA",
            "response": {
                "clientDataJSON": "valid_client_data",
                "authenticatorData": "valid_authenticator_data",
                "signature": "valid_signature",
                "userHandle": "valid_user_handle"
            },
            "type": "public-key"
        })
    }

    /// Generate a challenge ID that doesn't exist in storage
    pub fn create_nonexistent_challenge_id() -> String {
        "nonexistent_challenge_id_12345".to_string()
    }
}

/// Session boundary attack scenarios
pub mod session_attacks {
    use super::*;

    /// Create headers that attempt to bypass CSRF protection
    pub fn create_csrf_bypass_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            // Missing X-CSRF-Token header for state-changing request
            ("Content-Type", "application/json"),
            ("User-Agent", "AttackerBot/1.0"),
        ]
    }

    /// Create headers with invalid CSRF token
    pub fn create_invalid_csrf_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("X-CSRF-Token", "invalid_csrf_token_12345"),
            ("Content-Type", "application/json"),
        ]
    }

    /// Create a session cookie with expired/invalid session ID
    pub fn create_expired_session_cookie() -> String {
        "expired_session_id_12345".to_string()
    }

    /// Create a malicious session cookie attempting injection
    pub fn create_malicious_session_cookie() -> String {
        "malicious'; DROP TABLE sessions; --".to_string()
    }

    /// Create form data for cross-user operation attempt
    pub fn create_cross_user_operation_data(target_user_id: &str) -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("target_user_id".to_string(), target_user_id.to_string());
        data.insert("operation".to_string(), "delete_user".to_string());
        data
    }
}

/// Admin privilege escalation attack scenarios
pub mod admin_attacks {
    use super::*;

    /// Create data attempting to escalate to admin privileges
    pub fn create_privilege_escalation_data() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("is_admin".to_string(), "true".to_string());
        data.insert("admin_action".to_string(), "grant_admin".to_string());
        data
    }

    /// Create unauthorized admin operation request
    pub fn create_unauthorized_admin_request() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("operation".to_string(), "list_all_users".to_string());
        data.insert("admin_context".to_string(), "fake_admin_token".to_string());
        data
    }

    /// Create malicious admin context token
    pub fn create_malicious_admin_context() -> String {
        "fake_admin_context_token_12345".to_string()
    }
}

/// Cross-flow attack scenarios (OAuth2 + Passkey interactions)
pub mod cross_flow_attacks {
    use super::*;

    /// Create account linking request without proper authentication
    pub fn create_unauthenticated_linking_request() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("mode".to_string(), "add_to_user".to_string());
        data.insert("context".to_string(), "fake_context_token".to_string());
        data
    }

    /// Create credential addition request with invalid session context
    pub fn create_invalid_context_credential_request() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("mode".to_string(), "add_to_user".to_string());
        data.insert("username".to_string(), "test@example.com".to_string());
        data.insert("displayname".to_string(), "Test User".to_string());
        data
    }

    /// Create cross-user credential addition attempt
    pub fn create_cross_user_credential_request(victim_user_id: &str) -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("target_user_id".to_string(), victim_user_id.to_string());
        data.insert("mode".to_string(), "add_to_user".to_string());
        data.insert("username".to_string(), "attacker@evil.com".to_string());
        data
    }
}
