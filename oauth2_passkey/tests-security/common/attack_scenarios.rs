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

    // ================================================================================
    // ADVANCED OAUTH2 ATTACK SCENARIO FUNCTIONS
    // ================================================================================

    /// Create a valid state parameter for advanced tests
    pub fn create_valid_state_parameter() -> String {
        let valid_state = json!({
            "csrf_id": "valid_csrf_id_12345",
            "nonce_id": "valid_nonce_id_12345",
            "pkce_id": "valid_pkce_id_12345",
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(valid_state.to_string().as_bytes())
    }

    /// Create state parameter with replayed nonce for nonce replay attack testing
    pub fn create_state_with_replayed_nonce() -> String {
        let replayed_nonce_state = json!({
            "csrf_id": "valid_csrf_id_12345",
            "nonce_id": "previously_used_nonce_12345", // This nonce was "used" in a previous auth
            "pkce_id": "valid_pkce_id_12345",
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(replayed_nonce_state.to_string().as_bytes())
    }

    /// Create state parameter for concurrent nonce attack testing
    pub fn create_state_with_concurrent_nonce_attack() -> String {
        let concurrent_nonce_state = json!({
            "csrf_id": "valid_csrf_id_concurrent",
            "nonce_id": "concurrent_nonce_attack_12345", // Same nonce used concurrently
            "pkce_id": "valid_pkce_id_concurrent",
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(concurrent_nonce_state.to_string().as_bytes())
    }

    /// Create PKCE state without verifier for downgrade attack testing
    pub fn create_pkce_state_without_verifier() -> String {
        let pkce_state = json!({
            "csrf_id": "valid_csrf_id_pkce",
            "nonce_id": "valid_nonce_id_pkce",
            "pkce_id": "pkce_without_verifier_attack", // PKCE flow without verifier
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(pkce_state.to_string().as_bytes())
    }

    /// Create PKCE state with wrong verifier for downgrade attack testing
    pub fn create_pkce_state_with_wrong_verifier() -> String {
        let pkce_state = json!({
            "csrf_id": "valid_csrf_id_pkce_wrong",
            "nonce_id": "valid_nonce_id_pkce_wrong",
            "pkce_id": "pkce_wrong_verifier_attack", // PKCE flow with wrong verifier
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(pkce_state.to_string().as_bytes())
    }

    /// Create state for PKCE bypass attempt
    pub fn create_pkce_bypass_state() -> String {
        let pkce_bypass_state = json!({
            "csrf_id": "valid_csrf_id_bypass",
            "nonce_id": "valid_nonce_id_bypass",
            "pkce_id": null, // Attempting to bypass PKCE by nullifying pkce_id
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(pkce_bypass_state.to_string().as_bytes())
    }

    /// Create state with malicious redirect URI for redirect validation bypass testing
    pub fn create_state_with_malicious_redirect(redirect_uri: &str) -> String {
        let malicious_redirect_state = json!({
            "csrf_id": "valid_csrf_id_redirect",
            "nonce_id": "valid_nonce_id_redirect",
            "pkce_id": "valid_pkce_id_redirect",
            "redirect_uri": redirect_uri, // Malicious redirect URI injection
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(malicious_redirect_state.to_string().as_bytes())
    }

    /// Create state with protocol confusion for protocol confusion attack testing
    pub fn create_state_with_protocol_confusion(confused_uri: &str) -> String {
        let protocol_confusion_state = json!({
            "csrf_id": "valid_csrf_id_protocol",
            "nonce_id": "valid_nonce_id_protocol",
            "pkce_id": "valid_pkce_id_protocol",
            "callback_uri": confused_uri, // Protocol confusion attack
            "misc_id": null,
            "mode_id": null
        });
        URL_SAFE_NO_PAD.encode(protocol_confusion_state.to_string().as_bytes())
    }
}

/// Passkey/WebAuthn attack scenarios
pub mod passkey_attacks {
    use super::*;

    /// Create an invalid WebAuthn registration response (malformed CBOR in attestation)
    pub fn create_invalid_registration_response(valid_challenge: &str) -> serde_json::Value {
        // Valid structure but with invalid attestation object that will fail CBOR parsing
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": valid_challenge, // Use real challenge to pass challenge validation
            "origin": "http://127.0.0.1:3000"
        });

        json!({
            "id": "invalid_credential_id",
            "raw_id": "aW52YWxpZF9jcmVkZW50aWFsX2lk", // base64 of "invalid_credential_id"
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "attestation_object": "invalid_cbor_data_not_base64!!!" // This will fail CBOR parsing
            },
            "type": "public-key"
        })
    }

    /// Create a WebAuthn response with invalid CBOR data
    pub fn create_invalid_cbor_response(valid_challenge: &str) -> serde_json::Value {
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": valid_challenge, // Use real challenge to pass challenge validation
            "origin": "http://127.0.0.1:3000"
        });

        json!({
            "id": "invalid_cbor_credential",
            "raw_id": "aW52YWxpZF9jYm9yX2NyZWRlbnRpYWw",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "attestation_object": "dGhpc19pc19ub3RfdmFsaWRfY2Jvcl9kYXRh" // Base64 but invalid CBOR
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
            "id": "tampered_challenge_cred",
            "raw_id": "dGFtcGVyZWRfY2hhbGxlbmdlX2NyZWQ",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik" // Valid base64 CBOR header
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
            "id": "wrong_origin_credential",
            "raw_id": "d3Jvbmdfb3JpZ2luX2NyZWRlbnRpYWw",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "attestation_object": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik" // Valid base64 CBOR header
            },
            "type": "public-key"
        })
    }

    /// Create an authentication response with expired challenge ID
    pub fn create_expired_auth_response() -> serde_json::Value {
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": "ZXhwaXJlZF9jaGFsbGVuZ2U", // base64 of "expired_challenge"
            "origin": "http://127.0.0.1:3000"
        });

        json!({
            "id": "expired_auth_credential",
            "raw_id": "ZXhwaXJlZF9hdXRoX2NyZWRlbnRpYWw",
            "response": {
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes()),
                "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAACQ", // Valid base64
                "signature": "MEUCIQDValid123Signature456Base64",
                "user_handle": "dXNlcl9oYW5kbGU"
            },
            "type": "public-key",
            "auth_id": "expired_challenge_id_12345" // This will be checked for expiration
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
