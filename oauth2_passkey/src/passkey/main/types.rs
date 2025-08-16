use ciborium::value::Value as CborValue;
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::passkey::{
    config::{ORIGIN, PASSKEY_RP_ID, PASSKEY_USER_VERIFICATION},
    errors::PasskeyError,
    types::PublicKeyCredentialUserEntity,
};
use crate::utils::base64url_decode;

/// Options for initiating a WebAuthn authentication request.
///
/// This structure contains the parameters needed to create a credential request
/// to authenticate a user with a previously registered passkey. It follows the
/// WebAuthn specification format for navigator.credentials.get() options.
///
/// The browser uses these options to prompt the user for their passkey and
/// generate a signed authentication assertion.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    pub(super) challenge: String,
    pub(super) timeout: u32,
    pub(super) rp_id: String,
    pub(super) allow_credentials: Vec<AllowCredential>,
    pub(super) user_verification: String,
    pub(super) auth_id: String,
}

#[derive(Serialize, Debug)]
pub(super) struct AllowCredential {
    pub(super) type_: String,
    pub(super) id: String,
}

#[derive(Serialize, Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticatorSelection {
    pub(super) authenticator_attachment: String,
    pub(super) resident_key: String,
    pub(super) user_verification: String,
    pub(super) require_resident_key: bool,
}

/// Response from the authenticator during a WebAuthn authentication flow.
///
/// This structure contains the data returned from the browser after a successful
/// credential authentication request. It includes the credential ID and the authentication
/// assertion containing the signature that proves possession of the private key.
///
/// The server uses this data to verify the user's identity and complete the authentication.
#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct AuthenticatorResponse {
    pub(super) id: String,
    raw_id: String,
    pub(super) response: AuthenticatorAssertionResponse,
    authenticator_attachment: Option<String>,
    pub(super) auth_id: String,
}

impl AuthenticatorResponse {
    #[cfg(test)]
    pub(super) fn new_for_test(
        id: String,
        response: AuthenticatorAssertionResponse,
        auth_id: String,
    ) -> Self {
        Self {
            id,
            raw_id: "test_raw_id".to_string(),
            response,
            authenticator_attachment: None,
            auth_id,
        }
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct AuthenticatorAssertionResponse {
    pub(super) client_data_json: String,
    pub(super) authenticator_data: String,
    pub(super) signature: String,
    pub(super) user_handle: Option<String>,
}

#[derive(Serialize, Debug)]
pub(super) struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) alg: i32,
}

/// Options for initiating a WebAuthn registration request.
///
/// This structure contains the parameters needed to create a new passkey credential
/// for a user. It follows the WebAuthn specification format for navigator.credentials.create()
/// options.
///
/// The browser uses these options to prompt the user to create a new passkey using
/// their authenticator (platform or cross-platform).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOptions {
    pub(super) challenge: String,
    pub(super) rp_id: String,
    pub(super) rp: RelyingParty,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) pub_key_cred_params: Vec<PubKeyCredParam>,
    pub(super) authenticator_selection: AuthenticatorSelection,
    pub(super) timeout: u32,
    pub(super) attestation: String,
}

#[derive(Serialize, Debug)]
pub(super) struct RelyingParty {
    pub(super) name: String,
    pub(super) id: String,
}

#[allow(unused)]
/// Credential data received during WebAuthn registration.
///
/// This structure represents the data returned from the browser after a successful
/// credential creation request. It includes the credential ID and the attestation
/// information that allows the server to verify the authenticator's properties
/// and the newly generated credential.
///
/// This is used in the registration flow to create and store a new passkey credential.
#[derive(Deserialize, Debug)]
pub struct RegisterCredential {
    pub(super) id: String,
    pub(super) raw_id: String,
    pub(super) response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) user_handle: Option<String>,
}

impl RegisterCredential {
    /// Attempts to retrieve the user fields (name, display_name) from stored registration data
    /// If the stored options are no longer available, falls back to default values
    pub(crate) async fn get_registration_user_fields(&self) -> (String, String) {
        // Try to get the stored options if user_handle exists
        if let Some(handle) = &self.user_handle {
            let challenge_type = crate::passkey::types::ChallengeType::registration();
            let challenge_id = match crate::passkey::types::ChallengeId::new(handle.clone()) {
                Ok(id) => id,
                Err(_) => {
                    tracing::warn!("Invalid challenge ID format, using defaults");
                    return ("Passkey User".to_string(), "Passkey User".to_string());
                }
            };
            match super::challenge::get_and_validate_options(&challenge_type, &challenge_id).await {
                Ok(stored_options) => (stored_options.user.name, stored_options.user.display_name),
                Err(e) => {
                    tracing::warn!("Failed to get stored user: {}", e);
                    ("Passkey User".to_string(), "Passkey User".to_string())
                }
            }
        } else {
            // Fall back to default if user_handle is None
            ("Passkey User".to_string(), "Passkey User".to_string())
        }
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct AuthenticatorAttestationResponse {
    pub(super) client_data_json: String,
    pub(super) attestation_object: String,
}

#[derive(Debug)]
pub(super) struct AttestationObject {
    pub(super) fmt: String,
    pub(super) auth_data: Vec<u8>,
    pub(super) att_stmt: Vec<(CborValue, CborValue)>,
}

#[derive(Debug)]
pub(super) struct ParsedClientData {
    pub(super) challenge: String,
    pub(super) origin: String,
    pub(super) type_: String,
    pub(super) raw_data: Vec<u8>,
}

impl ParsedClientData {
    pub(super) fn from_base64(client_data_json: &str) -> Result<Self, PasskeyError> {
        let raw_data = base64url_decode(client_data_json)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {e}")))?;

        let data_str = String::from_utf8(raw_data.clone())
            .map_err(|e| PasskeyError::Format(format!("Invalid UTF-8: {e}")))?;

        let data: serde_json::Value = serde_json::from_str(&data_str)
            .map_err(|e| PasskeyError::Format(format!("Invalid JSON: {e}")))?;

        let challenge_str = data["challenge"]
            .as_str()
            .ok_or_else(|| PasskeyError::ClientData("Missing challenge".into()))?;

        Ok(Self {
            challenge: challenge_str.to_string(),
            origin: data["origin"]
                .as_str()
                .ok_or_else(|| PasskeyError::ClientData("Missing origin".into()))?
                .to_string(),
            type_: data["type"]
                .as_str()
                .ok_or_else(|| PasskeyError::ClientData("Missing type".into()))?
                .to_string(),
            raw_data,
        })
    }

    pub(super) fn verify(&self, stored_challenge: &str) -> Result<(), PasskeyError> {
        // Verify challenge
        if self.challenge != stored_challenge {
            return Err(PasskeyError::Challenge(
                "Challenge mismatch. For more details, run with RUST_LOG=debug".into(),
            ));
        }

        // Verify origin
        if self.origin != *ORIGIN {
            return Err(PasskeyError::ClientData(format!(
                "Invalid origin. Expected: {}, Got: {}",
                *ORIGIN, self.origin
            )));
        }

        // Verify type for authentication
        if self.type_ != "webauthn.get" {
            return Err(PasskeyError::ClientData(format!(
                "Invalid type. Expected 'webauthn.get', Got: {}",
                self.type_
            )));
        }

        Ok(())
    }
}

/// AuthenticatorData structure as defined in WebAuthn spec Level 2
/// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
#[derive(Debug)]
pub(super) struct AuthenticatorData {
    /// SHA-256 hash of the RP ID (32 bytes)
    pub(super) rp_id_hash: Vec<u8>,

    /// Flags (1 byte) indicating various attributes:
    /// - Bit 0: User Present (UP)
    /// - Bit 2: User Verified (UV)
    /// - Bit 3: Backup Eligibility (BE) - Indicates if credential is discoverable
    /// - Bit 4: Backup State (BS)
    /// - Bit 6: Attested Credential Data Present (AT)
    /// - Bit 7: Extension Data Present (ED)
    pub(super) flags: u8,

    /// Signature counter (4 bytes), 32-bit unsigned big-endian integer
    pub(super) counter: u32,

    /// Raw authenticator data for verification
    pub(super) raw_data: Vec<u8>,
}

/// Flags for AuthenticatorData as defined in WebAuthn spec Level 2
mod auth_data_flags {
    /// User Present (UP) - Bit 0
    pub(super) const UP: u8 = 1 << 0;
    /// User Verified (UV) - Bit 2
    pub(super) const UV: u8 = 1 << 2;
    /// Backup Eligibility (BE) - Bit 3 - Indicates if credential is discoverable
    pub(super) const BE: u8 = 1 << 3;
    /// Backup State (BS) - Bit 4
    pub(super) const BS: u8 = 1 << 4;
    /// Attested Credential Data Present - Bit 6
    pub(super) const AT: u8 = 1 << 6;
    /// Extension Data Present - Bit 7
    pub(super) const ED: u8 = 1 << 7;
}

impl AuthenticatorData {
    /// Parse base64url-encoded authenticator data
    /// Format (minimum 37 bytes):
    /// - RP ID Hash (32 bytes)
    /// - Flags (1 byte)
    /// - Counter (4 bytes)
    /// - Optional: Attested Credential Data
    /// - Optional: Extensions
    pub(super) fn from_base64(auth_data: &str) -> Result<Self, PasskeyError> {
        let data = base64url_decode(auth_data)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {e}")))?;

        if data.len() < 37 {
            return Err(PasskeyError::AuthenticatorData(
                "Authenticator data too short. For more details, run with RUST_LOG=debug".into(),
            ));
        }

        Ok(Self {
            rp_id_hash: data[..32].to_vec(),
            flags: data[32],
            counter: u32::from_be_bytes([data[33], data[34], data[35], data[36]]),
            raw_data: data,
        })
    }

    /// Check if user was present during the authentication
    pub(super) fn is_user_present(&self) -> bool {
        (self.flags & auth_data_flags::UP) != 0
    }

    /// Check if user was verified by the authenticator
    pub(super) fn is_user_verified(&self) -> bool {
        (self.flags & auth_data_flags::UV) != 0
    }

    /// Check if this is a discoverable credential (previously known as resident key)
    pub(super) fn is_discoverable(&self) -> bool {
        (self.flags & auth_data_flags::BE) != 0
    }

    /// Check if this credential is backed up
    pub(super) fn is_backed_up(&self) -> bool {
        (self.flags & auth_data_flags::BS) != 0
    }

    /// Check if attested credential data is present
    pub(super) fn has_attested_credential_data(&self) -> bool {
        (self.flags & auth_data_flags::AT) != 0
    }

    /// Check if extension data is present
    pub(super) fn has_extension_data(&self) -> bool {
        (self.flags & auth_data_flags::ED) != 0
    }

    /// Verify the authenticator data
    pub(super) fn verify(&self) -> Result<(), PasskeyError> {
        // Verify rpIdHash matches SHA-256 hash of rpId
        let expected_hash = digest::digest(&digest::SHA256, PASSKEY_RP_ID.as_bytes());
        if self.rp_id_hash != expected_hash.as_ref() {
            return Err(PasskeyError::AuthenticatorData(format!(
                "Invalid RP ID hash. Expected: {:?}, Got: {:?}",
                expected_hash.as_ref(),
                self.rp_id_hash
            )));
        }

        // Verify user present flag
        if !self.is_user_present() {
            return Err(PasskeyError::Authentication(
                "User not present. For more details, run with RUST_LOG=debug".into(),
            ));
        }

        // Verify user verification if required
        if *PASSKEY_USER_VERIFICATION == "required" && !self.is_user_verified() {
            return Err(PasskeyError::AuthenticatorData(format!(
                "User verification required but flag not set. Flags: {:02x}",
                self.flags
            )));
        }

        tracing::debug!("Authenticator data verification passed");
        tracing::debug!("User present: {}", self.is_user_present());
        tracing::debug!("User verified: {}", self.is_user_verified());
        tracing::debug!("Discoverable credential: {}", self.is_discoverable());
        tracing::debug!("Backed up: {}", self.is_backed_up());
        tracing::debug!(
            "Attested credential data: {}",
            self.has_attested_credential_data()
        );
        tracing::debug!("Extension data: {}", self.has_extension_data());

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct WebAuthnClientData {
    #[serde(rename = "type")]
    pub(super) type_: String,
    pub(super) challenge: String, // base64url encoded
    pub(super) origin: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils;
    use crate::utils::base64url_encode;
    use ring::digest;
    use serde_json::json;

    // Test serialization of AuthenticationOptions struct
    mod authentication_options_tests {
        use super::*;

        /// Test serialization of AuthenticationOptions struct
        ///
        /// This test verifies that `AuthenticationOptions` can be correctly serialized to JSON
        /// with all fields properly formatted. It tests the serde serialization implementation
        /// and validates that all authentication option fields are included in the output.
        #[test]
        fn test_authentication_options_serialization() {
            // Create test data
            let auth_options = AuthenticationOptions {
                challenge: "test_challenge_12345".to_string(),
                timeout: 60000,
                rp_id: "example.com".to_string(),
                allow_credentials: vec![
                    AllowCredential {
                        type_: "public-key".to_string(),
                        id: "credential_id_1".to_string(),
                    },
                    AllowCredential {
                        type_: "public-key".to_string(),
                        id: "credential_id_2".to_string(),
                    },
                ],
                user_verification: "preferred".to_string(),
                auth_id: "auth_session_12345".to_string(),
            };

            // Test serialization to JSON
            let json_result = serde_json::to_string(&auth_options);
            assert!(
                json_result.is_ok(),
                "Failed to serialize AuthenticationOptions"
            );

            let json_str = json_result.unwrap();

            // Verify JSON contains expected fields in camelCase (due to rename_all)
            assert!(json_str.contains("\"challenge\""));
            assert!(json_str.contains("\"timeout\""));
            assert!(json_str.contains("\"rpId\""));
            assert!(json_str.contains("\"allowCredentials\""));
            assert!(json_str.contains("\"userVerification\""));
            assert!(json_str.contains("\"authId\""));

            // Verify values are correctly serialized
            assert!(json_str.contains("\"test_challenge_12345\""));
            assert!(json_str.contains("\"example.com\""));
            assert!(json_str.contains("\"preferred\""));
            assert!(json_str.contains("\"auth_session_12345\""));
            assert!(json_str.contains("60000"));
            assert!(json_str.contains("\"credential_id_1\""));
            assert!(json_str.contains("\"credential_id_2\""));

            // Verify array structure
            assert!(json_str.contains("[") && json_str.contains("]"));
        }
    }

    mod webauthn_client_data_tests {
        use super::*;

        /// Test serialization of WebAuthnClientData struct
        ///
        /// This test verifies that `WebAuthnClientData` can be correctly serialized to JSON
        /// with proper field mapping and formatting. It tests the serde serialization
        /// implementation for WebAuthn client data structures.
        #[test]
        fn test_webauthn_client_data_serialization() {
            // Create a WebAuthnClientData instance
            let client_data = WebAuthnClientData {
                type_: "webauthn.get".to_string(),
                challenge: "dGVzdF9jaGFsbGVuZ2U".to_string(), // base64url for "test_challenge"
                origin: "https://example.com".to_string(),
            };

            // Serialize to JSON
            let json = serde_json::to_string(&client_data).expect("Failed to serialize");

            // Deserialize back to struct
            let deserialized: WebAuthnClientData =
                serde_json::from_str(&json).expect("Failed to deserialize");

            // Verify fields match
            assert_eq!(deserialized.type_, "webauthn.get");
            assert_eq!(deserialized.challenge, "dGVzdF9jaGFsbGVuZ2U");
            assert_eq!(deserialized.origin, "https://example.com");
        }

        /// Test field mapping of WebAuthnClientData struct
        ///
        /// This test verifies that `WebAuthnClientData` field names are correctly mapped
        /// during serialization, including the proper handling of the "type" field name
        /// conversion. It validates JSON field naming conventions for WebAuthn compliance.
        #[test]
        fn test_webauthn_client_data_field_mapping() {
            // Create JSON with "type" field (not "type_")
            let json_str = r#"{
                "type": "webauthn.create",
                "challenge": "YW5vdGhlcl9jaGFsbGVuZ2U",
                "origin": "https://test.example.org"
            }"#;

            // Deserialize to struct
            let deserialized: WebAuthnClientData =
                serde_json::from_str(json_str).expect("Failed to deserialize");

            // Verify field mapping works correctly
            assert_eq!(deserialized.type_, "webauthn.create");
            assert_eq!(deserialized.challenge, "YW5vdGhlcl9jaGFsbGVuZ2U");
            assert_eq!(deserialized.origin, "https://test.example.org");

            // Verify serialization produces correct field names
            let serialized = serde_json::to_string(&deserialized).expect("Failed to serialize");
            let json_value: serde_json::Value =
                serde_json::from_str(&serialized).expect("Failed to parse JSON");

            // Check that we have "type" in the JSON (not "type_")
            assert!(json_value.get("type").is_some());
            assert!(json_value.get("type_").is_none());
        }
    }

    // Helper function to create a mock ParsedClientData for testing
    // Note: This can be replaced with crate::common::create_test_parsed_client_data in integration tests
    fn create_parsed_client_data(challenge: &str, origin: &str, type_: &str) -> ParsedClientData {
        ParsedClientData {
            challenge: challenge.to_string(),
            origin: origin.to_string(),
            type_: type_.to_string(),
            raw_data: vec![],
        }
    }

    // Tests for ParsedClientData
    mod parsed_client_data_tests {
        use super::*;

        /// Test successful parsing of client data JSON
        ///
        /// This test verifies that `WebAuthnClientData` can be correctly deserialized from
        /// valid JSON with all required fields. It tests the parsing of WebAuthn client
        /// data received from authenticator responses.
        #[test]
        fn test_from_base64_success() {
            let client_data = json!({
                "challenge": "sample-challenge",
                "origin": "https://example.com",
                "type": "webauthn.get"
            });
            let client_data_str = client_data.to_string();
            let client_data_b64 = base64url_encode(client_data_str.as_bytes().to_vec()).unwrap();
            let result = ParsedClientData::from_base64(&client_data_b64);
            assert!(result.is_ok(), "Expected Ok result, got {result:?}");
            let parsed = result.unwrap();
            assert_eq!(parsed.challenge, "sample-challenge");
            assert_eq!(parsed.origin, "https://example.com");
            assert_eq!(parsed.type_, "webauthn.get");
            assert_eq!(parsed.raw_data, client_data_str.as_bytes());
        }

        /// Test ParsedClientData parsing with invalid base64 encoding
        ///
        /// This test verifies that `ParsedClientData::from_base64` properly handles
        /// invalid base64 input data. It tests the error handling when provided
        /// with malformed base64 strings that cannot be decoded.
        #[test]
        fn test_from_base64_invalid_base64() {
            let result = ParsedClientData::from_base64("invalid-base64!");
            assert!(result.is_err());
            match result {
                Err(PasskeyError::Format(msg)) => {
                    assert!(msg.contains("Failed to decode"));
                }
                _ => panic!("Expected Format error"),
            }
        }

        /// Test ParsedClientData parsing with invalid UTF-8 data
        ///
        /// This test verifies that `ParsedClientData::from_base64` properly handles
        /// data that is valid base64 but contains invalid UTF-8 sequences. It tests
        /// the error handling when the decoded data cannot be converted to a string.
        #[test]
        fn test_from_base64_invalid_utf8() {
            let invalid_utf8 = vec![0xFF, 0xFF, 0xFF];
            let encoded = base64url_encode(invalid_utf8).unwrap();
            let result = ParsedClientData::from_base64(&encoded);
            assert!(result.is_err());
            match result {
                Err(PasskeyError::Format(msg)) => {
                    assert!(msg.contains("Invalid UTF-8"));
                }
                _ => panic!("Expected Format error"),
            }
        }

        /// Test ParsedClientData parsing with invalid JSON data
        ///
        /// This test verifies that `ParsedClientData::from_base64` properly handles
        /// data that is valid base64 and UTF-8 but contains invalid JSON syntax.
        /// It tests the error handling when the decoded string cannot be parsed as JSON.
        #[test]
        fn test_from_base64_invalid_json() {
            let invalid_json = "not valid json";
            let encoded = base64url_encode(invalid_json.as_bytes().to_vec()).unwrap();
            let result = ParsedClientData::from_base64(&encoded);
            assert!(result.is_err());
            match result {
                Err(PasskeyError::Format(msg)) => {
                    assert!(msg.contains("Invalid JSON"));
                }
                _ => panic!("Expected Format error"),
            }
        }

        /// Test ParsedClientData parsing with missing challenge field
        ///
        /// This test verifies that `ParsedClientData::from_base64` properly validates
        /// required fields in the client data JSON. It tests error handling when
        /// the challenge field is missing from the client data structure.
        #[test]
        fn test_from_base64_missing_challenge() {
            let client_data = json!({
                "origin": "https://example.com",
                "type": "webauthn.get"
            });
            let client_data_str = client_data.to_string();
            let client_data_b64 = base64url_encode(client_data_str.as_bytes().to_vec()).unwrap();
            let result = ParsedClientData::from_base64(&client_data_b64);
            assert!(result.is_err());
            match result {
                Err(PasskeyError::ClientData(msg)) => {
                    assert_eq!(msg, "Missing challenge");
                }
                _ => panic!("Expected ClientData error"),
            }
        }

        /// Test ParsedClientData parsing with missing origin field
        ///
        /// This test verifies that `ParsedClientData::from_base64` properly validates
        /// required fields in the client data JSON. It tests error handling when
        /// the origin field is missing from the client data structure.
        #[test]
        fn test_from_base64_missing_origin() {
            let client_data = json!({
                "challenge": "sample-challenge",
                "type": "webauthn.get"
            });
            let client_data_str = client_data.to_string();
            let client_data_b64 = base64url_encode(client_data_str.as_bytes().to_vec()).unwrap();
            let result = ParsedClientData::from_base64(&client_data_b64);
            assert!(result.is_err());
            match result {
                Err(PasskeyError::ClientData(msg)) => {
                    assert_eq!(msg, "Missing origin");
                }
                _ => panic!("Expected ClientData error"),
            }
        }

        /// Test ParsedClientData parsing with missing type field
        ///
        /// This test verifies that `ParsedClientData::from_base64` properly validates
        /// required fields in the client data JSON. It tests error handling when
        /// the type field is missing from the client data structure.
        #[test]
        fn test_from_base64_missing_type() {
            let client_data = json!({
                "challenge": "sample-challenge",
                "origin": "https://example.com"
            });
            let client_data_str = client_data.to_string();
            let client_data_b64 = base64url_encode(client_data_str.as_bytes().to_vec()).unwrap();
            let result = ParsedClientData::from_base64(&client_data_b64);
            assert!(result.is_err());
            match result {
                Err(PasskeyError::ClientData(msg)) => {
                    assert_eq!(msg, "Missing type");
                }
                _ => panic!("Expected ClientData error"),
            }
        }

        /// Test successful ParsedClientData verification
        ///
        /// This test verifies that `ParsedClientData::verify` correctly validates
        /// client data when all parameters match expected values. It tests successful
        /// verification with matching challenge, origin, and type values.
        #[tokio::test]
        async fn test_verify_success() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            let test_origin = crate::test_utils::get_test_origin();
            let parsed_data =
                create_parsed_client_data("sample-challenge", &test_origin, "webauthn.get");
            let result = parsed_data.verify("sample-challenge");
            assert!(result.is_ok(), "Expected Ok result, got {result:?}");
            // No need to restore environment variables as they're now managed by test_utils
        }

        /// Test ParsedClientData challenge verification with mismatched challenge
        ///
        /// This test verifies that `ParsedClientData::verify` properly validates
        /// the challenge parameter. It tests error handling when the provided
        /// challenge doesn't match the challenge stored in the client data.
        #[tokio::test]
        async fn test_verify_challenge_mismatch() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            let parsed_data = create_parsed_client_data(
                "sample-challenge",
                "https://example.com",
                "webauthn.get",
            );
            let result = parsed_data.verify("different-challenge");
            assert!(result.is_err());
            match result {
                Err(PasskeyError::Challenge(msg)) => {
                    assert!(msg.contains("Challenge mismatch"));
                }
                _ => panic!("Expected Challenge error"),
            }
        }

        /// Test ParsedClientData origin verification with mismatched origin
        ///
        /// This test verifies that `ParsedClientData::verify` properly validates
        /// the origin parameter against the configured ORIGIN environment variable.
        /// It tests error handling when the client data origin doesn't match the expected origin.
        #[tokio::test]
        async fn test_verify_origin_mismatch() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            let parsed_data = create_parsed_client_data(
                "sample-challenge",
                "https://attacker.com",
                "webauthn.get",
            );
            let result = parsed_data.verify("sample-challenge");
            assert!(result.is_err());
            match result {
                Err(PasskeyError::ClientData(msg)) => {
                    assert!(msg.contains("Invalid origin"));
                    assert!(msg.contains(&crate::test_utils::get_test_origin()));
                    assert!(msg.contains("https://attacker.com"));
                }
                _ => panic!("Expected ClientData error"),
            }
        }

        /// Test ParsedClientData verification with invalid type
        ///
        /// This test verifies that `ParsedClientData::verify` properly validates
        /// the type field against the expected "webauthn.get" value. It tests error
        /// handling when the client data contains an incorrect authentication type.
        #[tokio::test]
        async fn test_verify_invalid_type() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            let test_origin = crate::test_utils::get_test_origin();
            let parsed_data =
                create_parsed_client_data("sample-challenge", &test_origin, "webauthn.create");
            let result = parsed_data.verify("sample-challenge");
            assert!(result.is_err());
            match result {
                Err(PasskeyError::ClientData(msg)) => {
                    assert!(msg.contains("Invalid type"));
                    assert!(msg.contains("webauthn.get"));
                    assert!(msg.contains("webauthn.create"));
                }
                _ => panic!("Expected ClientData error"),
            }
        }
    }

    // Tests for AuthenticatorData
    mod authenticator_data_tests {
        use super::*;

        fn create_test_auth_data(
            rp_id_hash: Vec<u8>,
            flags: u8,
            counter: u32,
            extra_data: Option<Vec<u8>>,
        ) -> Vec<u8> {
            let mut data = Vec::with_capacity(37);
            data.extend_from_slice(&rp_id_hash);
            data.push(flags);
            data.extend_from_slice(&counter.to_be_bytes());
            if let Some(extra) = extra_data {
                data.extend_from_slice(&extra);
            }
            data
        }

        /// Test successful parsing of authenticator data from base64
        ///
        /// This test verifies that `AuthenticatorData::from_base64` can correctly
        /// parse valid authenticator data. It tests the parsing of RP ID hash,
        /// flags, counter, and raw data preservation during the parsing process.
        #[test]
        fn test_from_base64_success() {
            let rp_id_hash = vec![0; 32];
            let flags = 0x01 | 0x04; // UP | UV
            let counter = 12345u32;
            let auth_data_vec = create_test_auth_data(rp_id_hash.clone(), flags, counter, None);
            let auth_data_b64 = base64url_encode(auth_data_vec.clone()).unwrap();
            let result = AuthenticatorData::from_base64(&auth_data_b64);
            assert!(result.is_ok(), "Expected Ok result, got {result:?}");
            let parsed = result.unwrap();
            assert_eq!(parsed.rp_id_hash, rp_id_hash);
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.counter, counter);
            assert_eq!(parsed.raw_data, auth_data_vec);
        }

        /// Test AuthenticatorData parsing with invalid base64 encoding
        ///
        /// This test verifies that `AuthenticatorData::from_base64` properly handles
        /// invalid base64 input data. It tests error handling when provided with
        /// malformed base64 strings that cannot be decoded.
        #[test]
        fn test_from_base64_invalid_base64() {
            let result = AuthenticatorData::from_base64("invalid-base64!");
            assert!(result.is_err());
            match result {
                Err(PasskeyError::Format(msg)) => {
                    assert!(msg.contains("Failed to decode"));
                }
                _ => panic!("Expected Format error"),
            }
        }

        /// Test AuthenticatorData parsing with insufficient data length
        ///
        /// This test verifies that `AuthenticatorData::from_base64` properly validates
        /// the minimum required data length. It tests error handling when the decoded
        /// data is too short to contain the required authenticator data fields.
        #[test]
        fn test_from_base64_too_short() {
            let short_data = vec![0; 36];
            let short_data_b64 = base64url_encode(short_data).unwrap();
            let result = AuthenticatorData::from_base64(&short_data_b64);
            assert!(result.is_err());
            match result {
                Err(PasskeyError::AuthenticatorData(msg)) => {
                    assert!(msg.contains("too short"));
                }
                _ => panic!("Expected AuthenticatorData error"),
            }
        }

        /// Test AuthenticatorData flag bit checking methods
        ///
        /// This test verifies that the individual flag checking methods (is_user_present,
        /// is_user_verified, etc.) correctly interpret the flag bits in the authenticator
        /// data. It tests various flag combinations and their corresponding method responses.
        #[test]
        fn test_individual_flag_methods() {
            // Create AuthenticatorData with various flags set
            let rp_id_hash = vec![0; 32];
            let counter = 0;

            // Test User Present flag (0x01)
            let auth_data_up = AuthenticatorData {
                rp_id_hash: rp_id_hash.clone(),
                flags: auth_data_flags::UP,
                counter,
                raw_data: vec![],
            };
            assert!(auth_data_up.is_user_present());
            assert!(!auth_data_up.is_user_verified());
            assert!(!auth_data_up.is_discoverable());
            assert!(!auth_data_up.is_backed_up());
            assert!(!auth_data_up.has_attested_credential_data());
            assert!(!auth_data_up.has_extension_data());

            // Test User Verified flag (0x04)
            let auth_data_uv = AuthenticatorData {
                rp_id_hash: rp_id_hash.clone(),
                flags: auth_data_flags::UV,
                counter,
                raw_data: vec![],
            };
            assert!(!auth_data_uv.is_user_present());
            assert!(auth_data_uv.is_user_verified());

            // Test Discoverable Credential flag (0x08)
            let auth_data_be = AuthenticatorData {
                rp_id_hash: rp_id_hash.clone(),
                flags: auth_data_flags::BE,
                counter,
                raw_data: vec![],
            };
            assert!(auth_data_be.is_discoverable());
            assert!(!auth_data_be.is_backed_up());

            // Test Backup State flag (0x10)
            let auth_data_bs = AuthenticatorData {
                rp_id_hash: rp_id_hash.clone(),
                flags: auth_data_flags::BS,
                counter,
                raw_data: vec![],
            };
            assert!(auth_data_bs.is_backed_up());

            // Test Attested Credential Data flag (0x40)
            let auth_data_at = AuthenticatorData {
                rp_id_hash: rp_id_hash.clone(),
                flags: auth_data_flags::AT,
                counter,
                raw_data: vec![],
            };
            assert!(auth_data_at.has_attested_credential_data());

            // Test Extension Data flag (0x80)
            let auth_data_ed = AuthenticatorData {
                rp_id_hash: rp_id_hash.clone(),
                flags: auth_data_flags::ED,
                counter,
                raw_data: vec![],
            };
            assert!(auth_data_ed.has_extension_data());

            // Test multiple flags
            let auth_data_multi = AuthenticatorData {
                rp_id_hash,
                flags: auth_data_flags::UP | auth_data_flags::UV | auth_data_flags::BE,
                counter,
                raw_data: vec![],
            };
            assert!(auth_data_multi.is_user_present());
            assert!(auth_data_multi.is_user_verified());
            assert!(auth_data_multi.is_discoverable());
            assert!(!auth_data_multi.is_backed_up());
        }

        /// Test comprehensive AuthenticatorData flag checking methods
        ///
        /// This test verifies that all flag checking methods correctly interpret flag bits
        /// in the AuthenticatorData. It tests various flag combinations to ensure proper
        /// detection of user presence, verification, backup state, and other attributes.
        #[test]
        fn test_flag_methods() {
            let all_flags = 0x01 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80;
            let auth_data = AuthenticatorData {
                rp_id_hash: vec![0; 32],
                flags: all_flags,
                counter: 0,
                raw_data: vec![],
            };
            assert!(auth_data.is_user_present());
            assert!(auth_data.is_user_verified());
            assert!(auth_data.is_discoverable());
            assert!(auth_data.is_backed_up());
            assert!(auth_data.has_attested_credential_data());
            assert!(auth_data.has_extension_data());

            let no_flags = 0u8;
            let auth_data_no_flags = AuthenticatorData {
                rp_id_hash: vec![0; 32],
                flags: no_flags,
                counter: 0,
                raw_data: vec![],
            };
            assert!(!auth_data_no_flags.is_user_present());
            assert!(!auth_data_no_flags.is_user_verified());
            assert!(!auth_data_no_flags.is_discoverable());
            assert!(!auth_data_no_flags.is_backed_up());
            assert!(!auth_data_no_flags.has_attested_credential_data());
            assert!(!auth_data_no_flags.has_extension_data());

            let up_flag = 0x01;
            let auth_data_up = AuthenticatorData {
                rp_id_hash: vec![0; 32],
                flags: up_flag,
                counter: 0,
                raw_data: vec![],
            };
            assert!(auth_data_up.is_user_present());
            assert!(!auth_data_up.is_user_verified());

            let uv_flag = 0x04;
            let auth_data_uv = AuthenticatorData {
                rp_id_hash: vec![0; 32],
                flags: uv_flag,
                counter: 0,
                raw_data: vec![],
            };
            assert!(!auth_data_uv.is_user_present());
            assert!(auth_data_uv.is_user_verified());
        }

        /// Test successful AuthenticatorData verification
        ///
        /// This test verifies that `AuthenticatorData::verify` correctly validates
        /// the RP ID hash against the configured PASSKEY_RP_ID. It tests successful
        /// verification when the hash matches the expected value.
        #[tokio::test]
        async fn test_verify_success() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            // Get the current RP_ID from environment (should be set by init_test_environment)
            let rp_id =
                std::env::var("PASSKEY_RP_ID").unwrap_or_else(|_| "example.com".to_string());

            let expected_hash = digest::digest(&digest::SHA256, rp_id.as_bytes());
            let auth_data = AuthenticatorData {
                rp_id_hash: expected_hash.as_ref().to_vec(),
                flags: 0x05, // User present (0x01) and User verified (0x04) flags set
                counter: 0,
                raw_data: vec![],
            };
            let result = auth_data.verify();
            assert!(result.is_ok(), "Expected Ok result, got {result:?}");
        }

        /// Test AuthenticatorData verification with invalid RP ID hash
        ///
        /// This test verifies that `AuthenticatorData::verify` properly validates
        /// the RP ID hash against the expected hash. It tests error handling when
        /// the authenticator data contains an incorrect RP ID hash.
        #[tokio::test]
        async fn test_verify_invalid_rp_id_hash() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            let auth_data = AuthenticatorData {
                rp_id_hash: vec![1; 32], // Wrong hash
                flags: 0x01,             // UP
                counter: 0,
                raw_data: vec![],
            };
            let result = auth_data.verify();
            assert!(result.is_err());
            match result {
                Err(PasskeyError::AuthenticatorData(msg)) => {
                    assert!(msg.contains("Invalid RP ID hash"));
                }
                _ => panic!("Expected AuthenticatorData error"),
            }
        }

        /// Test AuthenticatorData verification with user not present
        ///
        /// This test verifies that `AuthenticatorData::verify` properly validates
        /// the user presence flag. It tests error handling when the authenticator
        /// data indicates the user was not present during the authentication.
        #[tokio::test]
        async fn test_verify_user_not_present() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            // Get the current RP_ID from environment (should be set by init_test_environment)
            let rp_id = std::env::var("PASSKEY_RP_ID").unwrap_or_else(|_| "127.0.0.1".to_string());
            let expected_hash = digest::digest(&digest::SHA256, rp_id.as_bytes());
            let auth_data = AuthenticatorData {
                rp_id_hash: expected_hash.as_ref().to_vec(),
                flags: 0, // No flags set, user not present
                counter: 0,
                raw_data: vec![],
            };
            let result = auth_data.verify();
            assert!(result.is_err());
            match result {
                Err(PasskeyError::Authentication(msg)) => {
                    assert!(msg.contains("User not present"));
                }
                _ => panic!("Expected Authentication error"),
            }

            // No need to restore environment variables when using test_utils
        }

        /// Test AuthenticatorData verification with missing user verification
        ///
        /// This test verifies that `AuthenticatorData::verify` properly enforces
        /// user verification requirements. It tests error handling when user verification
        /// is required but the authenticator data indicates the user was not verified.
        ///
        /// NOTE: This test requires .env_test to have PASSKEY_USER_VERIFICATION=required
        #[tokio::test]
        async fn test_verify_user_verification_required_but_not_verified() {
            // Use test_utils to set up environment variables safely
            test_utils::init_test_environment().await;

            // Get the current RP_ID from environment (should be set by init_test_environment)
            let rp_id =
                std::env::var("PASSKEY_RP_ID").unwrap_or_else(|_| "example.com".to_string());

            // Ensure test passes regardless of environment setting
            // We're testing the validation logic, not the specific setting
            if std::env::var("PASSKEY_USER_VERIFICATION").unwrap_or_default() != "required" {
                println!(
                    "Skipping test_verify_user_verification_required_but_not_verified because PASSKEY_USER_VERIFICATION is not set to 'required'"
                );
                return;
            }

            let expected_hash = digest::digest(&digest::SHA256, rp_id.as_bytes());
            let auth_data = AuthenticatorData {
                rp_id_hash: expected_hash.as_ref().to_vec(),
                flags: 0x01, // User present but not verified
                counter: 0,
                raw_data: vec![],
            };
            let result = auth_data.verify();
            assert!(result.is_err());
            match result {
                Err(PasskeyError::AuthenticatorData(msg)) => {
                    assert!(msg.contains("User verification required but flag not set"));
                }
                _ => panic!("Expected AuthenticatorData error: {result:?}"),
            }
        }
    }
}
