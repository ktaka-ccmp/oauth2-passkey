use ciborium::value::Value as CborValue;
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::passkey::{
    config::{ORIGIN, PASSKEY_RP_ID, PASSKEY_USER_VERIFICATION},
    errors::PasskeyError,
    types::PublicKeyCredentialUserEntity,
};
use crate::utils::base64url_decode;

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

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct AuthenticatorResponse {
    pub(super) id: String,
    raw_id: String,
    pub(super) response: AuthenticatorAssertionResponse,
    authenticator_attachment: Option<String>,
    pub(super) auth_id: String,
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
            match super::challenge::get_and_validate_options("regi_challenge", handle).await {
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
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

        let data_str = String::from_utf8(raw_data.clone())
            .map_err(|e| PasskeyError::Format(format!("Invalid UTF-8: {}", e)))?;

        let data: serde_json::Value = serde_json::from_str(&data_str)
            .map_err(|e| PasskeyError::Format(format!("Invalid JSON: {}", e)))?;

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
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

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
