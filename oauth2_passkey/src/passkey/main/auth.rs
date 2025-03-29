use ring::{digest, signature::UnparsedPublicKey};

use super::challenge::{get_and_validate_options, remove_options};
use super::types::{
    AllowCredential, AuthenticationOptions, AuthenticatorData, AuthenticatorResponse,
    ParsedClientData,
};
use super::utils::{name2cid_str_vec, store_in_cache};

use crate::passkey::config::{
    ORIGIN, PASSKEY_CHALLENGE_TIMEOUT, PASSKEY_RP_ID, PASSKEY_TIMEOUT, PASSKEY_USER_VERIFICATION,
};
use crate::passkey::errors::PasskeyError;
use crate::passkey::storage::PasskeyStore;
use crate::passkey::types::{PasskeyCredential, PublicKeyCredentialUserEntity, StoredOptions};

use crate::utils::{base64url_decode, gen_random_string};

pub async fn start_authentication(
    username: Option<String>,
) -> Result<AuthenticationOptions, PasskeyError> {
    let mut allow_credentials = Vec::new();
    match username.clone() {
        Some(username) => {
            let credential_id_strs = name2cid_str_vec(&username).await?;

            for credential in credential_id_strs {
                allow_credentials.push(AllowCredential {
                    type_: "public-key".to_string(),
                    id: credential.credential_id,
                });
            }
        }
        None => {
            // allow_credentials = vec![];
        }
    }

    let challenge_str = gen_random_string(32)?;
    let auth_id = gen_random_string(16)?;

    let stored_options = StoredOptions {
        challenge: challenge_str.clone(),
        user: PublicKeyCredentialUserEntity {
            user_handle: "temp".to_string(),
            name: "temp".to_string(),
            display_name: "temp".to_string(),
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl: *PASSKEY_CHALLENGE_TIMEOUT as u64,
    };

    store_in_cache(
        "auth_challenge",
        &auth_id,
        stored_options,
        *PASSKEY_CHALLENGE_TIMEOUT as usize,
    )
    .await?;

    let auth_option = AuthenticationOptions {
        challenge: challenge_str,
        timeout: (*PASSKEY_TIMEOUT) * 1000, // Convert seconds to milliseconds
        rp_id: PASSKEY_RP_ID.to_string(),
        allow_credentials,
        user_verification: PASSKEY_USER_VERIFICATION.to_string(),
        auth_id,
    };

    tracing::debug!("Auth options: {:?}", auth_option);

    Ok(auth_option)
}

pub async fn finish_authentication(
    auth_response: AuthenticatorResponse,
) -> Result<(String, String), PasskeyError> {
    tracing::debug!(
        "Starting authentication verification for response: {:?}",
        auth_response
    );

    // Get stored challenge and verify auth
    let stored_options = get_and_validate_options("auth_challenge", &auth_response.auth_id).await?;

    tracing::debug!(
        "Parsing client data: {}",
        &auth_response.response.client_data_json
    );

    let client_data = ParsedClientData::from_base64(&auth_response.response.client_data_json)?;

    tracing::debug!("Parsed client data: {:?}", client_data);

    // Verify client data i.e. challenge, origin and type(="webauthn.get")
    client_data.verify(&stored_options.challenge)?;

    tracing::debug!(
        "Parsing authenticator data: {}",
        &auth_response.response.authenticator_data
    );

    let auth_data = AuthenticatorData::from_base64(&auth_response.response.authenticator_data)?;

    tracing::debug!("Parsed authenticator data: {:?}", auth_data);

    // Verify authenticator data i.e. rpIdHash, flags and counter
    auth_data.verify()?;

    // Get credential then public key
    let stored_credential = PasskeyStore::get_credential(&auth_response.id)
        .await?
        .ok_or_else(|| {
            tracing::error!("Credential not found");
            PasskeyError::NotFound("Credential not found".into())
        })?;

    tracing::debug!(
        "finish_authentication: Credential &id: {:?}, id: {}",
        &auth_response.id,
        auth_response.id
    );
    tracing::debug!("Found credential: {:?}", stored_credential);
    tracing::debug!(
        "Credential properties:\n\
         - Type: {}\n\
         - User present: {}\n\
         - User verified: {}\n\
         - Backed up: {}",
        if auth_data.is_discoverable() {
            "discoverable"
        } else {
            "server-side"
        },
        auth_data.is_user_present(),
        auth_data.is_user_verified(),
        auth_data.is_backed_up(),
    );

    // Verify user handle and counter
    verify_user_handle(
        &auth_response,
        &stored_credential,
        auth_data.is_discoverable(),
    )?;
    verify_counter(&auth_response.id, &auth_data, &stored_credential).await?;

    // Verify signature and cleanup
    verify_signature(&auth_response, &client_data, &auth_data, &stored_credential).await?;

    // Remove challenge from cache
    remove_options("auth_challenge", &auth_response.auth_id).await?;
    let user_name = stored_credential.user.name.clone();
    let user_id = stored_credential.user_id.clone();

    Ok((user_id, user_name))
}

impl ParsedClientData {
    fn from_base64(client_data_json: &str) -> Result<Self, PasskeyError> {
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

    fn verify(&self, stored_challenge: &str) -> Result<(), PasskeyError> {
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
    fn from_base64(auth_data: &str) -> Result<Self, PasskeyError> {
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
    fn is_user_present(&self) -> bool {
        (self.flags & auth_data_flags::UP) != 0
    }

    /// Check if user was verified by the authenticator
    fn is_user_verified(&self) -> bool {
        (self.flags & auth_data_flags::UV) != 0
    }

    /// Check if this is a discoverable credential (previously known as resident key)
    fn is_discoverable(&self) -> bool {
        (self.flags & auth_data_flags::BE) != 0
    }

    /// Check if this credential is backed up
    fn is_backed_up(&self) -> bool {
        (self.flags & auth_data_flags::BS) != 0
    }

    /// Check if attested credential data is present
    fn has_attested_credential_data(&self) -> bool {
        (self.flags & auth_data_flags::AT) != 0
    }

    /// Check if extension data is present
    fn has_extension_data(&self) -> bool {
        (self.flags & auth_data_flags::ED) != 0
    }

    /// Verify the authenticator data
    fn verify(&self) -> Result<(), PasskeyError> {
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

/// Verifies that the user handle in the authenticator response matches the stored credential
///
/// For discoverable credentials, a user handle is required.
/// For non-discoverable credentials, a user handle is optional.
fn verify_user_handle(
    auth_response: &AuthenticatorResponse,
    stored_credential: &PasskeyCredential,
    is_discoverable: bool,
) -> Result<(), PasskeyError> {
    let user_handle = auth_response.response.user_handle.clone();

    tracing::debug!(
        "User handle: {:?}, Stored handle: {:?}, User handle raw: {:?}, Is discoverable: {}",
        user_handle,
        &stored_credential.user.user_handle,
        auth_response.response.user_handle,
        is_discoverable,
    );

    match (
        user_handle,
        &stored_credential.user.user_handle,
        is_discoverable,
    ) {
        (Some(handle), stored_handle, _) if handle != *stored_handle => {
            tracing::error!("User handle mismatch: {} != {}", handle, stored_handle);
            return Err(PasskeyError::Authentication(
                "User handle mismatch. For more details, run with RUST_LOG=debug".into(),
            ));
        }
        (None, _, true) => {
            // Discoverable credentials MUST provide a user handle
            return Err(PasskeyError::Authentication(
                "Missing required user handle for discoverable credential. For more details, run with RUST_LOG=debug".into(),
            ));
        }
        (None, _, false) => {
            // Non-discoverable credentials may omit the user handle
            tracing::debug!("No user handle provided for non-discoverable credential");
        }
        _ => {
            tracing::debug!("User handle verified successfully");
        }
    }

    Ok(())
}

/// Verifies the authenticator counter to prevent replay attacks
///
/// The counter should always increase to prevent replay attacks.
/// A counter value of 0 indicates the authenticator doesn't support counters.
async fn verify_counter(
    credential_id: &str,
    auth_data: &AuthenticatorData,
    stored_credential: &PasskeyCredential,
) -> Result<(), PasskeyError> {
    let auth_counter = auth_data.counter;
    tracing::debug!(
        "Counter verification - stored: {}, received: {}",
        stored_credential.counter,
        auth_counter
    );

    if auth_counter == 0 {
        // Counter value of 0 means the authenticator doesn't support counters
        tracing::info!("Authenticator does not support counters (received counter=0)");
    } else if auth_counter <= stored_credential.counter {
        // Counter value decreased or didn't change - possible cloning attack
        tracing::warn!(
            "Counter verification failed - stored: {}, received: {}",
            stored_credential.counter,
            auth_counter
        );
        return Err(PasskeyError::Authentication(
            "Counter value decreased - possible credential cloning detected. For more details, run with RUST_LOG=debug".into(),
        ));
    } else {
        // Counter increased as expected
        tracing::debug!(
            "Counter verification successful - stored: {}, received: {}",
            stored_credential.counter,
            auth_counter
        );

        // Update the counter
        PasskeyStore::update_credential_counter(credential_id, auth_counter).await?;
    }

    Ok(())
}

/// Verifies the signature using the public key and cleans up the challenge
///
/// This function:
/// 1. Verifies the signature using the stored public key
/// 2. Cleans up the challenge from the cache store on success
/// 3. Returns the user's name on success
async fn verify_signature(
    auth_response: &AuthenticatorResponse,
    client_data: &ParsedClientData,
    auth_data: &AuthenticatorData,
    stored_credential: &PasskeyCredential,
) -> Result<(), PasskeyError> {
    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;

    let public_key = base64url_decode(&stored_credential.public_key)
        .map_err(|e| PasskeyError::Format(format!("Invalid public key: {}", e)))?;

    let unparsed_public_key = UnparsedPublicKey::new(verification_algorithm, &public_key);

    // Signature
    let signature = base64url_decode(&auth_response.response.signature)
        .map_err(|e| PasskeyError::Format(format!("Invalid signature: {}", e)))?;

    tracing::debug!("Decoded signature length: {}", signature.len());

    // Prepare signed data
    let client_data_hash = digest::digest(&digest::SHA256, &client_data.raw_data);
    let mut signed_data = Vec::new();

    signed_data.extend_from_slice(&auth_data.raw_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    tracing::debug!("Signed data length: {}", signed_data.len());

    // Verify signature using public key
    match unparsed_public_key.verify(&signed_data, &signature) {
        Ok(_) => {
            tracing::info!("Signature verification successful");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Signature verification failed: {:?}", e);
            Err(PasskeyError::Verification(
                "Signature verification failed. For more details, run with RUST_LOG=debug".into(),
            ))
        }
    }
}
