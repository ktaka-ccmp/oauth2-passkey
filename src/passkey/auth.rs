use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::{digest, signature::UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::PasskeyError;
use crate::passkey::{base64url_decode, generate_challenge};
use crate::passkey::{AppState, PublicKeyCredentialUserEntity, StoredChallenge};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    challenge: String,
    timeout: u32,
    rp_id: String,
    allow_credentials: Vec<AllowCredential>,
    user_verification: String,
    auth_id: String,
}

#[derive(Serialize, Debug)]
struct AllowCredential {
    type_: String,
    id: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct AuthenticatorResponse {
    id: String,
    raw_id: String,
    response: AuthenticatorAssertionResponse,
    authenticator_attachment: Option<String>,
    auth_id: String,
}

#[derive(Deserialize, Debug)]
struct AuthenticatorAssertionResponse {
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option<String>,
}

pub async fn start_authentication(state: &AppState) -> Result<AuthenticationOptions, PasskeyError> {
    let challenge = generate_challenge();
    let auth_id = Uuid::new_v4().to_string();

    let stored_challenge = StoredChallenge {
        challenge: challenge.clone().unwrap_or_default(),
        user: PublicKeyCredentialUserEntity {
            id: auth_id.clone(),
            name: "temp".to_string(),
            display_name: "temp".to_string(),
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut challenge_store = state.challenge_store.lock().await;
    challenge_store
        .store_challenge(auth_id.clone(), stored_challenge)
        .await?;

    let auth_option = AuthenticationOptions {
        challenge: URL_SAFE.encode(challenge.unwrap_or_default()),
        timeout: 60000,
        rp_id: state.config.rp_id.clone(),
        allow_credentials: vec![], // Empty for resident keys
        user_verification: state
            .config
            .authenticator_selection
            .user_verification
            .clone(),
        auth_id,
    };

    #[cfg(debug_assertions)]
    println!("Auth options: {:?}", auth_option);
    Ok(auth_option)
}

pub async fn verify_authentication(
    state: &AppState,
    auth_response: AuthenticatorResponse,
) -> Result<String, PasskeyError> {
    #[cfg(debug_assertions)]
    println!(
        "Starting authentication verification for response: {:?}",
        auth_response
    );

    // Get stored challenge and verify auth
    let mut challenge_store = state.challenge_store.lock().await;
    let credential_store = state.credential_store.lock().await;

    // let mut store = state.store.lock().await;
    let stored_challenge = challenge_store
        .get_challenge(&auth_response.auth_id)
        .await?
        .ok_or(PasskeyError::Storage("Challenge not found".into()))?;

    #[cfg(debug_assertions)]
    println!("Found stored challenge: {:?}", stored_challenge);

    // Parse and verify client data
    #[cfg(debug_assertions)]
    println!(
        "Parsing client data: {}",
        &auth_response.response.client_data_json
    );

    let client_data = ParsedClientData::from_base64(&auth_response.response.client_data_json)?;

    #[cfg(debug_assertions)]
    println!("Parsed client data: {:?}", client_data);

    client_data.verify(state, &stored_challenge.challenge)?;

    // Parse and verify authenticator data
    #[cfg(debug_assertions)]
    println!(
        "Parsing authenticator data: {}",
        &auth_response.response.authenticator_data
    );

    let auth_data = AuthenticatorData::from_base64(&auth_response.response.authenticator_data)?;

    #[cfg(debug_assertions)]
    println!("Parsed authenticator data: {:?}", auth_data);

    auth_data.verify(state)?;

    // Get credential then public key
    let credential = credential_store
        .get_credential(&auth_response.id)
        .await?
        .ok_or(PasskeyError::Authentication("Unknown credential".into()))?;

    #[cfg(debug_assertions)]
    println!("Found credential: {:?}", credential);

    let user_handle = auth_response
        .response
        .user_handle
        .as_ref()
        .and_then(|handle| {
            base64url_decode(handle)
                .ok()
                .and_then(|decoded| String::from_utf8(decoded).ok())
        })
        .unwrap_or("default".to_string());

    #[cfg(debug_assertions)]
    println!("user_info stored in credential: {:?}", &credential.user);
    #[cfg(debug_assertions)]
    println!("user_handle received from client: {:?}", &user_handle);

    let display_name = credential.user.display_name.as_str().to_owned();

    if credential.user.id != user_handle {
        return Err(PasskeyError::Authentication("User handle mismatch".into()));
    }

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);

    // Signature
    let signature = base64url_decode(&auth_response.response.signature)
        .map_err(|e| PasskeyError::Format(format!("Invalid signature: {}", e)))?;

    #[cfg(debug_assertions)]
    println!("Decoded signature length: {}", signature.len());

    // Prepare signed data
    let client_data_hash = digest::digest(&digest::SHA256, &client_data.raw_data);
    let mut signed_data = Vec::new();

    signed_data.extend_from_slice(&auth_data.raw_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    #[cfg(debug_assertions)]
    println!("Signed data length: {}", signed_data.len());

    // Verify signature using public key
    match public_key.verify(&signed_data, &signature) {
        Ok(_) => {
            #[cfg(debug_assertions)]
            println!("Signature verification successful");

            // Cleanup and return success
            challenge_store
                .remove_challenge(&auth_response.auth_id)
                .await?;
            Ok(display_name)
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            println!("Signature verification failed: {:?}", e);

            Err(PasskeyError::Verification(
                "Signature verification failed".into(),
            ))
        }
    }
}

#[derive(Debug)]
struct ParsedClientData {
    challenge: Vec<u8>,
    origin: String,
    type_: String,
    raw_data: Vec<u8>,
}

impl ParsedClientData {
    fn from_base64(client_data_json: &str) -> Result<Self, PasskeyError> {
        let raw_data = base64url_decode(client_data_json)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

        let data_str = String::from_utf8(raw_data.clone())
            .map_err(|e| PasskeyError::Format(format!("Invalid UTF-8: {}", e)))?;

        let data: serde_json::Value = serde_json::from_str(&data_str)
            .map_err(|e| PasskeyError::Format(format!("Invalid JSON: {}", e)))?;

        let challenge = base64url_decode(
            data["challenge"]
                .as_str()
                .ok_or_else(|| PasskeyError::ClientData("Missing challenge".into()))?,
        )
        .map_err(|e| PasskeyError::Format(format!("Invalid challenge: {}", e)))?;

        Ok(Self {
            challenge,
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

    fn verify(&self, state: &AppState, stored_challenge: &[u8]) -> Result<(), PasskeyError> {
        // Verify challenge
        if self.challenge != stored_challenge {
            return Err(PasskeyError::Challenge("Challenge mismatch".into()));
        }

        // Verify origin
        if self.origin != state.config.origin {
            return Err(PasskeyError::ClientData(format!(
                "Invalid origin. Expected: {}, Got: {}",
                state.config.origin, self.origin
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

#[derive(Debug)]
struct AuthenticatorData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    raw_data: Vec<u8>,
}

impl AuthenticatorData {
    fn from_base64(auth_data: &str) -> Result<Self, PasskeyError> {
        let data = base64url_decode(auth_data)
            .map_err(|e| PasskeyError::Format(format!("Failed to decode: {}", e)))?;

        if data.len() < 37 {
            return Err(PasskeyError::AuthenticatorData(
                "Authenticator data too short".into(),
            ));
        }

        Ok(Self {
            rp_id_hash: data[..32].to_vec(),
            flags: data[32],
            raw_data: data,
        })
    }

    fn verify(&self, state: &AppState) -> Result<(), PasskeyError> {
        // Verify RP ID hash
        let expected_hash = digest::digest(&digest::SHA256, state.config.rp_id.as_bytes());
        if self.rp_id_hash != expected_hash.as_ref() {
            return Err(PasskeyError::AuthenticatorData(format!(
                "Invalid RP ID hash. Expected: {:?}, Got: {:?}",
                expected_hash.as_ref(),
                self.rp_id_hash
            )));
        }

        // Check user presence flag
        if self.flags & 0x01 == 0 {
            return Err(PasskeyError::AuthenticatorData(
                "User presence flag not set".into(),
            ));
        }

        // Check user verification flag if required
        if state.config.authenticator_selection.user_verification == "required"
            && self.flags & 0x04 == 0
        {
            return Err(PasskeyError::AuthenticatorData(format!(
                "User verification required but flag not set. Flags: {:02x}",
                self.flags
            )));
        }

        Ok(())
    }
}
