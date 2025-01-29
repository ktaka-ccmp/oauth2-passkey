use axum::{extract::State, http::StatusCode, Json};

use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::{digest, signature::UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::passkey::{
    base64url_decode, generate_challenge, AppState, PublicKeyCredentialUserEntity, StoredChallenge,
};

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
    #[serde(rename = "type")]
    type_: String,
    id: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct AuthenticatorResponse {
    id: String,
    raw_id: String,
    response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    type_: String,
    auth_id: String,
    authenticator_attachment: Option<String>,
}

#[derive(Deserialize, Debug)]
struct AuthenticatorAssertionResponse {
    authenticator_data: String,
    client_data_json: String,
    signature: String,
    user_handle: Option<String>,
}

pub async fn start_authentication(State(state): State<AppState>) -> Json<AuthenticationOptions> {
    let challenge = generate_challenge();

    let user_info = PublicKeyCredentialUserEntity {
        id: "".to_string(),
        name: "".to_string(),
        display_name: "".to_string(),
    };

    let auth_id = Uuid::new_v4().to_string();
    let stored_challenge = StoredChallenge {
        challenge: challenge.clone().unwrap_or_default(),
        user: user_info,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut store = state.store.lock().await;
    store.challenges.insert(auth_id.clone(), stored_challenge);

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
    Json(auth_option)
}

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("Invalid client data: {0}")]
    InvalidClientData(String),
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    #[error("Invalid authenticator: {0}")]
    InvalidAuthenticator(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

impl From<WebAuthnError> for (StatusCode, String) {
    fn from(err: WebAuthnError) -> Self {
        (StatusCode::BAD_REQUEST, err.to_string())
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
    fn from_base64(client_data_json: &str) -> Result<Self, WebAuthnError> {
        let raw_data = base64url_decode(client_data_json)
            .map_err(|e| WebAuthnError::InvalidClientData(format!("Failed to decode: {}", e)))?;

        let data_str = String::from_utf8(raw_data.clone())
            .map_err(|e| WebAuthnError::InvalidClientData(format!("Invalid UTF-8: {}", e)))?;

        let data: serde_json::Value = serde_json::from_str(&data_str)
            .map_err(|e| WebAuthnError::InvalidClientData(format!("Invalid JSON: {}", e)))?;

        let challenge = base64url_decode(
            data["challenge"]
                .as_str()
                .ok_or_else(|| WebAuthnError::InvalidClientData("Missing challenge".into()))?,
        )
        .map_err(|e| WebAuthnError::InvalidClientData(format!("Invalid challenge: {}", e)))?;

        Ok(Self {
            challenge,
            origin: data["origin"]
                .as_str()
                .ok_or_else(|| WebAuthnError::InvalidClientData("Missing origin".into()))?
                .to_string(),
            type_: data["type"]
                .as_str()
                .ok_or_else(|| WebAuthnError::InvalidClientData("Missing type".into()))?
                .to_string(),
            raw_data,
        })
    }

    fn verify(&self, state: &AppState, stored_challenge: &[u8]) -> Result<(), WebAuthnError> {
        // Verify challenge
        if self.challenge != stored_challenge {
            return Err(WebAuthnError::InvalidChallenge("Challenge mismatch".into()));
        }

        // Verify origin
        if self.origin != state.config.origin {
            return Err(WebAuthnError::InvalidClientData(format!(
                "Invalid origin. Expected: {}, Got: {}",
                state.config.origin, self.origin
            )));
        }

        // Verify type for authentication
        if self.type_ != "webauthn.get" {
            return Err(WebAuthnError::InvalidClientData(format!(
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
    fn from_base64(auth_data: &str) -> Result<Self, WebAuthnError> {
        let data = base64url_decode(auth_data)
            .map_err(|e| WebAuthnError::InvalidAuthenticator(format!("Failed to decode: {}", e)))?;

        if data.len() < 37 {
            return Err(WebAuthnError::InvalidAuthenticator(
                "Authenticator data too short".into(),
            ));
        }

        Ok(Self {
            rp_id_hash: data[..32].to_vec(),
            flags: data[32],
            raw_data: data,
        })
    }

    fn verify(&self, state: &AppState) -> Result<(), WebAuthnError> {
        // Verify RP ID hash
        let expected_hash = digest::digest(&digest::SHA256, state.config.rp_id.as_bytes());
        if self.rp_id_hash != expected_hash.as_ref() {
            return Err(WebAuthnError::InvalidAuthenticator(format!(
                "Invalid RP ID hash. Expected: {:?}, Got: {:?}",
                expected_hash.as_ref(),
                self.rp_id_hash
            )));
        }

        // Check user presence flag
        if self.flags & 0x01 == 0 {
            return Err(WebAuthnError::InvalidAuthenticator(
                "User presence flag not set".into(),
            ));
        }

        // Check user verification flag if required
        if state.config.authenticator_selection.user_verification == "required"
            && self.flags & 0x04 == 0
        {
            return Err(WebAuthnError::InvalidAuthenticator(format!(
                "User verification required but flag not set. Flags: {:02x}",
                self.flags
            )));
        }

        Ok(())
    }
}

pub async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    #[cfg(debug_assertions)]
    println!(
        "Starting authentication verification for response: {:?}",
        auth_response
    );

    // Get stored challenge and verify auth
    let mut store = state.store.lock().await;
    let stored_challenge = store
        .challenges
        .get(&auth_response.auth_id)
        .ok_or(WebAuthnError::StorageError("Challenge not found".into()))?;

    #[cfg(debug_assertions)]
    println!("Found stored challenge: {:?}", stored_challenge);

    // Verify authenticator attachment if specified
    let expected = state
        .config
        .authenticator_selection
        .authenticator_attachment
        .clone();

    let received = auth_response.authenticator_attachment.unwrap_or_default();

    #[cfg(debug_assertions)]
    println!(
        "Expected attachment: {:?}, received attachment: {:?}",
        expected, received
    );

    if expected != received {
        return Err(WebAuthnError::InvalidAuthenticator("Invalid attachment".into()).into());
    }

    // Parse and verify client data
    #[cfg(debug_assertions)]
    println!(
        "Parsing client data: {}",
        &auth_response.response.client_data_json
    );

    let client_data = ParsedClientData::from_base64(&auth_response.response.client_data_json)?;

    #[cfg(debug_assertions)]
    println!("Parsed client data: {:?}", client_data);

    client_data.verify(&state, &stored_challenge.challenge)?;

    // Parse and verify authenticator data
    #[cfg(debug_assertions)]
    println!(
        "Parsing authenticator data: {}",
        &auth_response.response.authenticator_data
    );

    let auth_data = AuthenticatorData::from_base64(&auth_response.response.authenticator_data)?;

    #[cfg(debug_assertions)]
    println!("Parsed authenticator data: {:?}", auth_data);

    auth_data.verify(&state)?;

    // Get credential then public key
    let credential = store
        .credentials
        .get(&auth_response.id)
        .ok_or(WebAuthnError::InvalidSignature("Unknown credential".into()))?;

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
        return Err(WebAuthnError::InvalidSignature("User handle mismatch".into()).into());
    }

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &credential.public_key);

    // Signature
    let signature = base64url_decode(&auth_response.response.signature)
        .map_err(|e| WebAuthnError::InvalidSignature(format!("Invalid signature: {}", e)))?;

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
            store.challenges.remove(&auth_response.auth_id);
            Ok(display_name)
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            println!("Signature verification failed: {:?}", e);

            Err(WebAuthnError::InvalidSignature("Signature verification failed".into()).into())
        }
    }
}
