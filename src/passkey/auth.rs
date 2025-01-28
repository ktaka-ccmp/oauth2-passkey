/// This module handles the authentication process using WebAuthn.
/// It provides routes for starting and verifying authentication.
///
/// The main components are:
/// - `router`: Sets up the routes for authentication.
/// - `start_authentication`: Initiates the authentication process by generating a challenge.
/// - `verify_authentication`: Verifies the authentication response from the client.
///
/// # Structures
/// - `AuthenticationOptions`: Represents the options for authentication.
/// - `AllowCredential`: Represents allowed credentials for authentication.
/// - `AuthenticateCredential`: Represents the credential data received from the client.
/// - `AuthenticatorAssertionResponse`: Represents the response from the authenticator.
///
/// # Functions
/// - `start_authentication`: Generates a challenge and returns authentication options.
/// - `verify_authentication`: Verifies the client's response to the authentication challenge.
///
/// # Errors
/// The functions return appropriate HTTP status codes and error messages in case of failures,
/// such as invalid client data, challenge verification failure, invalid origin, and invalid signature.
use axum::{
    extract::State,
    http::StatusCode,
    routing::{post, Router},
    Json,
};

use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::{digest, signature::UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::passkey::{
    base64url_decode, generate_challenge, AppState, PublicKeyCredentialUserEntity, StoredChallenge,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/start", post(start_authentication))
        .route(
            "/verify",
            post(|state, json| async move {
                match verify_authentication(state, json).await {
                    Ok(message) => (StatusCode::OK, message.to_string()),
                    Err((status, message)) => (status, message),
                }
            }),
        )
        .with_state(state)
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AuthenticationOptions {
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
struct AuthenticatorResponse {
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

async fn start_authentication(State(state): State<AppState>) -> Json<AuthenticationOptions> {
    let challenge = generate_challenge();

    let user_info = PublicKeyCredentialUserEntity {
        id: "".to_string(),
        name: "".to_string(),
        display_name: "".to_string(),
    };

    let auth_id = Uuid::new_v4().to_string();
    let stored_challenge = StoredChallenge {
        challenge: challenge.clone(),
        user: user_info,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut store = state.store.lock().await;
    store.challenges.insert(auth_id.clone(), stored_challenge);

    // let allow_credentials: Vec<_> = store
    //     .credentials
    //     .keys()
    //     .map(|id| AllowCredential {
    //         type_: "public-key".to_string(),
    //         id: id.clone(), // ID is already base64url encoded
    //     })
    //     .collect();

    // let allow_credentials: Vec<AllowCredential> = Vec::new();
    // #[cfg(debug_assertions)]
    // println!("Available credentials: {:?}", allow_credentials);

    let auth_option = AuthenticationOptions {
        challenge: URL_SAFE.encode(&challenge),
        timeout: 60000,
        rp_id: state.config.rp_id.clone(),
        allow_credentials: vec![],
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
            return Err(WebAuthnError::InvalidClientData("Invalid origin".into()));
        }

        // Verify type
        if self.type_ != "webauthn.get" {
            return Err(WebAuthnError::InvalidClientData("Invalid type".into()));
        }

        Ok(())
    }
}

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
            return Err(WebAuthnError::InvalidAuthenticator(
                "Invalid RP ID hash".into(),
            ));
        }

        // Verify user presence
        if self.flags & 0x01 != 0x01 {
            return Err(WebAuthnError::InvalidAuthenticator(
                "User presence not verified".into(),
            ));
        }

        // Verify user verification if required
        if state.config.authenticator_selection.user_verification == "required"
            && self.flags & 0x04 != 0x04
        {
            return Err(WebAuthnError::InvalidAuthenticator(
                "User verification required".into(),
            ));
        }

        Ok(())
    }
}

async fn verify_authentication(
    State(state): State<AppState>,
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    // Get stored challenge and verify auth
    let mut store = state.store.lock().await;
    let stored_challenge = store
        .challenges
        .get(&auth_response.auth_id)
        .ok_or(WebAuthnError::StorageError("Challenge not found".into()))?;

    // Verify authenticator attachment if specified
    let expected = state
        .config
        .authenticator_selection
        .authenticator_attachment
        .clone();

    let received = auth_response.authenticator_attachment.as_deref();

    #[cfg(debug_assertions)]
    println!(
        "Expected attachment: {:?}, received attachment: {:?}",
        expected, received
    );

    if expected.is_some() && expected.as_deref() != received {
        return Err(WebAuthnError::InvalidAuthenticator("Invalid attachment".into()).into());
    }

    // Parse and verify client data
    let client_data = ParsedClientData::from_base64(&auth_response.response.client_data_json)?;
    client_data.verify(&state, &stored_challenge.challenge)?;

    // Parse and verify authenticator data
    let auth_data = AuthenticatorData::from_base64(&auth_response.response.authenticator_data)?;
    auth_data.verify(&state)?;

    // #1. Get credential then public key
    let credential = store
        .credentials
        .get(&auth_response.id)
        .ok_or(WebAuthnError::InvalidSignature("Unknown credential".into()))?;

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

    // #2. Signature
    let signature = base64url_decode(&auth_response.response.signature)
        .map_err(|e| WebAuthnError::InvalidSignature(format!("Invalid signature: {}", e)))?;

    // #3. Prepare signed data
    let client_data_hash = digest::digest(&digest::SHA256, &client_data.raw_data);
    let mut signed_data = Vec::new();

    signed_data.extend_from_slice(&auth_data.raw_data);
    signed_data.extend_from_slice(client_data_hash.as_ref());

    // Verify signature using #1, #2 and #3
    public_key
        .verify(&signed_data, &signature)
        .map_err(|_| WebAuthnError::InvalidSignature("Signature verification failed".into()))?;

    // Cleanup and return success
    store.challenges.remove(&auth_response.auth_id);

    Ok(display_name)
}
