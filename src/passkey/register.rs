use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::{Integer, Value as CborValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AuthenticatorSelection;
use crate::errors::PasskeyError;
use crate::passkey::{base64url_decode, generate_challenge};
use crate::passkey::{
    AppState, AttestationObject, PublicKeyCredentialUserEntity, StoredChallenge, StoredCredential,
};

#[derive(Serialize, Debug)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOptions {
    pub challenge: String,
    pub rp_id: String,
    pub rp: RelyingParty,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub authenticator_selection: AuthenticatorSelection,
    pub timeout: u32,
    pub attestation: String,
}

#[derive(Serialize, Debug)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct RegisterCredential {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub type_: String,
    pub username: Option<String>,
    pub user_handle: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

pub async fn start_registration(
    state: &AppState,
    username: String,
) -> Result<RegistrationOptions, PasskeyError> {
    println!("Registering user: {}", username);

    let user_info = PublicKeyCredentialUserEntity {
        id: Uuid::new_v4().to_string(),
        name: username.clone(),
        display_name: username.clone(),
    };

    let challenge = generate_challenge();

    let stored_challenge = StoredChallenge {
        challenge: challenge.clone().unwrap_or_default(),
        user: user_info.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Store the challenge
    let mut challenge_store = state.challenge_store.lock().await;
    challenge_store
        .store_challenge(user_info.id.clone(), stored_challenge)
        .await?;

    let options = RegistrationOptions {
        challenge: URL_SAFE.encode(challenge.unwrap_or_default()),
        rp_id: state.config.rp_id.clone(),
        rp: RelyingParty {
            name: state.config.rp_name.clone(),
            id: state.config.rp_id.clone(),
        },
        user: user_info,
        pub_key_cred_params: vec![
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -7,
            },
            PubKeyCredParam {
                type_: "public-key".to_string(),
                alg: -257,
            },
        ],
        authenticator_selection: state.config.authenticator_selection.clone(),
        timeout: 60000,
        attestation: "direct".to_string(),
    };

    #[cfg(debug_assertions)]
    println!("Registration options: {:?}", options);

    Ok(options)
}

pub async fn finish_registration(
    state: &AppState,
    reg_data: RegisterCredential,
) -> Result<String, PasskeyError> {
    println!("Registering user: {:?}", reg_data);
    let mut challenge_store = state.challenge_store.lock().await;
    let mut credential_store = state.credential_store.lock().await;

    verify_client_data(state, &reg_data, &challenge_store).await?;

    let public_key = extract_credential_public_key(&reg_data, state)?;

    // Decode and store credential
    let credential_id = base64url_decode(&reg_data.raw_id)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode credential ID: {}", e)))?;

    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let stored_challenge =
        challenge_store
            .get_challenge(user_handle)
            .await?
            .ok_or(PasskeyError::Storage(
                "No challenge found for this user".to_string(),
            ))?;

    let stored_user = stored_challenge.user.clone();

    // Store using base64url encoded credential_id as the key
    let credential_id_str = reg_data.raw_id.clone();
    credential_store
        .store_credential(
            credential_id_str,
            StoredCredential {
                credential_id,
                public_key,
                counter: 0,
                user: stored_user,
            },
        )
        .await?;

    // Remove used challenge
    challenge_store.remove_challenge(user_handle).await?;

    Ok("Registration successful".to_string())
}

fn extract_credential_public_key(
    reg_data: &RegisterCredential,
    state: &AppState,
) -> Result<Vec<u8>, PasskeyError> {
    let decoded_client_data = base64url_decode(&reg_data.response.client_data_json)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode client data: {}", e)))?;

    let decoded_client_data_json = String::from_utf8(decoded_client_data.clone())
        .map_err(|e| PasskeyError::Format(format!("Client data is not valid UTF-8: {}", e)))
        .and_then(|s: String| {
            serde_json::from_str::<serde_json::Value>(&s).map_err(|e| {
                PasskeyError::Format(format!("Failed to parse client data JSON: {}", e))
            })
        })?;

    println!("Client data json: {:?}", decoded_client_data_json);

    let attestation_obj = parse_attestation_object(&reg_data.response.attestation_object)?;

    // Verify attestation based on format
    crate::passkey::attestation::verify_attestation(&attestation_obj, &decoded_client_data, state)?;

    // Extract public key from authenticator data
    let public_key = extract_public_key_from_auth_data(&attestation_obj.auth_data)?;

    Ok(public_key)
}

fn parse_attestation_object(attestation_base64: &str) -> Result<AttestationObject, PasskeyError> {
    let attestation_bytes = base64url_decode(attestation_base64)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode attestation object: {}", e)))?;

    let attestation_cbor: CborValue = ciborium::de::from_reader(&attestation_bytes[..])
        .map_err(|e| PasskeyError::Format(format!("Invalid CBOR data: {}", e)))?;

    if let CborValue::Map(map) = attestation_cbor {
        let mut fmt = None;
        let mut auth_data = None;
        let mut att_stmt = None;

        for (key, value) in map {
            if let CborValue::Text(k) = key {
                match k.as_str() {
                    "fmt" => {
                        if let CborValue::Text(f) = value {
                            fmt = Some(f);
                        }
                    }
                    "authData" => {
                        if let CborValue::Bytes(data) = value {
                            auth_data = Some(data);
                        }
                    }
                    "attStmt" => {
                        if let CborValue::Map(stmt) = value {
                            att_stmt = Some(stmt);
                        }
                    }
                    _ => {}
                }
            }
        }

        #[cfg(debug_assertions)]
        println!(
            "Attestation format: {:?}, auth data: {:?}, attestation statement: {:?}",
            fmt, auth_data, att_stmt
        );

        match (fmt, auth_data, att_stmt) {
            (Some(f), Some(d), Some(s)) => Ok(AttestationObject {
                fmt: f,
                auth_data: d,
                att_stmt: s,
            }),
            _ => Err(PasskeyError::Format(
                "Missing required attestation data".to_string(),
            )),
        }
    } else {
        Err(PasskeyError::Format(
            "Invalid attestation format".to_string(),
        ))
    }
}

fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    // Check attested credential data flag
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;
    if !has_attested_cred_data {
        return Err(PasskeyError::AuthenticatorData(
            "No attested credential data present".to_string(),
        ));
    }

    // Parse credential data
    let credential_data = parse_credential_data(auth_data)?;

    // Extract public key coordinates
    let (x_coord, y_coord) = extract_key_coordinates(credential_data)?;

    // Concatenate x and y coordinates for public key
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point format
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    Ok(public_key)
}

fn parse_credential_data(auth_data: &[u8]) -> Result<&[u8], PasskeyError> {
    let mut pos = 37; // Skip RP ID hash (32) + flags (1) + counter (4)

    if auth_data.len() < pos + 18 {
        return Err(PasskeyError::Format(
            "Authenticator data too short".to_string(),
        ));
    }

    pos += 16; // Skip AAGUID

    // Get credential ID length
    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2;

    if cred_id_len == 0 || cred_id_len > 1024 {
        return Err(PasskeyError::Format(
            "Invalid credential ID length".to_string(),
        ));
    }

    if auth_data.len() < pos + cred_id_len {
        return Err(PasskeyError::Format(
            "Authenticator data too short for credential ID".to_string(),
        ));
    }

    pos += cred_id_len;

    Ok(&auth_data[pos..])
}

fn extract_key_coordinates(credential_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
    let public_key_cbor: CborValue = ciborium::de::from_reader(credential_data)
        .map_err(|e| PasskeyError::Format(format!("Invalid public key CBOR: {}", e)))?;

    if let CborValue::Map(map) = public_key_cbor {
        let mut x_coord = None;
        let mut y_coord = None;

        for (key, value) in map {
            if let CborValue::Integer(i) = key {
                if i == Integer::from(-2) {
                    if let CborValue::Bytes(x) = value {
                        x_coord = Some(x);
                    }
                } else if i == Integer::from(-3) {
                    if let CborValue::Bytes(y) = value {
                        y_coord = Some(y);
                    }
                }
            }
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => Ok((x, y)),
            _ => Err(PasskeyError::Format(
                "Missing or invalid key coordinates".to_string(),
            )),
        }
    } else {
        Err(PasskeyError::Format(
            "Invalid public key format".to_string(),
        ))
    }
}

async fn verify_client_data(
    state: &AppState,
    reg_data: &RegisterCredential,
    store: &tokio::sync::MutexGuard<'_, Box<dyn crate::storage::ChallengeStore>>,
) -> Result<(), PasskeyError> {
    // Decode and verify client data
    let decoded_client_data = base64url_decode(&reg_data.response.client_data_json)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode client data: {}", e)))?;

    let client_data_str = String::from_utf8(decoded_client_data.clone())
        .map_err(|e| PasskeyError::Format(format!("Client data is not valid UTF-8: {}", e)))
        .and_then(|s: String| {
            serde_json::from_str::<serde_json::Value>(&s).map_err(|e| {
                PasskeyError::Format(format!("Failed to parse client data JSON: {}", e))
            })
        })?;

    let origin = client_data_str["origin"]
        .as_str()
        .ok_or(PasskeyError::ClientData(
            "Missing origin in client data".to_string(),
        ))?;

    if origin != state.config.origin {
        return Err(PasskeyError::ClientData("Invalid origin".to_string()));
    }

    let type_ = client_data_str["type"]
        .as_str()
        .ok_or(PasskeyError::ClientData(
            "Missing type in client data".to_string(),
        ))?;

    if type_ != "webauthn.create" {
        return Err(PasskeyError::ClientData("Invalid type".to_string()));
    }

    let challenge = client_data_str["challenge"]
        .as_str()
        .ok_or(PasskeyError::ClientData(
            "Missing challenge in client data".to_string(),
        ))?;

    let decoded_challenge = base64url_decode(challenge)
        .map_err(|e| PasskeyError::Format(format!("Failed to decode challenge: {}", e)))?;

    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let stored_challenge = store
        .get_challenge(user_handle)
        .await?
        .ok_or(PasskeyError::Storage(
            "No challenge found for this user".to_string(),
        ))?;

    if decoded_challenge != stored_challenge.challenge {
        return Err(PasskeyError::Challenge(
            "Challenge verification failed".to_string(),
        ));
    }

    Ok(())
}
