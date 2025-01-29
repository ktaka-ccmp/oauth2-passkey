use axum::{extract::State, http::StatusCode, Json};

use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::{Integer, Value as CborValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::passkey::AppState;
use crate::{
    config::AuthenticatorSelection,
    passkey::{
        base64url_decode, generate_challenge, AttestationObject, PublicKeyCredentialUserEntity,
        StoredChallenge, StoredCredential,
    },
};

#[derive(Serialize, Debug)]
struct PubKeyCredParam {
    #[serde(rename = "type")]
    type_: String,
    alg: i32,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOptions {
    challenge: String,
    rp_id: String,
    rp: RelyingParty,
    user: PublicKeyCredentialUserEntity,
    pub_key_cred_params: Vec<PubKeyCredParam>,
    authenticator_selection: AuthenticatorSelection,
    timeout: u32,
    attestation: String,
}

#[derive(Serialize, Debug)]
struct RelyingParty {
    name: String,
    id: String,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct RegisterCredential {
    id: String,
    raw_id: String,
    response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    type_: String,
    username: Option<String>,
    user_handle: Option<String>,
}

#[derive(Deserialize, Debug)]
struct AuthenticatorAttestationResponse {
    client_data_json: String,
    attestation_object: String,
}

pub async fn start_registration(
    State(state): State<AppState>,
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
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

    let mut store = state.store.lock().await;
    store
        .challenges
        .insert(user_info.id.clone(), stored_challenge);

    let options = RegistrationOptions {
        challenge: URL_SAFE.encode(challenge.unwrap_or_default()),
        rp_id: state.config.rp_id.clone(),
        rp: RelyingParty {
            name: "Passkey Demo".to_string(),
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

    #[cfg(not(debug_assertions))]
    println!("Debugging disabled");

    #[cfg(debug_assertions)]
    println!("Registration options: {:?}", options);

    Json(options)
}

pub async fn finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<&'static str, (StatusCode, String)> {
    println!("Registering user: {:?}", reg_data);
    let mut store = state.store.lock().await;

    verify_client_data(&state, &reg_data, &store).await?;

    let public_key = extract_credential_public_key(&reg_data, &state)?;

    // Decode and store credential
    let credential_id = base64url_decode(&reg_data.raw_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode credential ID: {}", e),
        )
    })?;

    let user_handle = reg_data.user_handle.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "User handle is missing".to_string(),
    ))?;
    let stored_user = store
        .challenges
        .get(user_handle)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "No challenge found for this user".to_string(),
        ))?
        .user
        .clone();

    // let username = stored_user.name.clone();

    // Store using base64url encoded credential_id as the key
    // let credential_id_str = URL_SAFE.encode(&credential_id);
    let credential_id_str = reg_data.raw_id.clone();
    store.credentials.insert(
        credential_id_str, // Use this as the key instead of reg_data.id
        StoredCredential {
            credential_id,
            public_key,
            counter: 0,
            user: stored_user,
        },
    );

    // Remove used challenge
    store.challenges.remove(user_handle);

    Ok("Registration successful")
}

fn extract_credential_public_key(
    reg_data: &RegisterCredential,
    state: &AppState,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let decoded_client_data =
        base64url_decode(&reg_data.response.client_data_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode client data: {}", e),
            )
        })?;

    let decoded_client_data_json = String::from_utf8(decoded_client_data.clone())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Client data is not valid UTF-8: {}", e),
            )
        })
        .and_then(|s: String| {
            serde_json::from_str::<serde_json::Value>(&s).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to parse client data JSON: {}", e),
                )
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

fn parse_attestation_object(
    attestation_base64: &str,
) -> Result<AttestationObject, (StatusCode, String)> {
    let attestation_bytes = base64url_decode(attestation_base64).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode attestation object: {}", e),
        )
    })?;

    let attestation_cbor: CborValue = ciborium::de::from_reader(&attestation_bytes[..])
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid CBOR data: {}", e)))?;

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
            _ => Err((
                StatusCode::BAD_REQUEST,
                "Missing required attestation data".to_string(),
            )),
        }
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "Invalid attestation format".to_string(),
        ))
    }
}

fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Result<Vec<u8>, (StatusCode, String)> {
    // Check attested credential data flag
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;
    if !has_attested_cred_data {
        return Err((
            StatusCode::BAD_REQUEST,
            "No attested credential data present".to_string(),
        ));
    }

    // Parse credential data
    let credential_data = parse_credential_data(auth_data)?;

    // Extract public key coordinates
    let (x_coord, y_coord) = extract_key_coordinates(credential_data)?;

    // Format public key
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point format
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    Ok(public_key)
}

fn parse_credential_data(auth_data: &[u8]) -> Result<&[u8], (StatusCode, String)> {
    let mut pos = 37; // Skip RP ID hash (32) + flags (1) + counter (4)

    if auth_data.len() < pos + 18 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Authenticator data too short".to_string(),
        ));
    }

    pos += 16; // Skip AAGUID

    // Get credential ID length
    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2;

    if cred_id_len == 0 || cred_id_len > 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential ID length".to_string(),
        ));
    }

    if auth_data.len() < pos + cred_id_len {
        return Err((
            StatusCode::BAD_REQUEST,
            "Authenticator data too short for credential ID".to_string(),
        ));
    }

    pos += cred_id_len;

    Ok(&auth_data[pos..])
}

fn extract_key_coordinates(
    credential_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), (StatusCode, String)> {
    let public_key_cbor: CborValue = ciborium::de::from_reader(credential_data).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key CBOR: {}", e),
        )
    })?;

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
            _ => Err((
                StatusCode::BAD_REQUEST,
                "Missing or invalid key coordinates".to_string(),
            )),
        }
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "Invalid public key format".to_string(),
        ))
    }
}

async fn verify_client_data(
    state: &AppState,
    reg_data: &RegisterCredential,
    store: &tokio::sync::MutexGuard<'_, super::AuthStore>,
) -> Result<(), (StatusCode, String)> {
    // Decode and verify client data
    let decoded_client_data =
        base64url_decode(&reg_data.response.client_data_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode client data: {}", e),
            )
        })?;

    let client_data_str = String::from_utf8(decoded_client_data.clone()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Client data is not valid UTF-8: {}", e),
        )
    })?;

    let client_data: serde_json::Value = serde_json::from_str(&client_data_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid client data JSON: {}", e),
        )
    })?;

    let origin = client_data["origin"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing origin in client data".to_string(),
    ))?;

    if origin != state.config.origin {
        return Err((StatusCode::BAD_REQUEST, "Invalid origin".to_string()));
    }

    let type_ = client_data["type"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing type in client data".to_string(),
    ))?;

    if type_ != "webauthn.create" {
        return Err((StatusCode::BAD_REQUEST, "Invalid type".to_string()));
    }

    let challenge = client_data["challenge"].as_str().ok_or((
        StatusCode::BAD_REQUEST,
        "Missing challenge in client data".to_string(),
    ))?;

    let decoded_challenge = base64url_decode(challenge).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to decode challenge: {}", e),
        )
    })?;

    let user_handle = reg_data.user_handle.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "User handle is missing".to_string(),
    ))?;

    let stored_challenge = store.challenges.get(user_handle).ok_or((
        StatusCode::BAD_REQUEST,
        "No challenge found for this user".to_string(),
    ))?;

    if decoded_challenge != stored_challenge.challenge {
        return Err((
            StatusCode::BAD_REQUEST,
            "Challenge verification failed".to_string(),
        ));
    }

    Ok(())
}
