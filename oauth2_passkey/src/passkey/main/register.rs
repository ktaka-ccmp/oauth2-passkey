use chrono::Utc;
use ciborium::value::{Integer, Value as CborValue};

use crate::session::User as SessionUser;

use super::aaguid::{AuthenticatorInfo, get_authenticator_info};
use super::attestation::{extract_aaguid, verify_attestation};
use super::challenge::{get_and_validate_options, remove_options};
use super::types::{
    AttestationObject, AuthenticatorSelection, PubKeyCredParam, RegisterCredential,
    RegistrationOptions, RelyingParty, WebAuthnClientData,
};
use super::utils::{get_from_cache, remove_from_cache, store_in_cache};

use crate::passkey::config::{
    ORIGIN, PASSKEY_ATTESTATION, PASSKEY_AUTHENTICATOR_ATTACHMENT, PASSKEY_CHALLENGE_TIMEOUT,
    PASSKEY_REQUIRE_RESIDENT_KEY, PASSKEY_RESIDENT_KEY, PASSKEY_RP_ID, PASSKEY_RP_NAME,
    PASSKEY_TIMEOUT, PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL, PASSKEY_USER_VERIFICATION,
};
use crate::passkey::errors::PasskeyError;
use crate::passkey::storage::PasskeyStore;
use crate::passkey::types::{
    CredentialSearchField, PasskeyCredential, PublicKeyCredentialUserEntity, SessionInfo,
    StoredOptions,
};

use crate::utils::{base64url_decode, base64url_encode, gen_random_string};

/// Resolves a user handle for passkey registration
///
/// Behavior depends on the PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL setting:
///
/// - When true: Always generates a unique user handle for each credential,
///   allowing a user to have multiple credentials per site.
///
/// - When false: Reuses the user handle for logged-in users with existing credentials,
///   which enforces a one-to-one relationship between users and credentials per site.
///   This maintains compatibility with password managers that don't support multiple
///   credentials per user handle.
async fn get_or_create_user_handle(
    session_user: &Option<SessionUser>,
) -> Result<String, PasskeyError> {
    // If configured to always use unique user handles, generate a new one regardless of user state
    if *PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL {
        let new_handle = gen_random_string(32)?;
        tracing::debug!(
            "Using unique user handle for every credential: {}",
            new_handle
        );
        return Ok(new_handle);
    }

    // Otherwise, follow the normal logic of reusing handles for logged-in users
    if let Some(user) = session_user {
        tracing::debug!("User is logged in: {:#?}", user);

        // Try to find existing credentials for this user
        let existing_credentials =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user.id.clone()))
                .await?;

        if !existing_credentials.is_empty() {
            // Reuse the existing user_handle from the first credential
            let existing_handle = existing_credentials[0].user.user_handle.clone();
            tracing::debug!("Reusing existing user handle: {}", existing_handle);
            Ok(existing_handle)
        } else {
            // No existing credentials, generate a new user_handle
            let new_handle = gen_random_string(32)?;
            tracing::debug!(
                "No existing credentials found, generating new user handle: {}",
                new_handle
            );
            Ok(new_handle)
        }
    } else {
        // User is not logged in, generate a new user_handle
        let new_handle = gen_random_string(32)?;
        tracing::debug!(
            "User not logged in, generating new user handle: {}",
            new_handle
        );
        Ok(new_handle)
    }
}

pub(crate) async fn start_registration(
    session_user: Option<SessionUser>,
    username: String,
    displayname: String,
) -> Result<RegistrationOptions, PasskeyError> {
    // Get or create a user handle
    let user_handle = get_or_create_user_handle(&session_user).await?;

    if let Some(u) = session_user {
        tracing::debug!("User: {:#?}", u);
        let session_info = SessionInfo { user: u };
        store_in_cache(
            "session_info",
            &user_handle,
            session_info,
            *PASSKEY_CHALLENGE_TIMEOUT as usize,
        )
        .await?;
    }

    let user_info = PublicKeyCredentialUserEntity {
        user_handle,
        name: username.clone(),
        display_name: displayname.clone(),
    };

    let options = create_registration_options(user_info).await?;

    Ok(options)
}

async fn create_registration_options(
    user_info: PublicKeyCredentialUserEntity,
) -> Result<RegistrationOptions, PasskeyError> {
    let challenge_str = gen_random_string(32)?;
    let stored_challenge = StoredOptions {
        challenge: challenge_str.clone(),
        user: user_info.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl: *PASSKEY_CHALLENGE_TIMEOUT as u64,
    };

    store_in_cache(
        "regi_challenge",
        &user_info.user_handle,
        stored_challenge,
        *PASSKEY_CHALLENGE_TIMEOUT as usize,
    )
    .await?;

    let authenticator_selection = AuthenticatorSelection {
        authenticator_attachment: PASSKEY_AUTHENTICATOR_ATTACHMENT.to_string(),
        resident_key: PASSKEY_RESIDENT_KEY.to_string(),
        require_resident_key: *PASSKEY_REQUIRE_RESIDENT_KEY,
        user_verification: PASSKEY_USER_VERIFICATION.to_string(),
    };

    let options = RegistrationOptions {
        challenge: challenge_str,
        rp_id: PASSKEY_RP_ID.to_string(),
        rp: RelyingParty {
            name: PASSKEY_RP_NAME.to_string(),
            id: PASSKEY_RP_ID.to_string(),
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
        authenticator_selection,
        timeout: (*PASSKEY_TIMEOUT) * 1000, // Convert seconds to milliseconds
        attestation: PASSKEY_ATTESTATION.to_string(),
    };

    tracing::debug!("Registration options: {:?}", options);

    Ok(options)
}

pub(crate) async fn verify_session_then_finish_registration(
    session_user: SessionUser,
    reg_data: RegisterCredential,
) -> Result<String, PasskeyError> {
    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let session_info: SessionInfo = get_from_cache("session_info", user_handle)
        .await?
        .ok_or(PasskeyError::NotFound("Session not found".to_string()))?;

    // Delete the session info from the store
    remove_from_cache("session_info", user_handle).await?;

    tracing::trace!("session_info.user.id: {:#?}", session_info.user.id);
    tracing::trace!("session_user.id: {:#?}", session_user.id);
    tracing::trace!("reg_data.user_handle: {:#?}", reg_data.user_handle);

    // Verify the user is the same as the one in the cache store i.e. used to start the registration
    if session_user.id != session_info.user.id {
        return Err(PasskeyError::Format("User ID mismatch".to_string()));
    }

    finish_registration(&session_user.id, &reg_data).await?;

    Ok("Registration successful".to_string())
}

/// Finishes the registration process by storing the credential
///
/// 1. Verifies the client data
/// 2. Extracts the public key
/// 3. Validates the options
/// 4. Stores the credential
///
pub(crate) async fn finish_registration(
    user_id: &str,
    reg_data: &RegisterCredential,
) -> Result<String, PasskeyError> {
    tracing::debug!("finish_registration user: {:?}", reg_data);

    verify_client_data(reg_data).await?;

    let public_key = extract_credential_public_key(reg_data)?;

    let user_handle = reg_data
        .user_handle
        .as_deref()
        .ok_or(PasskeyError::ClientData(
            "User handle is missing".to_string(),
        ))?;

    let stored_options = get_and_validate_options("regi_challenge", user_handle).await?;
    let stored_user = stored_options.user.clone();

    let credential_id_str = reg_data.raw_id.clone();

    let attestation_obj = parse_attestation_object(&reg_data.response.attestation_object)?;
    let aaguid = extract_aaguid(&attestation_obj)?;
    tracing::trace!("AAGUID: {}", aaguid);

    let authenticator_info = match get_authenticator_info(&aaguid).await? {
        Some(info) => info,
        None => {
            tracing::warn!("Authenticator info not found for AAGUID: {}", aaguid);
            AuthenticatorInfo {
                name: "Unknown".to_string(),
                icon_dark: None,
                icon_light: None,
            }
        }
    };

    tracing::trace!("Authenticator info: {:#?}", authenticator_info);

    if !*PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL {
        // If PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL is true,
        //there isn't any pre-existing credentials with this user handle to begin with.
        // Therefore, we can skip the deletion step, I think.

        // Important todo: we delete credentials for a combination of "AAGUID" and user_handle
        // But we can't distinguish multiple authenticators of the same type,
        // e.g. Google Password Managers for different accounts or two Yubikeys with the same model.
        //
        // Current implementation will overwrite existing credentials for the same AAGUID regardless of difference in actual authenticator.

        let credentials_with_matching_handle = match PasskeyStore::get_credentials_by(
            CredentialSearchField::UserHandle(user_handle.to_string()),
        )
        .await
        {
            Ok(creds) => creds,
            Err(e) => {
                tracing::warn!(
                    "Error getting credentials for user handle {}: {}",
                    user_handle,
                    e
                );
                // Continue with registration - don't fail just because we couldn't get existing credentials
                vec![]
            }
        };

        // Filter and delete credentials that match user_handle, user_id, and aaguid
        for cred in credentials_with_matching_handle {
            if cred.aaguid == aaguid && cred.user_id == user_id {
                match PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
                    cred.credential_id.clone(),
                ))
                .await
                {
                    Ok(_) => {
                        tracing::info!(
                            "Removed existing credential with matching user_handle, user_id, and aaguid: {}",
                            cred.credential_id
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Error removing existing credential {}: {}",
                            cred.credential_id,
                            e
                        );
                        // Continue with registration - don't fail just because we couldn't remove existing credentials
                    }
                }
            }
        }
    }

    let credential = PasskeyCredential {
        credential_id: credential_id_str.clone(),
        user_id: user_id.to_string(),
        public_key,
        counter: 0,
        user: stored_user,
        aaguid,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_used_at: Utc::now(),
    };

    PasskeyStore::store_credential(credential_id_str, credential)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    // Remove used challenge
    remove_options("regi_challenge", user_handle).await?;

    Ok("Registration successful".to_string())
}

fn extract_credential_public_key(reg_data: &RegisterCredential) -> Result<String, PasskeyError> {
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
    verify_attestation(&attestation_obj, &decoded_client_data)?;

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

        tracing::debug!(
            "Attestation format: {:?}, auth data: {:?}, attestation statement: {:?}",
            fmt,
            auth_data,
            att_stmt
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

fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Result<String, PasskeyError> {
    // Check attested credential data flag
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;
    if !has_attested_cred_data {
        tracing::error!("No attested credential data present");
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

    let encoded = base64url_encode(public_key)
        .map_err(|_| PasskeyError::Format("Failed to encode public key".to_string()))?;
    Ok(encoded)
}

fn parse_credential_data(auth_data: &[u8]) -> Result<&[u8], PasskeyError> {
    let mut pos = 37; // Skip RP ID hash (32) + flags (1) + counter (4)

    if auth_data.len() < pos + 18 {
        tracing::error!("Authenticator data too short");
        return Err(PasskeyError::Format(
            "Authenticator data too short".to_string(),
        ));
    }

    pos += 16; // Skip AAGUID

    // Get credential ID length
    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2;

    if cred_id_len == 0 || cred_id_len > 1024 {
        tracing::error!("Invalid credential ID length");
        return Err(PasskeyError::Format(
            "Invalid credential ID length".to_string(),
        ));
    }

    if auth_data.len() < pos + cred_id_len {
        tracing::error!("Authenticator data too short for credential ID");
        return Err(PasskeyError::Format(
            "Authenticator data too short for credential ID".to_string(),
        ));
    }

    pos += cred_id_len;

    Ok(&auth_data[pos..])
}

fn extract_key_coordinates(credential_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
    let public_key_cbor: CborValue = ciborium::de::from_reader(credential_data).map_err(|e| {
        tracing::error!("Invalid public key CBOR: {}", e);
        PasskeyError::Format(format!("Invalid public key CBOR: {}", e))
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

/// Verifies the client data
///
/// 1. Decodes clientDataJSON as UTF-8
/// 2. Parses JSON
/// 3. Verifies type
/// 4. Verifies challenge
/// 5. Verifies origin
/// 6. Verifies user
///
/// Returns Ok(()) if all checks pass, Err(PasskeyError) otherwise.
///
/// # Arguments
/// * `reg_data` - A reference to the RegisterCredential struct containing the client data
///
/// # Returns
/// * `Ok(())` if all checks pass
/// * `Err(PasskeyError)` if any check fails
///
async fn verify_client_data(reg_data: &RegisterCredential) -> Result<(), PasskeyError> {
    // Step 5: Decode clientDataJSON as UTF-8
    let decoded_client_data =
        base64url_decode(&reg_data.response.client_data_json).map_err(|e| {
            tracing::error!("Failed to decode client data: {}", e);
            PasskeyError::Format(format!("Failed to decode client data: {}", e))
        })?;

    let client_data_str = String::from_utf8(decoded_client_data).map_err(|e| {
        tracing::error!("Client data is not valid UTF-8: {}", e);
        PasskeyError::Format(format!("Client data is not valid UTF-8: {}", e))
    })?;

    // Step 6: Parse JSON
    let client_data: WebAuthnClientData = serde_json::from_str(&client_data_str).map_err(|e| {
        tracing::error!("Failed to parse client data JSON: {}", e);
        PasskeyError::Format(format!("Failed to parse client data JSON: {}", e))
    })?;

    tracing::debug!("Client data: {:#?}", client_data);

    // Step 7: Verify type
    if client_data.type_ != "webauthn.create" {
        tracing::error!("Invalid client data type: {}", client_data.type_);
        return Err(PasskeyError::ClientData("Invalid type".to_string()));
    }

    let user_handle = reg_data.user_handle.as_deref().ok_or_else(|| {
        tracing::error!("User handle is missing");
        PasskeyError::ClientData("User handle is missing".to_string())
    })?;

    let stored_options = get_and_validate_options("regi_challenge", user_handle).await?;

    // Step 8: Verify challenge using base64url encoding comparison
    if client_data.challenge != stored_options.challenge {
        tracing::error!(
            "Challenge verification failed: client_data.challenge: {}, stored_options.challenge: {}",
            client_data.challenge,
            stored_options.challenge
        );
        return Err(PasskeyError::Challenge(
            "Challenge verification failed".to_string(),
        ));
    }

    // Step 9: Verify origin
    if client_data.origin != *ORIGIN {
        tracing::error!(
            "Invalid origin. Expected {}, got {}",
            *ORIGIN,
            client_data.origin
        );
        return Err(PasskeyError::ClientData(format!(
            "Invalid origin. Expected {}, got {}",
            *ORIGIN, client_data.origin
        )));
    }

    // Step 10: Token binding is optional in WebAuthn, we can skip it for now
    // If we want to support it later, we would verify client_data.token_binding here

    Ok(())
}
