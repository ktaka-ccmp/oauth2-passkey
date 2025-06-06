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

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value as CborValue;

    #[test]
    fn test_parse_attestation_object_success_none_fmt() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Construct the expected AttestationObject fields
        let expected_fmt = "none".to_string();
        let expected_auth_data = b"authdata".to_vec();
        let expected_att_stmt_map = Vec::<(CborValue, CborValue)>::new(); // Empty map

        // Create the CBOR structure programmatically
        let mut cbor_map = Vec::new();
        cbor_map.push((
            CborValue::Text("fmt".to_string()),
            CborValue::Text(expected_fmt.clone()),
        ));
        cbor_map.push((
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(expected_att_stmt_map.clone()),
        ));
        cbor_map.push((
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(expected_auth_data.clone()),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        // Serialize CBOR to bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes)
            .expect("CBOR serialization failed");

        // Encode bytes to base64url string
        let attestation_base64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);

        let result = parse_attestation_object(&attestation_base64);
        assert!(
            result.is_ok(),
            "Parsing failed for input '{}': {:?}",
            attestation_base64,
            result.err()
        );
        let att_obj = result.unwrap();

        assert_eq!(att_obj.fmt, expected_fmt);
        assert_eq!(att_obj.auth_data, expected_auth_data);
        assert_eq!(
            att_obj.att_stmt, expected_att_stmt_map,
            "attStmt should be an empty map"
        );
    }

    #[test]
    fn test_parse_attestation_object_invalid_base64() {
        let attestation_base64 = "not-valid-base64!@#";

        let result = parse_attestation_object(attestation_base64);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert!(msg.contains("Failed to decode attestation object"));
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_attestation_object_valid_base64_invalid_cbor() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        // This is valid base64url for "this is not cbor"
        let attestation_base64 = URL_SAFE_NO_PAD.encode(b"this is not cbor");

        let result = parse_attestation_object(&attestation_base64);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert!(
                    msg.contains("Invalid CBOR data"),
                    "Error message was: {}",
                    msg
                );
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_attestation_object_cbor_map_missing_fmt() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // CBOR: { "attStmt": {}, "authData": b"authdata" } (missing "fmt")
        let mut cbor_map = Vec::new();
        cbor_map.push((
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(Vec::new()),
        ));
        cbor_map.push((
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(b"authdata".to_vec()),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes).unwrap();
        let attestation_base64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);

        let result = parse_attestation_object(&attestation_base64);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Missing required attestation data");
            }
            e => panic!(
                "Expected PasskeyError::Format with specific message, got {:?}",
                e
            ),
        }
    }

    #[test]
    fn test_parse_attestation_object_cbor_map_missing_auth_data() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // CBOR: { "fmt": "none", "attStmt": {} } (missing "authData")
        let mut cbor_map = Vec::new();
        cbor_map.push((
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        ));
        cbor_map.push((
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(Vec::new()),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes).unwrap();
        let attestation_base64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);

        let result = parse_attestation_object(&attestation_base64);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Missing required attestation data");
            }
            e => panic!(
                "Expected PasskeyError::Format with specific message, got {:?}",
                e
            ),
        }
    }

    #[test]
    fn test_parse_attestation_object_cbor_map_missing_att_stmt() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // CBOR: { "fmt": "none", "authData": b"authdata" } (missing "attStmt")
        let mut cbor_map = Vec::new();
        cbor_map.push((
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        ));
        cbor_map.push((
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(b"authdata".to_vec()),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes).unwrap();
        let attestation_base64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);

        let result = parse_attestation_object(&attestation_base64);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Missing required attestation data");
            }
            e => panic!(
                "Expected PasskeyError::Format with specific message, got {:?}",
                e
            ),
        }
    }

    #[test]
    fn test_parse_attestation_object_cbor_not_a_map() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Create a CBOR value that is not a map (using an array instead)
        let cbor_value = CborValue::Array(vec![]);

        // Serialize CBOR to bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes)
            .expect("CBOR serialization failed");

        // Encode bytes to base64url string
        let attestation_base64 = URL_SAFE_NO_PAD.encode(&cbor_bytes);

        let result = parse_attestation_object(&attestation_base64);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Invalid attestation format");
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_extract_key_coordinates_success() {
        use ciborium::value::Integer;

        // Create a CBOR map with valid X and Y coordinates
        // COSE key format uses -2 and -3 for X and Y coordinates
        let x_coord = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]; // 16 bytes for X
        let y_coord = vec![
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]; // 16 bytes for Y

        let mut cbor_map = Vec::new();
        cbor_map.push((
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(x_coord.clone()),
        ));
        cbor_map.push((
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(y_coord.clone()),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes).unwrap();

        let result = extract_key_coordinates(&cbor_bytes);
        assert!(result.is_ok());
        let (extracted_x, extracted_y) = result.unwrap();
        assert_eq!(extracted_x, x_coord);
        assert_eq!(extracted_y, y_coord);
    }

    #[test]
    fn test_extract_key_coordinates_missing_x() {
        // Create a CBOR map with only Y coordinate, missing X
        let y_coord = vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let mut cbor_map = Vec::new();
        // Only add Y coordinate (-3)
        cbor_map.push((
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(y_coord),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        // Serialize CBOR to bytes
        let mut credential_data = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut credential_data)
            .expect("CBOR serialization failed");

        // Call the function
        let result = extract_key_coordinates(&credential_data);

        // Verify the result is an error
        assert!(
            result.is_err(),
            "Expected error but got success: {:?}",
            result.ok()
        );

        // Check the error type and message
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Missing or invalid key coordinates");
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_extract_key_coordinates_missing_y() {
        // Create a CBOR map with only X coordinate, missing Y
        let x_coord = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut cbor_map = Vec::new();
        // Only add X coordinate (-2)
        cbor_map.push((
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(x_coord),
        ));
        let cbor_value = CborValue::Map(cbor_map);

        // Serialize CBOR to bytes
        let mut credential_data = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut credential_data)
            .expect("CBOR serialization failed");

        // Call the function
        let result = extract_key_coordinates(&credential_data);

        // Verify the result is an error
        assert!(
            result.is_err(),
            "Expected error but got success: {:?}",
            result.ok()
        );

        // Check the error type and message
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Missing or invalid key coordinates");
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_credential_data_success() {
        // Create a mock authenticator data array
        // Structure:
        // - 32 bytes RP ID hash
        // - 1 byte flags (with attested credential data flag set)
        // - 4 bytes counter
        // - 16 bytes AAGUID
        // - 2 bytes credential ID length
        // - credential ID bytes
        // - credential public key bytes

        // Create a mock auth_data with all required fields
        let mut auth_data = Vec::new();

        // 32 bytes RP ID hash (just zeros for test)
        auth_data.extend_from_slice(&[0u8; 32]);

        // 1 byte flags with attested credential data flag set (0x40 = 01000000)
        auth_data.push(0x40);

        // 4 bytes counter
        auth_data.extend_from_slice(&[0, 0, 0, 0]);

        // 16 bytes AAGUID
        auth_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // 2 bytes credential ID length (10 bytes)
        auth_data.extend_from_slice(&[0, 10]);

        // 10 bytes credential ID
        auth_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Some mock credential public key bytes
        let public_key_bytes = [20, 21, 22, 23, 24, 25, 26, 27, 28, 29];
        auth_data.extend_from_slice(&public_key_bytes);

        // Call the function
        let result = parse_credential_data(&auth_data);

        // Verify the result
        assert!(result.is_ok(), "Parsing failed: {:?}", result.err());

        // The result should be the credential public key bytes
        let credential_data = result.unwrap();
        assert_eq!(credential_data, &public_key_bytes);
    }

    #[test]
    fn test_parse_credential_data_too_short() {
        // Create a mock authenticator data array that's too short
        // Only include RP ID hash and flags, missing the rest
        let mut auth_data = Vec::new();

        // 32 bytes RP ID hash
        auth_data.extend_from_slice(&[0u8; 32]);

        // 1 byte flags with attested credential data flag set
        auth_data.push(0x40);

        // Missing counter, AAGUID, credential ID length, etc.

        // Call the function
        let result = parse_credential_data(&auth_data);

        // Verify the result is an error
        assert!(
            result.is_err(),
            "Expected error but got success: {:?}",
            result.ok()
        );

        // Check the error type and message
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Authenticator data too short");
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_credential_data_invalid_length() {
        // Create a mock authenticator data array with invalid credential ID length
        let mut auth_data = Vec::new();

        // 32 bytes RP ID hash
        auth_data.extend_from_slice(&[0u8; 32]);

        // 1 byte flags (with attested credential data flag set)
        auth_data.push(0x40);

        // 4 bytes counter
        auth_data.extend_from_slice(&[0, 0, 0, 0]);

        // 16 bytes AAGUID
        auth_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // 2 bytes credential ID length (set to 0, which is invalid)
        auth_data.extend_from_slice(&[0, 0]);

        // Call the function
        let result = parse_credential_data(&auth_data);

        // Verify the result is an error
        assert!(
            result.is_err(),
            "Expected error but got success: {:?}",
            result.ok()
        );

        // Check the error type and message
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Invalid credential ID length");
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_credential_data_too_short_for_credential_id() {
        // Create a mock authenticator data array that's too short for the credential ID
        let mut auth_data = Vec::new();

        // 32 bytes RP ID hash
        auth_data.extend_from_slice(&[0u8; 32]);

        // 1 byte flags (with attested credential data flag set)
        auth_data.push(0x40);

        // 4 bytes counter
        auth_data.extend_from_slice(&[0, 0, 0, 0]);

        // 16 bytes AAGUID
        auth_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // 2 bytes credential ID length (set to 20, but we'll only provide 10 bytes)
        auth_data.extend_from_slice(&[0, 20]);

        // Only 10 bytes for credential ID (less than the 20 we specified)
        auth_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Call the function
        let result = parse_credential_data(&auth_data);

        // Verify the result is an error
        assert!(
            result.is_err(),
            "Expected error but got success: {:?}",
            result.ok()
        );

        // Check the error type and message
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Authenticator data too short for credential ID");
            }
            e => panic!("Expected PasskeyError::Format, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_credential_data_large_credential_id_length() {
        // Create authenticator data with credential ID length > 1024 bytes
        let mut auth_data = Vec::new();

        // RP ID hash (32 bytes)
        auth_data.extend_from_slice(&[0u8; 32]);

        // Flags (1 byte) - set attested credential data flag
        auth_data.push(0x40);

        // Counter (4 bytes)
        auth_data.extend_from_slice(&[0u8; 4]);

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0u8; 16]);

        // Credential ID length (2 bytes) - set to 1025 (exceeds 1024 limit)
        let large_cred_id_len = 1025u16;
        auth_data.push((large_cred_id_len >> 8) as u8);
        auth_data.push((large_cred_id_len & 0xFF) as u8);

        // Add some credential ID data (we don't need all 1025 bytes for this test)
        auth_data.extend_from_slice(&[0xAAu8; 100]);

        let result = parse_credential_data(&auth_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "Invalid credential ID length");
            }
            e => panic!(
                "Expected PasskeyError::Format with 'Invalid credential ID length', got {:?}",
                e
            ),
        }
    }

    #[test]
    fn test_extract_key_coordinates_invalid_cbor() {
        // Create malformed CBOR data that cannot be parsed
        let invalid_cbor_data = b"not valid cbor data";

        let result = extract_key_coordinates(invalid_cbor_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert!(
                    msg.contains("Invalid public key format"),
                    "Error message was: {}",
                    msg
                );
            }
            e => panic!(
                "Expected PasskeyError::Format with public key format error, got {:?}",
                e
            ),
        }
    }
}
