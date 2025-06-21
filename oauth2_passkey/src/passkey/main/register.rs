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
    use crate::passkey::main::types::AuthenticatorAttestationResponse;
    use ciborium::value::Value as CborValue;

    /// Test parse attestation object success none fmt
    ///
    /// This test verifies that `parse_attestation_object` successfully parses a valid
    /// attestation object with "none" format. It tests CBOR decoding and validates that
    /// all fields (fmt, authData, attStmt) are correctly extracted from the attestation object.
    #[test]
    fn test_parse_attestation_object_success_none_fmt() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Construct the expected AttestationObject fields
        let expected_fmt = "none".to_string();
        let expected_auth_data = b"authdata".to_vec();
        let expected_att_stmt_map = Vec::<(CborValue, CborValue)>::new(); // Empty map

        // Create the CBOR structure programmatically
        let cbor_map = vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text(expected_fmt.clone()),
            ),
            (
                CborValue::Text("attStmt".to_string()),
                CborValue::Map(expected_att_stmt_map.clone()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(expected_auth_data.clone()),
            ),
        ];
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

    /// Test parse attestation object invalid base64
    ///
    /// This test verifies that `parse_attestation_object` returns appropriate errors when
    /// given invalid base64 input that cannot be decoded. It tests the base64 validation
    /// and error handling for malformed attestation data.
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

    /// Test parse attestation object valid base64 invalid cbor
    ///
    /// This test verifies that `parse_attestation_object` returns appropriate errors when
    /// given valid base64 that contains invalid CBOR data. It tests the CBOR parsing
    /// validation and error handling for corrupted attestation objects.
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

    /// Test parse attestation object cbor map missing fmt
    ///
    /// This test verifies that `parse_attestation_object` returns appropriate errors when
    /// the CBOR map is missing the required "fmt" field. It tests validation of required
    /// attestation object structure and proper error reporting for incomplete data.
    #[test]
    fn test_parse_attestation_object_cbor_map_missing_fmt() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // CBOR: { "attStmt": {}, "authData": b"authdata" } (missing "fmt")
        let cbor_map = vec![
            (
                CborValue::Text("attStmt".to_string()),
                CborValue::Map(Vec::new()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(b"authdata".to_vec()),
            ),
        ];
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

    /// Test parse attestation object cbor map missing auth data
    ///
    /// This test verifies that `parse_attestation_object` returns appropriate errors when
    /// the CBOR map is missing the required "authData" field. It tests validation of
    /// required attestation structure and proper error handling for missing authenticator data.
    #[test]
    fn test_parse_attestation_object_cbor_map_missing_auth_data() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // CBOR: { "fmt": "none", "attStmt": {} } (missing "authData")
        let cbor_map = vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("none".to_string()),
            ),
            (
                CborValue::Text("attStmt".to_string()),
                CborValue::Map(Vec::new()),
            ),
        ];
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

    /// Test parse attestation object cbor map missing att stmt
    ///
    /// This test verifies that `parse_attestation_object` returns appropriate errors when
    /// the CBOR map is missing the required "attStmt" field. It tests validation of
    /// required attestation structure and proper error handling for missing attestation statements.
    #[test]
    fn test_parse_attestation_object_cbor_map_missing_att_stmt() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // CBOR: { "fmt": "none", "authData": b"authdata" } (missing "attStmt")
        let cbor_map = vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("none".to_string()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(b"authdata".to_vec()),
            ),
        ];
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

    /// Test parse attestation object cbor not a map
    ///
    /// This test verifies that `parse_attestation_object` returns appropriate errors when
    /// the CBOR data is not a map structure. It tests type validation and ensures that
    /// non-map CBOR structures are properly rejected with descriptive error messages.
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

    /// Test extract key coordinates success
    ///
    /// This test verifies that `extract_key_coordinates` successfully extracts X and Y
    /// coordinates from a valid CBOR key map. It tests the parsing of elliptic curve
    /// public key coordinates from CBOR-encoded key data.
    #[test]
    fn test_extract_key_coordinates_success() {
        use ciborium::value::Integer;

        // Create a CBOR map with valid X and Y coordinates
        // COSE key format uses -2 and -3 for X and Y coordinates
        let x_coord = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]; // 16 bytes for X
        let y_coord = vec![
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]; // 16 bytes for Y

        let cbor_map = vec![
            (
                CborValue::Integer(Integer::from(-2)),
                CborValue::Bytes(x_coord.clone()),
            ),
            (
                CborValue::Integer(Integer::from(-3)),
                CborValue::Bytes(y_coord.clone()),
            ),
        ];
        let cbor_value = CborValue::Map(cbor_map);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes).unwrap();

        let result = extract_key_coordinates(&cbor_bytes);
        assert!(result.is_ok());
        let (extracted_x, extracted_y) = result.unwrap();
        assert_eq!(extracted_x, x_coord);
        assert_eq!(extracted_y, y_coord);
    }

    /// Test extract key coordinates missing x
    ///
    /// This test verifies that `extract_key_coordinates` returns appropriate errors when
    /// the X coordinate is missing from the CBOR key map. It tests validation of required
    /// key components and proper error handling for incomplete key data.
    #[test]
    fn test_extract_key_coordinates_missing_x() {
        // Create a CBOR map with only Y coordinate, missing X
        let y_coord = vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let cbor_map = vec![
            // Only add Y coordinate (-3)
            (
                CborValue::Integer(Integer::from(-3)),
                CborValue::Bytes(y_coord),
            ),
        ];
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

    /// Test extract key coordinates missing y
    ///
    /// This test verifies that `extract_key_coordinates` returns appropriate errors when
    /// the Y coordinate is missing from the CBOR key map. It tests validation of required
    /// key components and proper error handling for incomplete key data.
    #[test]
    fn test_extract_key_coordinates_missing_y() {
        // Create a CBOR map with only X coordinate, missing Y
        let x_coord = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let cbor_map = vec![
            // Only add X coordinate (-2)
            (
                CborValue::Integer(Integer::from(-2)),
                CborValue::Bytes(x_coord),
            ),
        ];
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

    /// Test parse credential data success
    ///
    /// This test verifies that `parse_credential_data` successfully extracts credential ID
    /// and public key data from valid authenticator data. It tests the parsing of credential
    /// information embedded in the authenticator data structure.
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

    /// Test parse credential data too short
    ///
    /// This test verifies that `parse_credential_data` returns appropriate errors when
    /// the authenticator data is too short to contain valid credential information.
    /// It tests length validation and proper error handling for truncated data.
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

    /// Test parse credential data invalid length
    ///
    /// This test verifies that `parse_credential_data` returns appropriate errors when
    /// the credential ID length field contains invalid values. It tests validation of
    /// length fields and proper error handling for malformed credential data.
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

    /// Test parse credential data too short for credential id
    /// This test verifies that parsing fails when authenticator data contains
    /// insufficient data for the declared credential ID length.
    /// It performs the following steps:
    /// 1. Creates mock authenticator data with credential ID length set to 20 bytes
    /// 2. Provides only 10 bytes of credential ID data (less than declared)
    /// 3. Verifies that parsing returns a "too short for credential ID" error
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

    /// Test parse credential data large credential id length
    /// This test verifies that parsing fails when credential ID length exceeds the maximum allowed size.
    /// It performs the following steps:
    /// 1. Creates authenticator data with credential ID length set to 1025 bytes (exceeds 1024 limit)
    /// 2. Calls parse_credential_data with the oversized credential ID length
    /// 3. Verifies that parsing returns an "Invalid credential ID length" error
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

    /// Test extract key coordinates invalid cbor
    /// This test verifies that key coordinate extraction fails when provided with invalid CBOR data.
    /// It performs the following steps:
    /// 1. Creates malformed data that cannot be parsed as valid CBOR
    /// 2. Calls extract_key_coordinates with the invalid CBOR data
    /// 3. Verifies that extraction returns an "Invalid public key format" error
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

    /// Test create registration options integration
    ///
    /// This test verifies the complete registration options creation process in an integrated
    /// environment. It tests the generation of registration challenges, options formatting,
    /// and proper integration with cache and session systems.
    #[tokio::test]
    async fn test_create_registration_options_integration() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Create user info for registration
        let user_handle = "test_user_handle_456";
        let user_info = crate::passkey::types::PublicKeyCredentialUserEntity {
            user_handle: user_handle.to_string(),
            name: "test_user_456".to_string(),
            display_name: "Test User 456".to_string(),
        };

        // Call the function under test
        let options = super::create_registration_options(user_info.clone()).await;
        assert!(options.is_ok(), "Failed to create registration options");

        let registration_options = options.unwrap();

        // Verify that the options contain the expected user information
        assert_eq!(registration_options.user.user_handle, user_handle);
        assert_eq!(registration_options.user.name, "test_user_456");
        assert_eq!(registration_options.user.display_name, "Test User 456");

        // Verify that a challenge was stored in the cache
        let cache_result = super::get_and_validate_options("regi_challenge", user_handle).await;
        assert!(
            cache_result.is_ok(),
            "Challenge was not stored in cache properly"
        );

        // Clean up cache
        let cleanup_result =
            passkey_test_utils::remove_from_cache("regi_challenge", user_handle).await;
        assert!(
            cleanup_result.is_ok(),
            "Failed to clean up test data from cache"
        );

        // Verify removal
        let cache_get = GENERIC_CACHE_STORE
            .lock()
            .await
            .get("regi_challenge", user_handle)
            .await;
        assert!(cache_get.is_ok(), "Error checking cache");
        assert!(
            cache_get.unwrap().is_none(),
            "Cache entry should be removed"
        );
    }

    /// Test get or create user handle integration
    ///
    /// This test verifies the user handle creation and retrieval functionality for both
    /// anonymous and authenticated users. It tests user handle generation for new users
    /// and retrieval for existing users in different session states.
    #[tokio::test]
    #[ignore = "This test requires a valid session and cache setup"]
    async fn test_get_or_create_user_handle() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::session::User as SessionUser;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Test with no user (should generate a new handle)
        let no_user_result = super::get_or_create_user_handle(&None).await;
        assert!(
            no_user_result.is_ok(),
            "Failed to create user handle with no user"
        );
        let no_user_handle = no_user_result.unwrap();
        assert!(
            !no_user_handle.is_empty(),
            "User handle should not be empty"
        );

        // Test with logged-in user
        let session_user = Some(SessionUser {
            id: "test_user_id_789".to_string(),
            account: "test_account_789".to_string(),
            label: "Test User 789".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });

        // First call with this user should create a new handle
        let first_handle_result = super::get_or_create_user_handle(&session_user).await;
        assert!(
            first_handle_result.is_ok(),
            "Failed to create user handle for logged-in user"
        );
        let first_handle = first_handle_result.unwrap();

        // Insert a test credential for this user to simulate existing credentials
        let credential_id = "test_cred_id_for_user_handle";
        let result = passkey_test_utils::insert_test_user_and_credential(
            passkey_test_utils::TestCredentialParams::new(
                credential_id,
                "test_user_id_789", // Same as session user ID
                &first_handle,      // Use the generated handle
                "Test User 789",
                "Test Display Name 789",
                "test_public_key",
                "test_aaguid",
                0,
            )
        )
        .await;
        assert!(result.is_ok(), "Failed to insert test user and credential");

        // Second call with same user might reuse the handle depending on PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL
        let second_handle_result = super::get_or_create_user_handle(&session_user).await;
        assert!(second_handle_result.is_ok());

        // Clean up
        let cleanup_result = passkey_test_utils::cleanup_test_credential(credential_id).await;
        assert!(cleanup_result.is_ok(), "Failed to clean up test credential");
    }

    /// Test verify session then finish registration success
    /// This test verifies the complete registration flow with valid session and challenge data.
    /// It performs the following steps:
    /// 1. Sets up test environment with user session and registration challenge
    /// 2. Creates test credential data and stores it in the database
    /// 3. Calls verify_session_then_finish_registration with valid attestation response
    /// 4. Verifies that registration completes successfully with proper cleanup
    #[tokio::test]
    #[ignore = "This test requires a valid session and cache setup"]
    async fn test_verify_session_then_finish_registration_success() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::passkey::main::types::AuthenticatorAttestationResponse;
        use crate::passkey::main::utils::{get_from_cache, remove_from_cache, store_in_cache};
        use crate::passkey::types::{PublicKeyCredentialUserEntity, SessionInfo};
        use crate::session::User as SessionUser;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_id = "test_user_12345";
        let user_handle = "test_handle_12345";

        // Create session user
        let session_user = SessionUser {
            id: user_id.to_string(),
            account: "test_account".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Store session info in cache
        let session_info = SessionInfo {
            user: session_user.clone(),
        };
        let store_result = store_in_cache("session_info", user_handle, session_info, 3600).await;
        assert!(store_result.is_ok(), "Failed to store session info");

        // Create registration challenge in cache
        let user_entity = PublicKeyCredentialUserEntity {
            user_handle: user_handle.to_string(),
            name: "test_user".to_string(),
            display_name: "Test User".to_string(),
        };
        let stored_options = crate::passkey::types::StoredOptions {
            challenge: "test_challenge_12345".to_string(),
            user: user_entity,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: 3600,
        };
        let challenge_store_result =
            store_in_cache("regi_challenge", user_handle, stored_options, 3600).await;
        assert!(challenge_store_result.is_ok(), "Failed to store challenge");

        // Create test credential for storage
        let credential_id = "test_cred_verify_session_success";
        let user_creation_result = passkey_test_utils::insert_test_user_and_credential(
            passkey_test_utils::TestCredentialParams::new(
                credential_id,
                user_id,
                user_handle,
                "test_user",
                "Test User",
                "test_public_key",
                "test_aaguid",
                0,
            )
        )
        .await;
        assert!(
            user_creation_result.is_ok(),
            "Failed to create test user and credential"
        );

        // Create RegisterCredential with matching client data
        let client_data = super::WebAuthnClientData {
            type_: "webauthn.create".to_string(),
            challenge: "test_challenge_12345".to_string(),
            origin: crate::passkey::config::ORIGIN.to_string(),
        };
        let client_data_json = serde_json::to_string(&client_data).unwrap();
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        // Create mock attestation object with proper structure
        let mut cbor_map = Vec::new();
        cbor_map.push((
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        ));
        cbor_map.push((
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(Vec::new()),
        ));

        // Create mock auth data with proper structure for registration
        let mut auth_data = Vec::new();
        // RP ID hash (32 bytes) - must match SHA-256 hash of PASSKEY_RP_ID
        use ring::digest;
        let rp_id_hash = digest::digest(
            &digest::SHA256,
            crate::passkey::config::PASSKEY_RP_ID.as_bytes(),
        );
        auth_data.extend_from_slice(rp_id_hash.as_ref());
        // Flags (1 byte) - user present (0x01) + user verified (0x04) + attested credential data (0x40) = 0x45
        auth_data.push(0x45);
        // Counter (4 bytes)
        auth_data.extend_from_slice(&[0u8; 4]);

        // Attested credential data (required for registration)
        // 16 bytes AAGUID
        auth_data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        // 2 bytes credential ID length
        let cred_id_bytes = credential_id.as_bytes();
        let cred_id_len = cred_id_bytes.len() as u16;
        auth_data.extend_from_slice(&cred_id_len.to_be_bytes());
        // Credential ID bytes
        auth_data.extend_from_slice(cred_id_bytes);
        // Mock public key (COSE format) - simplified ES256 key
        let mock_public_key = vec![
            0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x22, 0x58, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ];
        auth_data.extend_from_slice(&mock_public_key);

        cbor_map.push((
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(auth_data),
        ));

        let cbor_value = CborValue::Map(cbor_map);
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut cbor_bytes).unwrap();
        let attestation_object_b64 = crate::utils::base64url_encode(cbor_bytes).unwrap();

        let reg_data = super::RegisterCredential {
            raw_id: credential_id.to_string(),
            id: credential_id.to_string(),
            type_: "public-key".to_string(),
            user_handle: Some(user_handle.to_string()),
            response: AuthenticatorAttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
            },
        };

        // Test the function
        let result = super::verify_session_then_finish_registration(session_user, reg_data).await;
        assert!(
            result.is_ok(),
            "verify_session_then_finish_registration should succeed: {:?}",
            result.err()
        );

        // Verify session info was removed from cache
        let session_check = get_from_cache::<SessionInfo>("session_info", user_handle).await;
        assert!(session_check.is_ok());
        assert!(
            session_check.unwrap().is_none(),
            "Session info should be removed from cache"
        );

        // Cleanup
        let cleanup_result = passkey_test_utils::cleanup_test_credential(credential_id).await;
        assert!(cleanup_result.is_ok(), "Failed to clean up test credential");
        let _ = remove_from_cache("regi_challenge", user_handle).await;
    }

    /// Test verify session then finish registration missing user handle
    /// This test verifies that registration fails when user handle is missing from the request.
    /// It performs the following steps:
    /// 1. Initializes test environment with session user
    /// 2. Creates RegisterCredential with missing user_handle field (set to None)
    /// 3. Calls verify_session_then_finish_registration with incomplete data
    /// 4. Verifies that it returns a "User handle is missing" error
    #[tokio::test]
    async fn test_verify_session_then_finish_registration_missing_user_handle() {
        use crate::passkey::main::types::AuthenticatorAttestationResponse;
        use crate::session::User as SessionUser;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let session_user = SessionUser {
            id: "test_user_missing_handle".to_string(),
            account: "test_account".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Create RegisterCredential with missing user_handle
        let reg_data = super::RegisterCredential {
            raw_id: "test_cred_id".to_string(),
            id: "test_cred_id".to_string(),
            type_: "public-key".to_string(),
            user_handle: None, // Missing user handle
            response: AuthenticatorAttestationResponse {
                client_data_json: "dummy".to_string(),
                attestation_object: "dummy".to_string(),
            },
        };

        let result = super::verify_session_then_finish_registration(session_user, reg_data).await;
        assert!(result.is_err(), "Should fail when user handle is missing");

        match result.err().unwrap() {
            PasskeyError::ClientData(msg) => {
                assert_eq!(msg, "User handle is missing");
            }
            e => panic!("Expected PasskeyError::ClientData, got {:?}", e),
        }
    }

    /// Test verify session then finish registration session not found
    /// This test verifies that registration fails when session information is not found in cache.
    /// It performs the following steps:
    /// 1. Initializes test environment with session user
    /// 2. Creates RegisterCredential with valid user handle but no session stored in cache
    /// 3. Calls verify_session_then_finish_registration with missing session data
    /// 4. Verifies that it returns a "Session not found" error
    #[tokio::test]
    async fn test_verify_session_then_finish_registration_session_not_found() {
        use crate::passkey::main::types::AuthenticatorAttestationResponse;
        use crate::session::User as SessionUser;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_handle = "nonexistent_handle_12345";

        let session_user = SessionUser {
            id: "test_user_no_session".to_string(),
            account: "test_account".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Create RegisterCredential without storing session info in cache
        let reg_data = super::RegisterCredential {
            raw_id: "test_cred_id".to_string(),
            id: "test_cred_id".to_string(),
            type_: "public-key".to_string(),
            user_handle: Some(user_handle.to_string()),
            response: AuthenticatorAttestationResponse {
                client_data_json: "dummy".to_string(),
                attestation_object: "dummy".to_string(),
            },
        };

        let result = super::verify_session_then_finish_registration(session_user, reg_data).await;
        assert!(result.is_err(), "Should fail when session is not found");

        match result.err().unwrap() {
            PasskeyError::NotFound(msg) => {
                assert_eq!(msg, "Session not found");
            }
            e => panic!("Expected PasskeyError::NotFound, got {:?}", e),
        }
    }

    /// Test verify session then finish registration user id mismatch
    /// This test verifies that registration fails when session user ID doesn't match stored session.
    /// It performs the following steps:
    /// 1. Stores session info in cache with one user ID ("stored_user_id")
    /// 2. Attempts registration with different user ID ("current_user_id")
    /// 3. Calls verify_session_then_finish_registration with mismatched user data
    /// 4. Verifies that it returns a "User ID mismatch" error (prevents session hijacking)
    #[tokio::test]
    async fn test_verify_session_then_finish_registration_user_id_mismatch() {
        use crate::passkey::main::types::AuthenticatorAttestationResponse;
        use crate::passkey::main::utils::{get_from_cache, store_in_cache};
        use crate::passkey::types::SessionInfo;
        use crate::session::User as SessionUser;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_handle = "test_handle_mismatch";

        // Create session user with one ID
        let stored_session_user = SessionUser {
            id: "stored_user_id".to_string(),
            account: "test_account".to_string(),
            label: "Stored User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Create different session user with different ID
        let current_session_user = SessionUser {
            id: "current_user_id".to_string(), // Different ID - security breach attempt
            account: "test_account".to_string(),
            label: "Current User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Store session info with the first user
        let session_info = SessionInfo {
            user: stored_session_user,
        };
        let store_result = store_in_cache("session_info", user_handle, session_info, 3600).await;
        assert!(store_result.is_ok(), "Failed to store session info");

        let reg_data = super::RegisterCredential {
            raw_id: "test_cred_id".to_string(),
            id: "test_cred_id".to_string(),
            type_: "public-key".to_string(),
            user_handle: Some(user_handle.to_string()),
            response: AuthenticatorAttestationResponse {
                client_data_json: "dummy".to_string(),
                attestation_object: "dummy".to_string(),
            },
        };

        // Try to verify with different user - this should fail (security protection)
        let result =
            super::verify_session_then_finish_registration(current_session_user, reg_data).await;
        assert!(
            result.is_err(),
            "Should fail when user IDs don't match - this prevents session hijacking"
        );

        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert_eq!(msg, "User ID mismatch");
            }
            e => panic!(
                "Expected PasskeyError::Format for user ID mismatch, got {:?}",
                e
            ),
        }

        // Verify session info was still removed from cache (cleanup on security failure)
        let session_check = get_from_cache::<SessionInfo>("session_info", user_handle).await;
        assert!(session_check.is_ok());
        assert!(
            session_check.unwrap().is_none(),
            "Session info should be removed even on security failure"
        );
    }

    // Tests for verify_client_data function

    // Helper function to create test RegisterCredential for verify_client_data tests
    fn create_test_register_credential_for_verify_client_data(
        client_data_json: String,
        user_handle: Option<String>,
    ) -> RegisterCredential {
        RegisterCredential {
            raw_id: "test_cred_id".to_string(),
            id: "test_cred_id".to_string(),
            type_: "public-key".to_string(),
            user_handle,
            response: AuthenticatorAttestationResponse {
                client_data_json,
                attestation_object: "test_attestation_object".to_string(),
            },
        }
    }

    // Helper function to create properly formatted client data JSON
    fn create_test_client_data_json(type_: &str, challenge: &str, origin: &str) -> String {
        let client_data = super::WebAuthnClientData {
            type_: type_.to_string(),
            challenge: challenge.to_string(),
            origin: origin.to_string(),
        };
        serde_json::to_string(&client_data).unwrap()
    }

    /// Test verify client data success
    /// This test verifies that client data verification succeeds with valid registration data.
    /// It performs the following steps:
    /// 1. Stores registration challenge in cache with valid user and challenge data
    /// 2. Creates properly formatted client data JSON with matching challenge and origin
    /// 3. Calls verify_client_data with valid registration credential
    /// 4. Verifies that verification succeeds and cleans up cache data
    #[tokio::test]
    async fn test_verify_client_data_success() {
        use crate::passkey::main::utils::store_in_cache;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_handle = "test_user_verify_client_data_success";
        let challenge = "test_challenge_verify_success";

        // Store challenge in cache
        let stored_options = StoredOptions {
            challenge: challenge.to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: user_handle.to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: 3600,
        };

        let store_result =
            store_in_cache("regi_challenge", user_handle, stored_options, 3600).await;
        assert!(store_result.is_ok(), "Failed to store challenge in cache");

        // Create valid client data
        let client_data_json = create_test_client_data_json(
            "webauthn.create",
            challenge,
            &crate::passkey::config::ORIGIN,
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            client_data_b64,
            Some(user_handle.to_string()),
        );

        // Test the function
        let result = super::verify_client_data(&reg_data).await;
        assert!(
            result.is_ok(),
            "verify_client_data should succeed with valid data: {:?}",
            result.err()
        );

        // Cleanup
        let _ = remove_from_cache("regi_challenge", user_handle).await;
    }

    /// Test verify client data invalid base64
    /// This test verifies that client data verification fails with invalid base64 encoding.
    /// It performs the following steps:
    /// 1. Creates RegisterCredential with malformed base64 client data JSON
    /// 2. Calls verify_client_data with invalid base64 data
    /// 3. Verifies that verification fails with "Failed to decode client data" error
    /// 4. Confirms proper error handling for base64 decoding issues
    #[tokio::test]
    async fn test_verify_client_data_invalid_base64() {
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let reg_data = create_test_register_credential_for_verify_client_data(
            "invalid_base64!@#$%".to_string(),
            Some("test_user".to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with invalid base64");

        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert!(msg.contains("Failed to decode client data"));
            }
            e => panic!(
                "Expected PasskeyError::Format for invalid base64, got {:?}",
                e
            ),
        }
    }

    /// Test verify client data invalid utf8
    /// This test verifies that client data verification fails with invalid UTF-8 encoding.
    /// It performs the following steps:
    /// 1. Creates invalid UTF-8 byte sequence (0xFF, 0xFE, 0xFD)
    /// 2. Encodes the invalid UTF-8 data as base64 and creates RegisterCredential
    /// 3. Calls verify_client_data with non-UTF-8 client data
    /// 4. Verifies that verification fails with "Client data is not valid UTF-8" error
    #[tokio::test]
    async fn test_verify_client_data_invalid_utf8() {
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Create invalid UTF-8 bytes and encode as base64
        let invalid_utf8_bytes = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
        let invalid_utf8_b64 = crate::utils::base64url_encode(invalid_utf8_bytes).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            invalid_utf8_b64,
            Some("test_user".to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with invalid UTF-8");

        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert!(msg.contains("Client data is not valid UTF-8"));
            }
            e => panic!(
                "Expected PasskeyError::Format for invalid UTF-8, got {:?}",
                e
            ),
        }
    }

    /// Test verify client data invalid json
    /// This test verifies that client data verification fails with malformed JSON.
    /// It performs the following steps:
    /// 1. Creates invalid JSON structure with malformed syntax
    /// 2. Encodes the invalid JSON as base64 and creates RegisterCredential
    /// 3. Calls verify_client_data with malformed JSON data
    /// 4. Verifies that verification fails with "Failed to parse client data JSON" error
    #[tokio::test]
    async fn test_verify_client_data_invalid_json() {
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Create invalid JSON
        let invalid_json = "{ invalid json structure }";
        let invalid_json_b64 =
            crate::utils::base64url_encode(invalid_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            invalid_json_b64,
            Some("test_user".to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with invalid JSON");

        match result.err().unwrap() {
            PasskeyError::Format(msg) => {
                assert!(msg.contains("Failed to parse client data JSON"));
            }
            e => panic!(
                "Expected PasskeyError::Format for invalid JSON, got {:?}",
                e
            ),
        }
    }

    /// Test verify client data wrong type
    /// This test verifies that client data verification fails with incorrect WebAuthn type.
    /// It performs the following steps:
    /// 1. Creates client data JSON with "webauthn.get" type (authentication) instead of "webauthn.create" (registration)
    /// 2. Encodes the wrong-type client data as base64 and creates RegisterCredential
    /// 3. Calls verify_client_data with incorrect ceremony type
    /// 4. Verifies that verification fails with appropriate type validation error
    #[tokio::test]
    async fn test_verify_client_data_wrong_type() {
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Create client data with wrong type (authentication instead of registration)
        let client_data_json = create_test_client_data_json(
            "webauthn.get", // Wrong type - should be "webauthn.create"
            "test_challenge",
            &crate::passkey::config::ORIGIN,
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            client_data_b64,
            Some("test_user".to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with wrong client data type");

        match result.err().unwrap() {
            PasskeyError::ClientData(msg) => {
                assert_eq!(msg, "Invalid type");
            }
            e => panic!(
                "Expected PasskeyError::ClientData for wrong type, got {:?}",
                e
            ),
        }
    }

    /// Test verify client data missing user handle
    /// This test verifies that client data verification fails when user handle is missing.
    /// It performs the following steps:
    /// 1. Creates valid client data JSON with proper format and challenge
    /// 2. Creates RegisterCredential with user_handle set to None
    /// 3. Calls verify_client_data with missing user identification
    /// 4. Verifies that verification fails with "User handle is missing" error
    #[tokio::test]
    async fn test_verify_client_data_missing_user_handle() {
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let client_data_json = create_test_client_data_json(
            "webauthn.create",
            "test_challenge",
            &crate::passkey::config::ORIGIN,
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            client_data_b64,
            None, // Missing user handle
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with missing user handle");

        match result.err().unwrap() {
            PasskeyError::ClientData(msg) => {
                assert!(msg.contains("User handle is missing"));
            }
            e => panic!(
                "Expected PasskeyError::ClientData for missing user handle, got {:?}",
                e
            ),
        }
    }

    /// Test verify client data challenge not found
    /// This test verifies that client data verification fails when challenge is not found in cache.
    /// It performs the following steps:
    /// 1. Creates valid client data JSON with challenge but doesn't store it in cache
    /// 2. Calls verify_client_data without pre-storing registration challenge
    /// 3. Verifies that verification fails with NotFound error
    /// 4. Confirms proper handling when challenge lookup fails
    #[tokio::test]
    async fn test_verify_client_data_challenge_not_found() {
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_handle = "test_user_challenge_not_found";

        // Don't store any challenge in cache
        let client_data_json = create_test_client_data_json(
            "webauthn.create",
            "test_challenge",
            &crate::passkey::config::ORIGIN,
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            client_data_b64,
            Some(user_handle.to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(
            result.is_err(),
            "Should fail when challenge not found in cache"
        );

        // The error comes from get_and_validate_options which should return NotFound
        match result.err().unwrap() {
            PasskeyError::NotFound(_) => {
                // Expected - challenge not found in cache
            }
            e => panic!(
                "Expected PasskeyError::NotFound for missing challenge, got {:?}",
                e
            ),
        }
    }

    /// Test verify client data challenge mismatch
    /// This test verifies that client data verification fails when challenge doesn't match stored value.
    /// It performs the following steps:
    /// 1. Stores registration challenge "stored_challenge_123" in cache
    /// 2. Creates client data JSON with different challenge "different_challenge_456"
    /// 3. Calls verify_client_data with mismatched challenge values
    /// 4. Verifies that verification fails with challenge validation error
    #[tokio::test]
    async fn test_verify_client_data_challenge_mismatch() {
        use crate::passkey::main::utils::store_in_cache;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_handle = "test_user_challenge_mismatch";
        let stored_challenge = "stored_challenge_123";
        let client_challenge = "different_challenge_456";

        // Store one challenge in cache
        let stored_options = StoredOptions {
            challenge: stored_challenge.to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: user_handle.to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: 3600,
        };

        let store_result =
            store_in_cache("regi_challenge", user_handle, stored_options, 3600).await;
        assert!(store_result.is_ok(), "Failed to store challenge in cache");

        // Create client data with different challenge
        let client_data_json = create_test_client_data_json(
            "webauthn.create",
            client_challenge, // Different from stored challenge
            &crate::passkey::config::ORIGIN,
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            client_data_b64,
            Some(user_handle.to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with challenge mismatch");

        match result.err().unwrap() {
            PasskeyError::Challenge(msg) => {
                assert!(msg.contains("Challenge verification failed"));
            }
            e => panic!(
                "Expected PasskeyError::Challenge for challenge mismatch, got {:?}",
                e
            ),
        }

        // Cleanup
        let _ = remove_from_cache("regi_challenge", user_handle).await;
    }

    /// Test verify client data origin mismatch
    /// This test verifies that client data verification fails when origin doesn't match configuration.
    /// It performs the following steps:
    /// 1. Stores valid registration challenge in cache
    /// 2. Creates client data JSON with malicious origin "https://evil-site.com"
    /// 3. Calls verify_client_data with origin different from configured ORIGIN
    /// 4. Verifies that verification fails with "Invalid origin" error (prevents origin spoofing)
    #[tokio::test]
    async fn test_verify_client_data_origin_mismatch() {
        use crate::passkey::main::utils::store_in_cache;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        let user_handle = "test_user_origin_mismatch";
        let challenge = "test_challenge_origin";

        // Store challenge in cache
        let stored_options = StoredOptions {
            challenge: challenge.to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: user_handle.to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl: 3600,
        };

        let store_result =
            store_in_cache("regi_challenge", user_handle, stored_options, 3600).await;
        assert!(store_result.is_ok(), "Failed to store challenge in cache");

        // Create client data with wrong origin
        let client_data_json = create_test_client_data_json(
            "webauthn.create",
            challenge,
            "https://evil-site.com", // Different from configured ORIGIN
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        let reg_data = create_test_register_credential_for_verify_client_data(
            client_data_b64,
            Some(user_handle.to_string()),
        );

        let result = super::verify_client_data(&reg_data).await;
        assert!(result.is_err(), "Should fail with origin mismatch");

        match result.err().unwrap() {
            PasskeyError::ClientData(msg) => {
                assert!(msg.contains("Invalid origin"));
                assert!(msg.contains("https://evil-site.com"));
            }
            e => panic!(
                "Expected PasskeyError::ClientData for origin mismatch, got {:?}",
                e
            ),
        }

        // Cleanup
        let _ = remove_from_cache("regi_challenge", user_handle).await;
    } // ========================================
    // extract_credential_public_key tests
    // ========================================

    /// Helper function to create a test RegisterCredential for extract_credential_public_key tests
    fn create_test_register_credential_for_extract_credential_public_key() -> RegisterCredential {
        let client_data_json = create_test_client_data_json(
            "webauthn.create",
            "test-challenge",
            "https://example.com",
        );
        let client_data_b64 =
            crate::utils::base64url_encode(client_data_json.as_bytes().to_vec()).unwrap();

        RegisterCredential {
            id: "test-credential-id".to_string(),
            raw_id: "dGVzdC1jcmVkZW50aWFsLWlk".to_string(),
            type_: "public-key".to_string(),
            user_handle: Some("test-user-handle".to_string()),
            response: AuthenticatorAttestationResponse {
                attestation_object: create_simple_test_attestation_object().unwrap(),
                client_data_json: client_data_b64,
            },
        }
    }

    /// Helper function to create a simple test attestation object
    fn create_simple_test_attestation_object() -> Result<String, String> {
        // Create COSE key for EC2 P-256 public key
        let mut cose_key = Vec::new();
        let mut cbor_map = Vec::new();

        // kty = 2 (EC2)
        cbor_map.push((
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ));
        // alg = -7 (ES256)
        cbor_map.push((
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ));
        // crv = 1 (P-256)
        cbor_map.push((
            CborValue::Integer(Integer::from(-1)),
            CborValue::Integer(Integer::from(1)),
        ));
        // x coordinate (32 bytes)
        let x_coord = vec![
            0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, 0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef,
            0xff, 0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, 0x8f, 0x9f, 0xaf, 0xbf, 0xcf,
            0xdf, 0xef, 0xff, 0x0f,
        ];
        cbor_map.push((
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(x_coord),
        ));
        // y coordinate (32 bytes)
        let y_coord = vec![
            0x0f, 0xff, 0xef, 0xdf, 0xcf, 0xbf, 0xaf, 0x9f, 0x8f, 0x7f, 0x6f, 0x5f, 0x4f, 0x3f,
            0x2f, 0x1f, 0x0f, 0xff, 0xef, 0xdf, 0xcf, 0xbf, 0xaf, 0x9f, 0x8f, 0x7f, 0x6f, 0x5f,
            0x4f, 0x3f, 0x2f, 0x1f,
        ];
        cbor_map.push((
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(y_coord),
        ));

        let cose_key_cbor = CborValue::Map(cbor_map);
        ciborium::ser::into_writer(&cose_key_cbor, &mut cose_key)
            .map_err(|e| format!("Failed to serialize COSE key: {}", e))?;

        // Create credential ID (16 bytes)
        let credential_id = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];

        // Build authenticator data
        let mut auth_data = Vec::new();

        // RP ID hash (32 bytes) - SHA256("example.com")
        auth_data.extend_from_slice(&[
            0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34,
            0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab, 0x13, 0xd2, 0x12, 0x55,
            0x86, 0xce, 0x19, 0x47,
        ]);

        // Flags (1 byte) - 0x45 = user present + user verified + attested credential data
        auth_data.push(0x45);

        // Counter (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        // Credential ID length (2 bytes, big-endian)
        let cred_id_len = credential_id.len() as u16;
        auth_data.push((cred_id_len >> 8) as u8);
        auth_data.push((cred_id_len & 0xff) as u8);

        // Credential ID
        auth_data.extend_from_slice(&credential_id);

        // Public key (COSE key)
        auth_data.extend_from_slice(&cose_key);

        // Create the full attestation object
        let attestation_cbor = vec![
            0xa3, // map with 3 pairs
            0x63, 0x66, 0x6d, 0x74, // "fmt"
            0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
            0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
            0xa0, // empty map
            0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
        ];

        let mut full_attestation = attestation_cbor;
        // Add byte string length for auth_data
        if auth_data.len() < 256 {
            full_attestation.push(0x58);
            full_attestation.push(auth_data.len() as u8);
        } else {
            full_attestation.push(0x59);
            full_attestation.push((auth_data.len() >> 8) as u8);
            full_attestation.push((auth_data.len() & 0xff) as u8);
        }
        full_attestation.extend_from_slice(&auth_data);

        crate::utils::base64url_encode(full_attestation).map_err(|e| e.to_string())
    }

    /// Test extract credential public key success
    /// This test verifies that public key extraction succeeds with valid registration data.
    /// It performs the following steps:
    /// 1. Creates valid RegisterCredential with properly formatted attestation object
    /// 2. Calls extract_credential_public_key with valid credential data
    /// 3. Verifies that extraction succeeds and returns non-empty public key
    /// 4. Confirms proper parsing of credential and public key data
    #[tokio::test]
    async fn test_extract_credential_public_key_success() {
        // Initialize test environment properly
        crate::test_utils::init_test_environment().await;

        let reg_data = create_test_register_credential_for_extract_credential_public_key();

        // Test the function (it's not async)
        let result = extract_credential_public_key(&reg_data);

        // Debug: Print the error if it failed
        match &result {
            Ok(key) => println!("Success: got public key of length {}", key.len()),
            Err(e) => println!("Error: {}", e),
        }

        // Should succeed and return a public key string
        assert!(result.is_ok());
        let public_key = result.unwrap();
        assert!(!public_key.is_empty());
    }

    /// Test extract credential public key invalid client data
    /// This test verifies that public key extraction fails with invalid client data encoding.
    /// It performs the following steps:
    /// 1. Creates RegisterCredential with malformed base64 client data JSON
    /// 2. Calls extract_credential_public_key with invalid client data encoding
    /// 3. Verifies that extraction fails with "Failed to decode client data" error
    /// 4. Confirms proper error handling for base64 decoding issues
    #[test]
    fn test_extract_credential_public_key_invalid_client_data() {
        let mut reg_data = create_test_register_credential_for_extract_credential_public_key();
        reg_data.response.client_data_json = "invalid-base64!@#".to_string();

        let result = extract_credential_public_key(&reg_data);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to decode client data")
        );
    }

    /// Test extract credential public key with invalid attestation object encoding
    ///
    /// This test verifies that `extract_credential_public_key` properly handles invalid
    /// base64 encoding in the attestation object. It tests error handling when the
    /// attestation object contains malformed base64 data that cannot be decoded.
    #[test]
    fn test_extract_credential_public_key_invalid_attestation_object() {
        let mut reg_data = create_test_register_credential_for_extract_credential_public_key();
        reg_data.response.attestation_object = "invalid-base64!@#".to_string();

        let result = extract_credential_public_key(&reg_data);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to decode attestation object")
        );
    }

    /// Test extract credential public key with malformed CBOR data
    ///
    /// This test verifies that `extract_credential_public_key` properly handles invalid
    /// CBOR content in the attestation object. It tests error handling when the
    /// attestation object contains valid base64 but invalid CBOR data structures.
    #[test]
    fn test_extract_credential_public_key_malformed_attestation_object() {
        let mut reg_data = create_test_register_credential_for_extract_credential_public_key();
        // Use valid base64 but invalid CBOR content
        reg_data.response.attestation_object =
            base64url_encode(b"not-valid-cbor".to_vec()).unwrap();

        let result = extract_credential_public_key(&reg_data);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid CBOR data")
        );
    }
}
