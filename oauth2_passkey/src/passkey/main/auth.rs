use chrono::Utc;
use ring::{digest, signature::UnparsedPublicKey};

use crate::utils::{base64url_decode, gen_random_string};

use crate::passkey::config::{
    PASSKEY_CHALLENGE_TIMEOUT, PASSKEY_RP_ID, PASSKEY_TIMEOUT, PASSKEY_USER_VERIFICATION,
};
use crate::passkey::errors::PasskeyError;
use crate::passkey::storage::PasskeyStore;
use crate::passkey::types::{PasskeyCredential, PublicKeyCredentialUserEntity, StoredOptions};

use super::challenge::{get_and_validate_options, remove_options};
use super::types::{
    AllowCredential, AuthenticationOptions, AuthenticatorData, AuthenticatorResponse,
    ParsedClientData,
};
use super::utils::{name2cid_str_vec, store_in_cache};

pub(crate) async fn start_authentication(
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

pub(crate) async fn finish_authentication(
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

    // Update last used at
    PasskeyStore::update_credential_last_used_at(&auth_response.id, Utc::now()).await?;

    // Remove challenge from cache
    remove_options("auth_challenge", &auth_response.auth_id).await?;
    let user_name = stored_credential.user.name.clone();
    let user_id = stored_credential.user_id.clone();

    Ok((user_id, user_name))
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
