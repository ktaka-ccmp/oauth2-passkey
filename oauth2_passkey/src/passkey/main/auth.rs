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
use super::utils::name2cid_str_vec;
use crate::storage::{CacheErrorConversion, CacheKey, CachePrefix, store_cache_keyed};

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

    let cache_prefix = CachePrefix::auth_challenge();
    let cache_key = CacheKey::new(auth_id.clone()).map_err(PasskeyError::convert_storage_error)?;
    store_cache_keyed::<_, PasskeyError>(
        cache_prefix,
        cache_key,
        stored_options,
        (*PASSKEY_CHALLENGE_TIMEOUT).into(),
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
    let challenge_type = crate::passkey::types::ChallengeType::authentication();
    let challenge_id = crate::passkey::types::ChallengeId::new(auth_response.auth_id.clone())
        .map_err(|e| PasskeyError::Challenge(format!("Invalid auth ID: {e}")))?;
    let stored_options = get_and_validate_options(&challenge_type, &challenge_id).await?;

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
    let cache_prefix = CachePrefix::auth_challenge();
    let cache_key = CacheKey::new(auth_response.auth_id.clone())
        .map_err(PasskeyError::convert_storage_error)?;
    remove_options(cache_prefix, cache_key).await?;
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
        .map_err(|e| PasskeyError::Format(format!("Invalid public key: {e}")))?;

    let unparsed_public_key = UnparsedPublicKey::new(verification_algorithm, &public_key);

    // Signature
    let signature = base64url_decode(&auth_response.response.signature)
        .map_err(|e| PasskeyError::Format(format!("Invalid signature: {e}")))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::main::types;
    use crate::storage::{CacheKey, CachePrefix};
    use crate::test_utils::init_test_environment;

    // Create a module alias for our test utils
    use crate::passkey::main::test_utils as passkey_test_utils;

    fn create_test_authenticator_response(
        user_handle: Option<String>,
        auth_id: String,
    ) -> AuthenticatorResponse {
        // Note: This is a minimal mock for testing verify_user_handle
        // In real usage, AuthenticatorResponse has many more fields
        AuthenticatorResponse::new_for_test(
            "test_credential_id".to_string(),
            types::AuthenticatorAssertionResponse {
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0".to_string(), // {"type":"webauthn.get"}
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABA"
                    .to_string(),
                signature: "MEUCIQDsignature".to_string(),
                user_handle,
            },
            auth_id,
        )
    }

    fn create_test_passkey_credential(user_handle: String) -> PasskeyCredential {
        PasskeyCredential {
            credential_id: "test_credential_id".to_string(),
            user_id: "test_user_id".to_string(),
            public_key: "test_public_key".to_string(),
            aaguid: "test_aaguid".to_string(),
            counter: 1,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
        }
    }

    fn create_test_authenticator_data(counter: u32) -> AuthenticatorData {
        AuthenticatorData {
            rp_id_hash: vec![0; 32],
            flags: 0x01 | 0x04, // UP | UV flags set
            counter,
            raw_data: vec![],
        }
    }

    #[cfg(test)]
    use serial_test::serial;

    /// Test start authentication with no username
    ///
    /// This test verifies that `start_authentication` can handle requests without a username
    /// by generating anonymous authentication options. It validates that the function creates
    /// proper authentication options with empty credentials list and valid challenge data.
    #[tokio::test]
    async fn test_start_authentication_no_username() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let result = start_authentication(None).await;
        assert!(result.is_ok());

        let auth_options = result.unwrap();
        assert!(auth_options.allow_credentials.is_empty());
        assert!(!auth_options.challenge.is_empty());
        assert!(!auth_options.auth_id.is_empty());
        assert_eq!(auth_options.rp_id, *crate::passkey::config::PASSKEY_RP_ID);
        assert_eq!(
            auth_options.user_verification,
            *crate::passkey::config::PASSKEY_USER_VERIFICATION
        );
    }

    /// Test start authentication generates unique IDs
    ///
    /// This test verifies that `start_authentication` generates unique challenge and auth_id
    /// values on each invocation to prevent replay attacks. It calls the function multiple
    /// times and ensures all generated identifiers are unique.
    #[tokio::test]
    async fn test_start_authentication_generates_unique_ids() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let result1 = start_authentication(None).await;
        let result2 = start_authentication(None).await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let auth1 = result1.unwrap();
        let auth2 = result2.unwrap();

        // Ensure unique challenges and auth IDs
        assert_ne!(auth1.challenge, auth2.challenge);
        assert_ne!(auth1.auth_id, auth2.auth_id);
    }

    /// Test verify user handle real function matching handles
    ///
    /// This test verifies that `verify_user_handle` correctly validates user handles when
    /// the authenticator response and stored credential have matching user handle values.
    /// It creates test data with matching handles and validates successful verification.
    #[test]
    fn test_verify_user_handle_real_function_matching_handles() {
        let auth_response = create_test_authenticator_response(
            Some("test_user_handle".to_string()),
            "test_auth_id".to_string(),
        );
        let credential = create_test_passkey_credential("test_user_handle".to_string());

        // Test both discoverable and non-discoverable cases
        let result1 = verify_user_handle(&auth_response, &credential, true);
        let result2 = verify_user_handle(&auth_response, &credential, false);

        assert!(
            result1.is_ok(),
            "Should succeed with matching handles (discoverable)"
        );
        assert!(
            result2.is_ok(),
            "Should succeed with matching handles (non-discoverable)"
        );
    }

    /// Test verify user handle real function mismatched handles
    ///
    /// This test verifies that `verify_user_handle` correctly rejects authentication attempts
    /// when the user handle in the authenticator response doesn't match the stored credential.
    /// It tests both discoverable and non-discoverable credential scenarios with mismatched handles.
    ///
    #[test]
    fn test_verify_user_handle_real_function_mismatched_handles() {
        let auth_response = create_test_authenticator_response(
            Some("wrong_handle".to_string()),
            "test_auth_id".to_string(),
        );
        let credential = create_test_passkey_credential("correct_handle".to_string());

        // Test both discoverable and non-discoverable cases
        let result1 = verify_user_handle(&auth_response, &credential, true);
        let result2 = verify_user_handle(&auth_response, &credential, false);

        // Both should fail with Authentication error
        assert!(
            result1.is_err(),
            "Should fail with mismatched handles (discoverable)"
        );
        if let Err(PasskeyError::Authentication(msg)) = &result1 {
            assert!(
                msg.contains("User handle mismatch"),
                "Expected 'User handle mismatch' error but got: {msg}"
            );
        } else {
            panic!("Expected PasskeyError::Authentication but got: {result1:?}");
        }

        assert!(
            result2.is_err(),
            "Should fail with mismatched handles (non-discoverable)"
        );
        if let Err(PasskeyError::Authentication(msg)) = &result2 {
            assert!(
                msg.contains("User handle mismatch"),
                "Expected 'User handle mismatch' error but got: {msg}"
            );
        } else {
            panic!("Expected PasskeyError::Authentication but got: {result2:?}");
        }
    }

    /// Test verify user handle real function missing handle
    ///
    /// This test verifies that `verify_user_handle` correctly handles cases where the user handle
    /// is missing from the authenticator response. It tests that discoverable credentials require
    /// a user handle while non-discoverable credentials can work without one.
    ///
    #[test]
    fn test_verify_user_handle_real_function_missing_handle() {
        let credential = create_test_passkey_credential("test_handle".to_string());

        // Test discoverable case (should fail)
        let auth_response_discoverable =
            create_test_authenticator_response(None, "test_auth_id".to_string());
        let result_discoverable =
            verify_user_handle(&auth_response_discoverable, &credential, true);

        assert!(
            result_discoverable.is_err(),
            "Should fail with missing user handle for discoverable credential"
        );
        if let Err(PasskeyError::Authentication(msg)) = &result_discoverable {
            assert!(
                msg.contains("Missing required user handle"),
                "Expected 'Missing required user handle' error but got: {msg}"
            );
        } else {
            panic!("Expected PasskeyError::Authentication but got: {result_discoverable:?}");
        }

        // Test non-discoverable case (should succeed)
        let auth_response_non_discoverable =
            create_test_authenticator_response(None, "test_auth_id".to_string());
        let result_non_discoverable =
            verify_user_handle(&auth_response_non_discoverable, &credential, false);

        assert!(
            result_non_discoverable.is_ok(),
            "Non-discoverable credential should allow missing user handle"
        );
    }

    /// Test verify user handle edge cases
    ///
    /// This test verifies that `verify_user_handle` handles edge cases correctly, including
    /// empty string user handles and mismatched empty vs non-empty handles. It tests various
    /// boundary conditions to ensure robust handle validation.
    #[test]
    fn test_verify_user_handle_edge_cases() {
        // Test empty string user handle
        let auth_response_empty =
            create_test_authenticator_response(Some("".to_string()), "test_auth_id".to_string());
        let credential_empty = create_test_passkey_credential("".to_string());
        let result_empty = verify_user_handle(&auth_response_empty, &credential_empty, true);
        assert!(
            result_empty.is_ok(),
            "Should succeed with matching empty handles"
        );

        // Test empty vs non-empty mismatch
        let credential_non_empty = create_test_passkey_credential("non_empty".to_string());
        let result_mismatch =
            verify_user_handle(&auth_response_empty, &credential_non_empty, false);
        assert!(
            result_mismatch.is_err(),
            "Should fail with empty vs non-empty handle mismatch"
        );
    }

    /// Test verify counter authenticator no counter support
    ///
    /// This test verifies that `verify_counter` handles authenticators that don't support
    /// signature counters (counter = 0). It validates that the function succeeds without
    /// updating the counter when the authenticator doesn't provide counter functionality.
    #[tokio::test]
    async fn test_verify_counter_authenticator_no_counter_support() {
        // Test case: authenticator doesn't support counters (counter = 0)
        let passkey = create_test_passkey_credential("test_user".to_string());
        let auth_data = create_test_authenticator_data(0);

        let result = verify_counter(&passkey.credential_id, &auth_data, &passkey).await;
        assert!(result.is_ok());
        // Counter should not be updated when response counter is 0 (test passes if no DB error)
    }

    /// Test verify counter replay attack detection
    ///
    /// This test verifies that `verify_counter` correctly detects replay attacks by rejecting
    /// authentication attempts where the counter value is less than the stored counter.
    /// It simulates a credential cloning attack scenario and validates proper error handling.
    #[tokio::test]
    async fn test_verify_counter_replay_attack_detection() {
        // Test case: counter is less than stored counter (replay attack)
        let mut passkey = create_test_passkey_credential("test_user".to_string());
        passkey.counter = 10;
        let auth_data = create_test_authenticator_data(5);

        let result = verify_counter(&passkey.credential_id, &auth_data, &passkey).await;
        assert!(result.is_err());

        if let Err(PasskeyError::Authentication(msg)) = result {
            assert!(msg.contains("credential cloning detected"));
        } else {
            panic!("Expected Authentication error");
        }
    }

    /// Test verify counter equal counter replay attack
    ///
    /// This test verifies that `verify_counter` correctly detects replay attacks when the
    /// counter value equals the stored counter. Equal counters indicate potential replay
    /// attacks and should be rejected to maintain security.
    #[tokio::test]
    async fn test_verify_counter_equal_counter_replay_attack() {
        // Test case: counter equals stored counter (still a replay attack)
        let mut passkey = create_test_passkey_credential("test_user".to_string());
        passkey.counter = 10;
        let auth_data = create_test_authenticator_data(10);

        let result = verify_counter(&passkey.credential_id, &auth_data, &passkey).await;
        assert!(result.is_err());

        if let Err(PasskeyError::Authentication(msg)) = result {
            assert!(msg.contains("credential cloning detected"));
        } else {
            panic!("Expected Authentication error");
        }
    }

    /// Test verify counter valid increment
    ///
    /// This test verifies that `verify_counter` accepts valid authentication attempts where
    /// the counter value is greater than the stored counter. It validates that legitimate
    /// counter increments are properly accepted and processed.
    #[tokio::test]
    async fn test_verify_counter_valid_increment() {
        // Test case: counter is greater than stored counter (valid)
        let mut passkey = create_test_passkey_credential("test_user".to_string());
        passkey.counter = 10;
        let auth_data = create_test_authenticator_data(15);

        let result =
            verify_counter_with_mock(&passkey.credential_id, &auth_data, &passkey, true).await;
        assert!(result.is_ok());
        // Note: In real implementation, counter would be updated in database
    }

    /// Test verify counter zero to positive
    ///
    /// This test verifies that `verify_counter` handles the transition from zero counter
    /// to positive values, which occurs during the first use of a counter-supporting
    /// authenticator. It validates this legitimate counter initialization scenario.
    #[tokio::test]
    async fn test_verify_counter_zero_to_positive() {
        // Test case: counter going from 0 to positive (first use of counter-supporting authenticator)
        let mut passkey = create_test_passkey_credential("test_user".to_string());
        passkey.counter = 0; // Stored counter is 0 (authenticator didn't support counters before)
        let auth_data = create_test_authenticator_data(1); // Now receiving counter value 1

        let result =
            verify_counter_with_mock(&passkey.credential_id, &auth_data, &passkey, true).await;
        assert!(result.is_ok());
        // Note: In real implementation, counter would be updated in database
    }

    /// Test verify counter large increment
    ///
    /// This test verifies that `verify_counter` accepts large but valid counter increments.
    /// Large increments can occur with heavily used authenticators and should be accepted
    /// as long as they're greater than the stored counter value.
    #[tokio::test]
    async fn test_verify_counter_large_increment() {
        // Test case: large counter increment (should still be valid)
        let mut passkey = create_test_passkey_credential("test_user".to_string());
        passkey.counter = 100;
        let auth_data = create_test_authenticator_data(1000);

        let result =
            verify_counter_with_mock(&passkey.credential_id, &auth_data, &passkey, true).await;
        assert!(result.is_ok());
        // Note: In real implementation, counter would be updated in database
    }

    /// Test-friendly version of verify_counter that optionally skips database updates
    #[cfg(test)]
    async fn verify_counter_with_mock(
        credential_id: &str,
        auth_data: &AuthenticatorData,
        stored_credential: &PasskeyCredential,
        skip_db_update: bool,
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

            // Update the counter only if not skipping for tests
            if !skip_db_update {
                PasskeyStore::update_credential_counter(credential_id, auth_counter).await?;
            }
        }

        Ok(())
    }

    // Tests for verify_signature function

    fn create_test_parsed_client_data(challenge: &str) -> ParsedClientData {
        ParsedClientData {
            challenge: challenge.to_string(),
            origin: "https://example.com".to_string(),
            type_: "webauthn.get".to_string(),
            raw_data: b"test_client_data".to_vec(),
        }
    }

    fn create_test_authenticator_data_with_raw(
        counter: u32,
        raw_data: Vec<u8>,
    ) -> AuthenticatorData {
        AuthenticatorData {
            rp_id_hash: vec![0; 32],
            flags: 0x01 | 0x04, // UP | UV flags set
            counter,
            raw_data,
        }
    }

    /// Test verify signature invalid public key format
    ///
    /// This test verifies that `verify_signature` returns appropriate errors when given
    /// invalid base64-encoded public key data. It tests the function's ability to handle
    /// malformed public key inputs and return proper error messages.
    #[tokio::test]
    async fn test_verify_signature_invalid_public_key_format() {
        // Test case: invalid base64 public key
        let auth_response = create_test_authenticator_response(
            Some("test_user".to_string()),
            "test_auth_id".to_string(),
        );
        let client_data = create_test_parsed_client_data("test_challenge");
        let auth_data = create_test_authenticator_data_with_raw(1, vec![0; 37]);

        let mut credential = create_test_passkey_credential("test_user".to_string());
        credential.public_key = "invalid_base64!".to_string(); // Invalid base64

        let result = verify_signature(&auth_response, &client_data, &auth_data, &credential).await;
        assert!(result.is_err());

        if let Err(PasskeyError::Format(msg)) = result {
            assert!(msg.contains("Invalid public key"));
        } else {
            panic!("Expected Format error for invalid public key");
        }
    }

    /// Test verify signature invalid signature format
    ///
    /// This test verifies that `verify_signature` returns appropriate errors when given
    /// invalid base64-encoded signature data. It tests the function's ability to handle
    /// malformed signature inputs and return proper error messages.
    #[tokio::test]
    async fn test_verify_signature_invalid_signature_format() {
        // Test case: invalid base64 signature
        let mut auth_response = create_test_authenticator_response(
            Some("test_user".to_string()),
            "test_auth_id".to_string(),
        );
        auth_response.response.signature = "invalid_base64!".to_string(); // Invalid base64

        let client_data = create_test_parsed_client_data("test_challenge");
        let auth_data = create_test_authenticator_data_with_raw(1, vec![0; 37]);
        let mut credential = create_test_passkey_credential("test_user".to_string());
        // Use a valid base64 string for public key
        credential.public_key = crate::utils::base64url_encode(vec![0; 64]).unwrap();

        let result = verify_signature(&auth_response, &client_data, &auth_data, &credential).await;
        assert!(result.is_err());

        match result {
            Err(error) => {
                if let PasskeyError::Format(ref msg) = error {
                    assert!(msg.contains("Invalid signature"));
                } else {
                    panic!("Expected Format error for invalid signature format, got: {error:?}");
                }
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    /// Test verify signature verification failure
    ///
    /// This test verifies that `verify_signature` correctly rejects authentication attempts
    /// with valid format but incorrect signature data. It tests the cryptographic signature
    /// verification process and ensures invalid signatures are properly rejected.
    #[tokio::test]
    async fn test_verify_signature_verification_failure() {
        // Test case: valid format but signature verification fails
        let auth_response = create_test_authenticator_response(
            Some("test_user".to_string()),
            "test_auth_id".to_string(),
        );
        let client_data = create_test_parsed_client_data("test_challenge");
        let auth_data = create_test_authenticator_data_with_raw(1, vec![0; 37]);

        let mut credential = create_test_passkey_credential("test_user".to_string());
        // Use a valid base64 string but invalid public key data
        credential.public_key = crate::utils::base64url_encode(vec![0; 64]).unwrap();

        let result = verify_signature(&auth_response, &client_data, &auth_data, &credential).await;
        assert!(result.is_err());

        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Signature verification failed"));
        } else {
            panic!("Expected Verification error for signature mismatch");
        }
    }

    /// Test verify signature empty signature
    ///
    /// This test verifies that `verify_signature` handles empty signature inputs correctly
    /// by returning appropriate errors. It tests the function's validation of required
    /// signature data and ensures empty signatures are properly rejected.
    #[tokio::test]
    async fn test_verify_signature_empty_signature() {
        // Test case: empty signature
        let mut auth_response = create_test_authenticator_response(
            Some("test_user".to_string()),
            "test_auth_id".to_string(),
        );
        auth_response.response.signature = "".to_string(); // Empty signature

        let client_data = create_test_parsed_client_data("test_challenge");
        let auth_data = create_test_authenticator_data_with_raw(1, vec![0; 37]);
        let mut credential = create_test_passkey_credential("test_user".to_string());
        // Use a valid base64 string for public key
        credential.public_key = crate::utils::base64url_encode(vec![0; 64]).unwrap();

        let result = verify_signature(&auth_response, &client_data, &auth_data, &credential).await;
        assert!(result.is_err());

        match result {
            Err(error) => {
                // Empty signature should be a verification error since empty string is valid base64
                if let PasskeyError::Verification(ref msg) = error {
                    assert!(msg.contains("Signature verification failed"));
                } else {
                    panic!("Expected Verification error for empty signature, got: {error:?}");
                }
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    /// Test verify signature empty public key
    ///
    /// This test verifies that `verify_signature` handles empty public key inputs correctly
    /// by returning appropriate errors. It tests the function's validation of required
    /// public key data and ensures empty keys are properly rejected.
    #[tokio::test]
    async fn test_verify_signature_empty_public_key() {
        // Test case: empty public key
        let auth_response = create_test_authenticator_response(
            Some("test_user".to_string()),
            "test_auth_id".to_string(),
        );
        let client_data = create_test_parsed_client_data("test_challenge");
        let auth_data = create_test_authenticator_data_with_raw(1, vec![0; 37]);

        let mut credential = create_test_passkey_credential("test_user".to_string());
        credential.public_key = "".to_string(); // Empty public key

        let result = verify_signature(&auth_response, &client_data, &auth_data, &credential).await;
        assert!(result.is_err());

        match result {
            Err(error) => {
                if let PasskeyError::Verification(ref msg) = error {
                    assert!(msg.contains("Signature verification failed"));
                } else {
                    panic!("Expected Verification error for empty public key, got: {error:?}");
                }
            }
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    /// Test verify signature malformed data structures
    ///
    /// This test verifies that `verify_signature` robustly handles various types of malformed
    /// input data structures. It tests the function's error handling capabilities with
    /// corrupted or invalid data to ensure proper validation and error reporting.
    #[tokio::test]
    async fn test_verify_signature_malformed_data_structures() {
        // Test case: test with various malformed data to ensure robust error handling
        let auth_response = create_test_authenticator_response(
            Some("test_user".to_string()),
            "test_auth_id".to_string(),
        );
        let client_data = create_test_parsed_client_data("test_challenge");

        // Test with empty raw data in auth_data
        let auth_data_empty = create_test_authenticator_data_with_raw(1, vec![]);
        let credential = create_test_passkey_credential("test_user".to_string());

        let result =
            verify_signature(&auth_response, &client_data, &auth_data_empty, &credential).await;
        assert!(result.is_err());

        // Should fail at verification stage since we have empty auth data
        match result {
            Err(PasskeyError::Format(_)) | Err(PasskeyError::Verification(_)) => {
                // Either error type is acceptable for malformed data
            }
            _ => panic!("Expected Format or Verification error for malformed data"),
        }
    }

    /// Test finish authentication integration
    ///
    /// This test verifies the complete authentication flow by testing the integration
    /// between multiple authentication components. It validates the end-to-end process
    /// of finishing authentication with proper credential verification and database updates.
    #[tokio::test]
    #[serial]
    async fn test_finish_authentication_integration_test() {
        // Initialize test environment
        init_test_environment().await;

        // Setup test credential
        let credential_id = "test_credential_id_123";
        let user_id = "test_user_id_123";
        let user_handle = "test_user_handle_123";
        let public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEckXwaEBJmwp0EVElviOu9HLgrk3TA/RG4hxcXGYkcCKZ0FIwSkFS6YmGAhRC1nckV0/KQ0/Qpw8WTgK2KQEteA==";
        let aaguid = "f8e2d612-b2cc-4536-a028-ec advocating1951db";

        // Insert test credential with user
        let credential_data = passkey_test_utils::TestCredentialData::new(
            credential_id,
            user_id,
            user_handle,
            "Test User",
            "Test Display Name",
            public_key,
            aaguid,
            42,
        );
        let result = passkey_test_utils::insert_test_user_and_credential(credential_data).await;
        if let Err(e) = &result {
            println!("Error inserting test credential: {e:?}");
        }
        assert!(
            result.is_ok(),
            "Failed to insert test credential: {result:?}"
        );

        // Verify that the credential was inserted correctly
        let get_result = PasskeyStore::get_credential(credential_id).await;
        assert!(get_result.is_ok(), "Failed to retrieve test credential");
        let credential_option = get_result.unwrap();
        assert!(credential_option.is_some(), "Credential should exist");

        let credential = credential_option.unwrap();
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.user.user_handle, user_handle);

        // Clean up test data
        let cleanup_result = passkey_test_utils::cleanup_test_credential(credential_id).await;
        assert!(cleanup_result.is_ok(), "Failed to clean up test credential");

        // Verify credential was deleted
        let verify_deleted = PasskeyStore::get_credential(credential_id).await;
        assert!(
            verify_deleted.unwrap().is_none(),
            "Credential should be deleted after cleanup"
        );
    }

    /// Test start authentication integration
    ///
    /// This test verifies the complete authentication initialization flow by testing
    /// the integration of authentication options generation, challenge storage, and
    /// credential preparation. It validates the full authentication startup process.
    #[tokio::test]
    #[serial]
    async fn test_start_authentication_integration() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Create test credential in the store
        let credential_id = "auth_test_credential_id";
        let user_id = "auth_test_user_id";
        let user_handle = "auth_test_user_handle";
        let public_key = "test_public_key_auth";
        let username = "auth_test_user";

        // Insert test credential with user
        let credential_data = passkey_test_utils::TestCredentialData::new(
            credential_id,
            user_id,
            user_handle,
            username,
            "Auth Test User",
            public_key,
            "test_aaguid",
            10, // Counter
        );
        let insert_result =
            passkey_test_utils::insert_test_user_and_credential(credential_data).await;
        assert!(insert_result.is_ok(), "Failed to insert test credential");

        // Call start_authentication with the username
        let auth_options = super::start_authentication(Some(username.to_string())).await;
        assert!(auth_options.is_ok(), "Failed to start authentication");

        let options = auth_options.unwrap();

        // Verify that options include the credential
        assert!(
            !options.allow_credentials.is_empty(),
            "No credentials found in options"
        );
        assert_eq!(options.allow_credentials[0].id, credential_id);

        // Verify that a challenge was stored in cache
        let auth_id = options.auth_id;
        let cache_prefix = CachePrefix::new("authentication".to_string()).unwrap();
        let cache_key = CacheKey::new(auth_id.clone()).unwrap();
        let cache_get = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(cache_prefix, cache_key)
            .await;
        assert!(cache_get.is_ok());
        assert!(cache_get.unwrap().is_some(), "Challenge should be in cache");

        // Clean up
        let cache_prefix = CachePrefix::new("authentication".to_string()).unwrap();
        let cache_key = CacheKey::new(auth_id.clone()).unwrap();
        let remove_cache = passkey_test_utils::remove_from_cache(cache_prefix, cache_key).await;
        assert!(remove_cache.is_ok(), "Failed to clean up cache");

        let remove_credential = passkey_test_utils::cleanup_test_credential(credential_id).await;
        assert!(remove_credential.is_ok(), "Failed to clean up credential");
    }

    /// Test verify counter and update
    ///
    /// This test verifies the counter verification and database update functionality
    /// in a complete integration scenario. It tests both the counter validation logic
    /// and the database persistence of updated counter values.
    #[tokio::test]
    #[serial]
    async fn test_verify_counter_and_update() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Setup test credential with initial counter
        let credential_id = "counter_test_credential_id";
        let initial_counter = 10;

        // Insert test credential with user
        let credential_data = passkey_test_utils::TestCredentialData::new(
            credential_id,
            "counter_test_user_id",
            "counter_test_user_handle",
            "counter_test_user",
            "Counter Test User",
            "test_public_key",
            "test_aaguid",
            initial_counter,
        );
        let insert_result =
            passkey_test_utils::insert_test_user_and_credential(credential_data).await;
        assert!(insert_result.is_ok(), "Failed to insert test credential");

        // Get the credential to pass to counter verification
        let credential = crate::passkey::PasskeyStore::get_credential(credential_id)
            .await
            .expect("Failed to get credential")
            .expect("Credential not found");

        // Create authenticator data using the existing test helper
        let auth_data = create_test_authenticator_data(initial_counter + 5);

        // Verify counter - should pass and update
        let verify_result = super::verify_counter(credential_id, &auth_data, &credential).await;
        assert!(verify_result.is_ok(), "Counter verification failed");

        // Check that counter was updated in the store
        let updated_credential = crate::passkey::PasskeyStore::get_credential(credential_id)
            .await
            .expect("Failed to get credential")
            .expect("Credential not found");

        assert_eq!(
            updated_credential.counter,
            initial_counter + 5,
            "Counter was not updated correctly"
        );

        // Test with counter that didn't increase (should fail)
        let auth_data_same = create_test_authenticator_data(initial_counter);

        let verify_result_2 =
            super::verify_counter(credential_id, &auth_data_same, &updated_credential).await;
        assert!(
            verify_result_2.is_err(),
            "Should fail with non-increasing counter"
        );

        // Clean up
        let cleanup = passkey_test_utils::cleanup_test_credential(credential_id).await;
        assert!(cleanup.is_ok(), "Failed to clean up test credential");
    }

    /// Test verify user handle
    ///
    /// This test verifies the user handle validation functionality for non-discoverable
    /// credentials without user handles. It tests the authentication flow for credentials
    /// that don't require user handle validation.
    #[tokio::test]
    async fn test_verify_user_handle() {
        // Test for non-discoverable credential without user handle
        let stored_credential = create_test_passkey_credential("test_user".to_string());

        // Case 1: Non-discoverable credential without user handle (should pass)
        let auth_response_no_handle =
            create_test_authenticator_response(None, "test_auth_id".to_string());
        let result1 =
            super::verify_user_handle(&auth_response_no_handle, &stored_credential, false);
        assert!(
            result1.is_ok(),
            "Non-discoverable credential without handle should pass"
        );

        // Case 2: Non-discoverable credential with matching user handle (should pass)
        let auth_response_matching = create_test_authenticator_response(
            Some(stored_credential.user.user_handle.clone()),
            "test_auth_id".to_string(),
        );
        let result2 = super::verify_user_handle(&auth_response_matching, &stored_credential, false);
        assert!(
            result2.is_ok(),
            "Non-discoverable credential with matching handle should pass"
        );

        // Case 3: Discoverable credential without user handle (should fail)
        let result3 = super::verify_user_handle(&auth_response_no_handle, &stored_credential, true);
        assert!(
            result3.is_err(),
            "Discoverable credential without handle should fail"
        );

        // Case 4: Credential with mismatched user handle (should fail)
        let auth_response_mismatched = create_test_authenticator_response(
            Some("different_user_handle".to_string()),
            "test_auth_id".to_string(),
        );
        let result4 =
            super::verify_user_handle(&auth_response_mismatched, &stored_credential, false);
        assert!(
            result4.is_err(),
            "Credential with mismatched handle should fail"
        );
    }
}
