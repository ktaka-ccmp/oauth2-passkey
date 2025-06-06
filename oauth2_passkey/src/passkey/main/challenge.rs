use std::time::SystemTime;

use super::utils::{get_from_cache, remove_from_cache};
use crate::passkey::config::PASSKEY_CHALLENGE_TIMEOUT;
use crate::passkey::errors::PasskeyError;
use crate::passkey::types::StoredOptions;

/// Retrieves and validates a stored challenge from the cache
///
/// This function:
/// 1. Retrieves the challenge from the cache using the provided challenge type and ID
/// 2. Validates the challenge TTL (Time-To-Live)
/// 3. Returns the validated StoredOptions if successful
pub(super) async fn get_and_validate_options(
    challenge_type: &str,
    id: &str,
) -> Result<StoredOptions, PasskeyError> {
    let stored_options: StoredOptions = get_from_cache(challenge_type, id)
        .await?
        .ok_or(PasskeyError::NotFound("Challenge not found".to_string()))?;

    // Validate challenge TTL
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now - stored_options.timestamp;
    let timeout = stored_options.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);
    if age > timeout {
        tracing::warn!(
            "Challenge expired after {} seconds (timeout: {})",
            age,
            timeout
        );
        return Err(PasskeyError::Authentication(
            "Challenge has expired. For more details, run with RUST_LOG=debug".into(),
        ));
    }

    tracing::debug!("Found stored challenge: {:?}", stored_options);

    Ok(stored_options)
}

/// Removes a challenge from the cache store after it has been used
///
/// This function is called after a successful registration or authentication
/// to clean up the challenge data from the cache.
pub(super) async fn remove_options(challenge_type: &str, id: &str) -> Result<(), PasskeyError> {
    remove_from_cache(challenge_type, id).await?;
    tracing::debug!("Removed {} options for ID: {}", challenge_type, id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_environment;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_valid_stored_options() -> StoredOptions {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        StoredOptions {
            challenge: "test_challenge".to_string(),
            user: crate::passkey::types::PublicKeyCredentialUserEntity {
                user_handle: "test_user_handle".to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: now,
            ttl: 300, // 5 minutes
        }
    }

    fn create_expired_stored_options() -> StoredOptions {
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 400; // 400 seconds ago

        StoredOptions {
            challenge: "expired_challenge".to_string(),
            user: crate::passkey::types::PublicKeyCredentialUserEntity {
                user_handle: "expired_user_handle".to_string(),
                name: "expired_user".to_string(),
                display_name: "Expired User".to_string(),
            },
            timestamp: old_timestamp,
            ttl: 300, // 5 minutes, but timestamp is old
        }
    }

    #[tokio::test]
    async fn test_get_and_validate_options_success() {
        init_test_environment().await;
        let challenge_type = "registration";
        let id = "test_id";
        let stored_options = create_valid_stored_options();

        // Store the options first using the utils function
        super::super::utils::store_in_cache(
            challenge_type,
            id,
            stored_options.clone(),
            300, // TTL in seconds
        )
        .await
        .expect("Failed to store options");

        // Test retrieval and validation
        let result = get_and_validate_options(challenge_type, id).await;
        assert!(result.is_ok());
        let retrieved_options = result.unwrap();
        assert_eq!(retrieved_options.challenge, stored_options.challenge);
        assert_eq!(retrieved_options.user.name, stored_options.user.name);
    }

    #[tokio::test]
    async fn test_get_and_validate_options_not_found() {
        init_test_environment().await;
        let result = get_and_validate_options("registration", "nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PasskeyError::NotFound(msg) => assert_eq!(msg, "Challenge not found"),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_get_and_validate_options_expired() {
        init_test_environment().await;
        let challenge_type = "registration";
        let id = "expired_id";
        let expired_options = create_expired_stored_options();

        // Store the expired options
        super::super::utils::store_in_cache(
            challenge_type,
            id,
            expired_options,
            300, // TTL in seconds
        )
        .await
        .expect("Failed to store expired options");

        // Test retrieval - should fail due to expiration
        let result = get_and_validate_options(challenge_type, id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PasskeyError::Authentication(msg) => {
                assert!(msg.contains("Challenge has expired"));
            }
            _ => panic!("Expected Authentication error for expired challenge"),
        }
    }

    #[tokio::test]
    async fn test_remove_options_success() {
        init_test_environment().await;
        let challenge_type = "authentication";
        let id = "remove_test";
        let stored_options = create_valid_stored_options();

        // Store the options first
        super::super::utils::store_in_cache(
            challenge_type,
            id,
            stored_options,
            300, // TTL in seconds
        )
        .await
        .expect("Failed to store options");

        // Verify it exists
        let before_removal =
            super::super::utils::get_from_cache::<StoredOptions>(challenge_type, id)
                .await
                .expect("Failed to get from cache");
        assert!(before_removal.is_some());

        // Remove it
        let result = remove_options(challenge_type, id).await;
        assert!(result.is_ok());

        // Verify it's gone
        let after_removal =
            super::super::utils::get_from_cache::<StoredOptions>(challenge_type, id)
                .await
                .expect("Failed to get from cache");
        assert!(after_removal.is_none());
    }

    #[tokio::test]
    async fn test_remove_options_nonexistent() {
        init_test_environment().await;
        // Removing a non-existent entry should not fail
        let result = remove_options("authentication", "nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ttl_validation_with_passkey_timeout() {
        init_test_environment().await;
        let challenge_type = "registration";
        let id = "ttl_test";

        // Create options with very long TTL but should be limited by PASSKEY_CHALLENGE_TIMEOUT
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored_options = StoredOptions {
            challenge: "ttl_test_challenge".to_string(),
            user: crate::passkey::types::PublicKeyCredentialUserEntity {
                user_handle: "ttl_test_user_handle".to_string(),
                name: "ttl_test_user".to_string(),
                display_name: "TTL Test User".to_string(),
            },
            timestamp: now - (*PASSKEY_CHALLENGE_TIMEOUT as u64) - 1, // Just past timeout
            ttl: 86400, // 24 hours - should be ignored
        };

        super::super::utils::store_in_cache(
            challenge_type,
            id,
            stored_options,
            300, // TTL in seconds
        )
        .await
        .expect("Failed to store options");

        // Should be expired due to PASSKEY_CHALLENGE_TIMEOUT limit
        let result = get_and_validate_options(challenge_type, id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PasskeyError::Authentication(msg) => {
                assert!(msg.contains("Challenge has expired"));
            }
            _ => panic!("Expected Authentication error for timeout"),
        }
    }
}
