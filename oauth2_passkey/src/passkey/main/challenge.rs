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
    let (cache_prefix, cache_key) = crate::storage::create_cache_keys(challenge_type, id)
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    let stored_options: StoredOptions = get_from_cache(cache_prefix, cache_key)
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
pub(super) async fn remove_options(
    cache_prefix: crate::storage::CachePrefix,
    cache_key: crate::storage::CacheKey,
) -> Result<(), PasskeyError> {
    remove_from_cache(cache_prefix, cache_key).await?;
    tracing::debug!("Removed challenge options for cache operation");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{CacheData, CacheKey, CachePrefix, GENERIC_CACHE_STORE};
    use crate::test_utils::init_test_environment;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Create a module alias for our test utils
    use crate::passkey::main::test_utils as passkey_test_utils;

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

    /// Test get and validate options success
    ///
    /// This test verifies that `get_and_validate_options` successfully retrieves and validates
    /// stored challenge options from the cache. It stores valid options, retrieves them,
    /// and validates that all fields are preserved correctly during the roundtrip.
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

    /// Test get and validate options not found
    ///
    /// This test verifies that `get_and_validate_options` returns appropriate errors when
    /// attempting to retrieve non-existent challenge options from the cache. It validates
    /// the error handling for missing challenge data.
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

    /// Test get and validate options expired
    ///
    /// This test verifies that `get_and_validate_options` correctly handles expired challenge
    /// options by returning appropriate errors. It stores options with a past expiration time
    /// and validates that they are properly rejected as expired.
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

    /// Test remove options success
    ///
    /// This test verifies that `remove_options` successfully removes stored challenge options
    /// from the cache. It stores options, removes them, and validates that they are no longer
    /// retrievable from the cache system.
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
        let (cache_prefix_verify, cache_key_verify) =
            crate::storage::create_cache_keys(challenge_type, id).unwrap();
        let before_removal = super::super::utils::get_from_cache::<StoredOptions>(
            cache_prefix_verify,
            cache_key_verify,
        )
        .await
        .expect("Failed to get from cache");
        assert!(before_removal.is_some());

        // Remove it
        let (cache_prefix_remove, cache_key_remove) =
            crate::storage::create_cache_keys(challenge_type, id).unwrap();
        let result = remove_options(cache_prefix_remove, cache_key_remove).await;
        assert!(result.is_ok());

        // Verify it's gone
        let (cache_prefix_after, cache_key_after) =
            crate::storage::create_cache_keys(challenge_type, id).unwrap();
        let after_removal = super::super::utils::get_from_cache::<StoredOptions>(
            cache_prefix_after,
            cache_key_after,
        )
        .await
        .expect("Failed to get from cache");
        assert!(after_removal.is_none());
    }

    /// Test remove options nonexistent
    ///
    /// This test verifies that `remove_options` handles attempts to remove non-existent
    /// challenge options gracefully without errors. It validates that the function
    /// succeeds even when the target options don't exist in the cache.
    #[tokio::test]
    async fn test_remove_options_nonexistent() {
        init_test_environment().await;
        // Removing a non-existent entry should not fail
        let (cache_prefix, cache_key) =
            crate::storage::create_cache_keys("authentication", "nonexistent").unwrap();
        let result = remove_options(cache_prefix, cache_key).await;
        assert!(result.is_ok());
    }

    /// Test ttl validation with passkey timeout
    ///
    /// This test verifies TTL (time-to-live) validation logic for challenge options using
    /// the passkey timeout configuration. It tests that TTL calculations are performed
    /// correctly and that timeout validations work as expected.
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

    /// Test options cache basics
    ///
    /// This test verifies basic cache operations for challenge options including storage,
    /// retrieval, and validation. It tests the fundamental caching functionality used
    /// throughout the challenge management system.
    #[tokio::test]
    async fn test_options_cache_basics() {
        init_test_environment().await;

        // Instead of using complex types that depend on serde, test the basic cache functionality
        let test_key = "test_cache_key";
        let test_category = "test_category";
        let test_value = "test_value_123".to_string();

        // Put a simple string value in the cache
        let cache_data = CacheData {
            value: test_value.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store in cache
        let cache_prefix = CachePrefix::new(test_category.to_string()).unwrap();
        let cache_key = CacheKey::new(test_key.to_string()).unwrap();
        let result = GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(cache_prefix, cache_key, cache_data, 300)
            .await;
        assert!(result.is_ok(), "Failed to put test data in cache");

        // Retrieve from cache
        let cache_prefix = CachePrefix::new(test_category.to_string()).unwrap();
        let cache_key = CacheKey::new(test_key.to_string()).unwrap();
        let get_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(cache_prefix, cache_key)
            .await;
        assert!(get_result.is_ok(), "Failed to get test data from cache");

        let retrieved_data = get_result.unwrap();
        assert!(
            retrieved_data.is_some(),
            "Cache should contain our test data"
        );
        assert_eq!(retrieved_data.unwrap().value, test_value);

        // Remove from cache
        let (cache_prefix_remove, cache_key_remove) =
            crate::storage::create_cache_keys(test_category, test_key).unwrap();
        let remove_result =
            passkey_test_utils::remove_from_cache(cache_prefix_remove, cache_key_remove).await;
        assert!(
            remove_result.is_ok(),
            "Failed to remove test data from cache"
        );

        // Verify it's removed
        let cache_prefix = CachePrefix::new(test_category.to_string()).unwrap();
        let cache_key = CacheKey::new(test_key.to_string()).unwrap();
        let final_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(cache_prefix, cache_key)
            .await
            .unwrap();
        assert!(
            final_result.is_none(),
            "Cache should be empty after removal"
        );
    }

    /// Test challenge lifecycle integration
    ///
    /// This test verifies the complete challenge lifecycle from creation to validation
    /// in an integrated environment. It tests challenge generation, storage, retrieval,
    /// and cleanup processes working together as a complete system.
    #[tokio::test]
    async fn test_challenge_lifecycle_integration() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // 1. Create a test challenge
        let challenge_type = "test_challenge";
        let id = "test_challenge_id_lifecycle";
        let challenge_str = "test_challenge_123";
        let user_handle = "test_user_handle_challenge";
        let name = "Test User Challenge";
        let display_name = "Test User Display Name";
        let ttl = 300; // 5 minutes

        let create_result = passkey_test_utils::create_test_challenge(
            challenge_type,
            id,
            challenge_str,
            user_handle,
            name,
            display_name,
            ttl,
        )
        .await;
        assert!(create_result.is_ok(), "Failed to create test challenge");

        // 2. Verify the challenge exists in cache
        let (cache_prefix_exists, cache_key_exists) =
            crate::storage::create_cache_keys(challenge_type, id).unwrap();
        let exists =
            passkey_test_utils::check_cache_exists(cache_prefix_exists, cache_key_exists).await;
        assert!(exists, "Challenge should exist in cache");

        // 3. Validate the challenge
        let validate_result = super::get_and_validate_options(challenge_type, id).await;
        assert!(validate_result.is_ok(), "Challenge validation failed");
        let stored_options = validate_result.unwrap();

        // 4. Verify challenge contents
        assert_eq!(stored_options.challenge, challenge_str);
        assert_eq!(stored_options.user.user_handle, user_handle);
        assert_eq!(stored_options.user.name, name);
        assert_eq!(stored_options.user.display_name, display_name);

        // 5. Remove the challenge
        let (cache_prefix_remove, cache_key_remove) =
            crate::storage::create_cache_keys(challenge_type, id).unwrap();
        let remove_result = super::remove_options(cache_prefix_remove, cache_key_remove).await;
        assert!(remove_result.is_ok(), "Failed to remove challenge");

        // 6. Verify it's gone
        let (cache_prefix_check, cache_key_check) =
            crate::storage::create_cache_keys(challenge_type, id).unwrap();
        let exists_after =
            passkey_test_utils::check_cache_exists(cache_prefix_check, cache_key_check).await;
        assert!(!exists_after, "Challenge should be removed from cache");

        // 7. Try to validate again - should fail with NotFound
        let validate_again = super::get_and_validate_options(challenge_type, id).await;
        assert!(
            validate_again.is_err(),
            "Challenge should not exist anymore"
        );
        match validate_again.unwrap_err() {
            crate::passkey::errors::PasskeyError::NotFound(_) => {
                // Expected error, success
            }
            e => panic!("Expected NotFound error, got: {e:?}"),
        }
    }

    /// Test challenge expiration
    ///
    /// This test verifies that challenge expiration mechanisms work correctly by testing
    /// time-based challenge invalidation. It validates that expired challenges are properly
    /// rejected and that expiration times are enforced correctly.
    #[tokio::test]
    async fn test_challenge_expiration() {
        use crate::passkey::main::test_utils as passkey_test_utils;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;

        // Create a challenge with very short TTL
        let challenge_type = "test_challenge";
        let id = "test_challenge_id_expiration";
        let challenge_str = "test_challenge_expiry";
        let user_handle = "test_user_handle_expiry";
        let name = "Test User Expiry";
        let display_name = "Test User Expiry";
        let ttl = 1; // 1 second TTL

        let create_result = passkey_test_utils::create_test_challenge(
            challenge_type,
            id,
            challenge_str,
            user_handle,
            name,
            display_name,
            ttl,
        )
        .await;
        assert!(create_result.is_ok(), "Failed to create test challenge");

        // Wait for expiration (2 seconds)
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Validate the challenge - should fail with expired error
        let validate_result = super::get_and_validate_options(challenge_type, id).await;

        match validate_result {
            Err(crate::passkey::errors::PasskeyError::Authentication(msg)) => {
                assert!(msg.contains("expired"), "Error should indicate expiration");
            }
            Err(crate::passkey::errors::PasskeyError::NotFound(_)) => {
                // This is also acceptable - cache might have already cleaned it up
            }
            _ => panic!("Expected Authentication or NotFound error for expired challenge"),
        }
    }
}
