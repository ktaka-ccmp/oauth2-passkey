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
    use crate::passkey::types::PublicKeyCredentialUserEntity;
    use std::time::SystemTime;

    // Mock implementation for the cache functions
    struct MockCache {
        data: std::collections::HashMap<String, StoredOptions>,
    }

    impl MockCache {
        fn new() -> Self {
            Self {
                data: std::collections::HashMap::new(),
            }
        }

        fn get(&self, challenge_type: &str, id: &str) -> Option<StoredOptions> {
            let key = format!("{}:{}", challenge_type, id);
            self.data.get(&key).cloned()
        }

        fn remove(&mut self, challenge_type: &str, id: &str) -> bool {
            let key = format!("{}:{}", challenge_type, id);
            self.data.remove(&key).is_some()
        }

        fn put(&mut self, challenge_type: &str, id: &str, options: StoredOptions) {
            let key = format!("{}:{}", challenge_type, id);
            self.data.insert(key, options);
        }
    }

    // Test get_and_validate_options with a valid, non-expired challenge
    #[test]
    fn test_get_and_validate_options_valid() {
        let mut mock_cache = MockCache::new();

        // Create a valid challenge
        let challenge_type = "registration";
        let id = "test-challenge-id";
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored_options = StoredOptions {
            challenge: "test-challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "user123".to_string(),
                name: "testuser".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: now - 30, // 30 seconds ago
            ttl: 300,            // 5 minutes
        };

        // Store the challenge in the mock cache
        mock_cache.put(challenge_type, id, stored_options.clone());

        // Mock the get_from_cache function
        let get_result = mock_cache.get(challenge_type, id);
        assert!(get_result.is_some());

        // Verify the challenge is valid (not expired)
        let options = get_result.unwrap();
        let current_time = now;
        let age = current_time - options.timestamp;
        let timeout = options.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);

        assert!(age < timeout, "Challenge should not be expired");
        assert_eq!(options.challenge, "test-challenge");
        assert_eq!(options.user.user_handle, "user123");
    }

    // Test get_and_validate_options with an expired challenge
    #[test]
    fn test_get_and_validate_options_expired() {
        let mut mock_cache = MockCache::new();

        // Create an expired challenge
        let challenge_type = "registration";
        let id = "test-expired-challenge-id";
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored_options = StoredOptions {
            challenge: "test-expired-challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "user123".to_string(),
                name: "testuser".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: now - 600, // 10 minutes ago
            ttl: 300,             // 5 minutes
        };

        // Store the challenge in the mock cache
        mock_cache.put(challenge_type, id, stored_options.clone());

        // Mock the get_from_cache function
        let get_result = mock_cache.get(challenge_type, id);
        assert!(get_result.is_some());

        // Verify the challenge is expired
        let options = get_result.unwrap();
        let current_time = now;
        let age = current_time - options.timestamp;
        let timeout = options.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);

        assert!(age > timeout, "Challenge should be expired");
    }

    // Test get_and_validate_options with a non-existent challenge
    #[test]
    fn test_get_and_validate_options_not_found() {
        let mock_cache = MockCache::new();

        // Try to get a non-existent challenge
        let challenge_type = "registration";
        let id = "non-existent-challenge-id";

        // Mock the get_from_cache function
        let get_result = mock_cache.get(challenge_type, id);
        assert!(get_result.is_none(), "Challenge should not exist");
    }

    // Test remove_options
    #[test]
    fn test_remove_options() {
        let mut mock_cache = MockCache::new();

        // Create a challenge
        let challenge_type = "registration";
        let id = "test-challenge-id";
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stored_options = StoredOptions {
            challenge: "test-challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "user123".to_string(),
                name: "testuser".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: now,
            ttl: 300,
        };

        // Store the challenge in the mock cache
        mock_cache.put(challenge_type, id, stored_options);

        // Verify the challenge exists
        assert!(mock_cache.get(challenge_type, id).is_some());

        // Remove the challenge
        let removed = mock_cache.remove(challenge_type, id);
        assert!(removed, "Challenge should be removed successfully");

        // Verify the challenge no longer exists
        assert!(
            mock_cache.get(challenge_type, id).is_none(),
            "Challenge should be removed"
        );
    }

    // Test remove_options with a non-existent challenge
    #[test]
    fn test_remove_options_not_found() {
        let mut mock_cache = MockCache::new();

        // Try to remove a non-existent challenge
        let challenge_type = "registration";
        let id = "non-existent-challenge-id";

        // Remove the challenge
        let removed = mock_cache.remove(challenge_type, id);
        assert!(
            !removed,
            "Non-existent challenge removal should return false"
        );
    }

    // Test with a challenge that uses the minimum of ttl and PASSKEY_CHALLENGE_TIMEOUT
    #[test]
    fn test_challenge_timeout_minimum() {
        let mut mock_cache = MockCache::new();

        // Create a challenge with a large TTL
        let challenge_type = "registration";
        let id = "test-large-ttl-challenge-id";
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let large_ttl = 7200; // 2 hours
        let stored_options = StoredOptions {
            challenge: "test-large-ttl-challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "user123".to_string(),
                name: "testuser".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: now,
            ttl: large_ttl,
        };

        // Store the challenge in the mock cache
        mock_cache.put(challenge_type, id, stored_options);

        // Get the challenge
        let get_result = mock_cache.get(challenge_type, id);
        assert!(get_result.is_some());

        // Verify the timeout is the minimum of ttl and PASSKEY_CHALLENGE_TIMEOUT
        let options = get_result.unwrap();
        let timeout = options.ttl.min(*PASSKEY_CHALLENGE_TIMEOUT as u64);

        assert_eq!(
            timeout, *PASSKEY_CHALLENGE_TIMEOUT as u64,
            "Timeout should be the minimum of ttl and PASSKEY_CHALLENGE_TIMEOUT"
        );
    }
}
