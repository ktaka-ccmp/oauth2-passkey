use std::time::SystemTime;

use crate::passkey::config::PASSKEY_CHALLENGE_TIMEOUT;
use crate::passkey::errors::PasskeyError;
use crate::passkey::types::StoredOptions;
use crate::storage::{CacheErrorConversion, CacheKey, CachePrefix, get_data, remove_data};

/// Retrieves and validates a stored challenge from the cache
///
/// This function:
/// 1. Retrieves the challenge from the cache using the provided challenge type and ID
/// 2. Validates the challenge TTL (Time-To-Live)
/// 3. Returns the validated StoredOptions if successful
pub(super) async fn get_and_validate_options(
    challenge_type: &crate::passkey::types::ChallengeType,
    id: &crate::passkey::types::ChallengeId,
) -> Result<StoredOptions, PasskeyError> {
    let cache_prefix = CachePrefix::new(challenge_type.as_str().to_string())
        .map_err(PasskeyError::convert_storage_error)?;
    let cache_key =
        CacheKey::new(id.as_str().to_string()).map_err(PasskeyError::convert_storage_error)?;

    let stored_options: StoredOptions =
        get_data::<StoredOptions, PasskeyError>(cache_prefix, cache_key)
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
    remove_data::<PasskeyError>(cache_prefix, cache_key).await?;
    tracing::debug!("Removed challenge options for cache operation");

    Ok(())
}

#[cfg(test)]
mod tests;
