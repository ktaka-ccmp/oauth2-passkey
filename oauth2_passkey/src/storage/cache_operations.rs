use crate::storage::{CacheData, CacheKey, CachePrefix, GENERIC_CACHE_STORE, StorageError};
use crate::utils::gen_random_string_with_entropy_validation;

/// Trait for converting storage errors to module-specific error types
pub trait CacheErrorConversion<E> {
    fn convert_storage_error(error: StorageError) -> E;
}

/// Unified cache operations supporting all module patterns with optional collision detection
///
/// This module provides a single, consistent interface for all cache operations across
/// the entire codebase, eliminating the need for module-specific wrapper functions.
///
/// Key features:
/// - Optional collision detection for auto-generated keys
/// - Support for both explicit keys and auto-generated keys
/// - Consistent error handling across all modules
/// - Zero overhead in normal operation (collision detection only retries on actual collisions)
///
/// Store data in cache with optional auto-generated key and collision detection
///
/// # Arguments
/// * `key` - Optional explicit key. If None, a secure random key is auto-generated
/// * `data` - Data to store (must implement Into<CacheData>)
/// * `ttl` - Time to live in seconds
/// * `collision_attempts` - Optional number of collision detection attempts for auto-generated keys
///
/// # Returns
/// * `Ok(Some(String))` - Generated key if key was None
/// * `Ok(None)` - Success when using explicit key
/// * `Err(E)` - Storage error converted to module-specific error type
///
/// # Examples
/// ```rust,no_run
/// // OAuth2: Auto-generate with collision detection  
/// // let token_id = store_data::<_, OAuth2Error>(None, token_data, 3600, Some(20)).await?.unwrap();
///
/// // Session: Explicit key, no collision detection
/// // store_data::<_, SessionError>(Some(&session_id), session_data, 3600, None).await?;
///
/// // Passkey: Could use collision detection for extra safety
/// // let challenge_id = store_data::<_, PasskeyError>(None, challenge_data, 300, Some(3)).await?.unwrap();
/// ```
#[allow(dead_code)]
pub async fn store_data<T, E>(
    key: Option<&str>,
    data: T,
    ttl: u64,
    collision_attempts: Option<usize>,
) -> Result<Option<String>, E>
where
    T: Into<CacheData>,
    E: CacheErrorConversion<E>,
{
    let cache_data = data.into();
    let ttl_usize = ttl.try_into().map_err(|_| {
        E::convert_storage_error(StorageError::InvalidInput(
            "TTL value too large for storage backend".to_string(),
        ))
    })?;

    match key {
        Some(explicit_key) => {
            // Use explicit key (Session, explicit Passkey pattern)
            let (cache_prefix, cache_key) = crate::storage::create_cache_keys("data", explicit_key)
                .map_err(E::convert_storage_error)?;

            GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl(cache_prefix, cache_key, cache_data, ttl_usize)
                .await
                .map_err(E::convert_storage_error)?;

            Ok(None)
        }
        None => {
            // Auto-generate key with optional collision detection (OAuth2 pattern)
            let max_attempts = collision_attempts.unwrap_or(1);

            for attempt in 1..=max_attempts {
                let generated_key = gen_random_string_with_entropy_validation(32).map_err(|e| {
                    E::convert_storage_error(StorageError::InvalidInput(format!(
                        "Key generation failed: {e}"
                    )))
                })?;

                let (cache_prefix, cache_key) =
                    crate::storage::create_cache_keys("data", &generated_key)
                        .map_err(E::convert_storage_error)?;

                let inserted = GENERIC_CACHE_STORE
                    .lock()
                    .await
                    .put_if_not_exists(cache_prefix, cache_key, cache_data.clone(), ttl_usize)
                    .await
                    .map_err(E::convert_storage_error)?;

                if inserted {
                    return Ok(Some(generated_key));
                }

                tracing::debug!(
                    "Collision detected on attempt {} for auto-generated key, retrying...",
                    attempt
                );
            }

            Err(E::convert_storage_error(StorageError::InvalidInput(
                format!("Failed to store data after {max_attempts} collision detection attempts"),
            )))
        }
    }
}

/// Store data with typed cache prefix and key arguments
///
/// This provides truly unified cache operations with type-safe validation at the call boundary.
/// All validation happens when callers construct the typed arguments, not inside this wrapper.
///
/// # Arguments
/// * `prefix` - Validated cache prefix (e.g., CachePrefix::session(), CachePrefix::aaguid())
/// * `key` - Optional validated key. If None, a secure random key is auto-generated and validated
/// * `data` - Data to store (must implement Into<CacheData>)
/// * `ttl` - Time to live in seconds
/// * `collision_attempts` - Optional number of collision detection attempts for auto-generated keys
pub async fn store_data_with_category<T, E>(
    prefix: CachePrefix,
    key: Option<CacheKey>,
    data: T,
    ttl: u64,
    collision_attempts: Option<usize>,
) -> Result<Option<String>, E>
where
    T: Into<CacheData>,
    E: CacheErrorConversion<E>,
{
    let cache_data = data.into();
    let ttl_usize = ttl.try_into().map_err(|_| {
        E::convert_storage_error(StorageError::InvalidInput(
            "TTL value too large for storage backend".to_string(),
        ))
    })?;

    match key {
        Some(explicit_key) => {
            // Use explicit typed key - no validation needed, already done at call site
            GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl(prefix, explicit_key, cache_data, ttl_usize)
                .await
                .map_err(E::convert_storage_error)?;

            Ok(None)
        }
        None => {
            // Auto-generate key with typed prefix - validation happens at generation
            let max_attempts = collision_attempts.unwrap_or(1);

            for attempt in 1..=max_attempts {
                let generated_key_str =
                    gen_random_string_with_entropy_validation(32).map_err(|e| {
                        E::convert_storage_error(StorageError::InvalidInput(format!(
                            "Key generation failed: {e}"
                        )))
                    })?;

                // Create typed key from generated string - validation happens here
                let cache_key =
                    CacheKey::new(generated_key_str.clone()).map_err(E::convert_storage_error)?;

                let inserted = GENERIC_CACHE_STORE
                    .lock()
                    .await
                    .put_if_not_exists(prefix.clone(), cache_key, cache_data.clone(), ttl_usize)
                    .await
                    .map_err(E::convert_storage_error)?;

                if inserted {
                    return Ok(Some(generated_key_str));
                }

                tracing::debug!(
                    "Collision detected on attempt {} for auto-generated key, retrying...",
                    attempt
                );
            }

            Err(E::convert_storage_error(StorageError::InvalidInput(
                format!("Failed to store data after {max_attempts} collision detection attempts"),
            )))
        }
    }
}

/// Retrieve data from cache
///
/// # Arguments
/// * `cache_prefix` - Typed cache prefix
/// * `cache_key` - Typed cache key
///
/// # Returns
/// * `Ok(Some(T))` - Data found and successfully converted
/// * `Ok(None)` - Data not found or expired
/// * `Err(E)` - Storage or conversion error
pub async fn get_data<T, E>(cache_prefix: CachePrefix, cache_key: CacheKey) -> Result<Option<T>, E>
where
    T: TryFrom<CacheData, Error = E>,
    E: CacheErrorConversion<E>,
{
    match GENERIC_CACHE_STORE
        .lock()
        .await
        .get(cache_prefix, cache_key)
        .await
        .map_err(E::convert_storage_error)?
    {
        Some(cache_data) => {
            let converted_data = T::try_from(cache_data)?;
            Ok(Some(converted_data))
        }
        None => Ok(None),
    }
}

/// Retrieve data from cache using typed prefix and key
///
/// This provides truly unified cache operations with type-safe validation at the call boundary.
/// All validation happens when callers construct the typed arguments, not inside this wrapper.
///
/// # Arguments
/// * `prefix` - Validated cache prefix (e.g., CachePrefix::session(), CachePrefix::aaguid())
/// * `key` - Validated cache key
pub async fn get_data_by_category<T, E>(prefix: CachePrefix, key: CacheKey) -> Result<Option<T>, E>
where
    T: TryFrom<CacheData, Error = E>,
    E: CacheErrorConversion<E>,
{
    get_data(prefix, key).await
}

/// Remove data from cache
///
/// # Arguments
/// * `cache_prefix` - Typed cache prefix
/// * `cache_key` - Typed cache key
pub async fn remove_data<E>(cache_prefix: CachePrefix, cache_key: CacheKey) -> Result<(), E>
where
    E: CacheErrorConversion<E>,
{
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(cache_prefix, cache_key)
        .await
        .map_err(E::convert_storage_error)
}

/// Remove data from cache using typed prefix and key
///
/// This provides truly unified cache operations with type-safe validation at the call boundary.
/// All validation happens when callers construct the typed arguments, not inside this wrapper.
///
/// # Arguments
/// * `prefix` - Validated cache prefix (e.g., CachePrefix::session(), CachePrefix::aaguid())
/// * `key` - Validated cache key
pub async fn remove_data_by_category<E>(prefix: CachePrefix, key: CacheKey) -> Result<(), E>
where
    E: CacheErrorConversion<E>,
{
    remove_data(prefix, key).await
}

/// Store data with manual expiration using typed prefix and key
///
/// This provides truly unified cache operations with type-safe validation at the call boundary.
/// All validation happens when callers construct the typed arguments, not inside this wrapper.
///
/// # Arguments
/// * `prefix` - Validated cache prefix (e.g., CachePrefix::aaguid())
/// * `key` - Validated cache key
/// * `data` - Data to store with pre-set expiration in CacheData
pub async fn store_data_with_manual_expiration<T, E>(
    prefix: CachePrefix,
    key: CacheKey,
    data: T,
) -> Result<(), E>
where
    T: Into<CacheData>,
    E: CacheErrorConversion<E>,
{
    let cache_data = data.into();

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put(prefix, key, cache_data)
        .await
        .map_err(E::convert_storage_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CacheData;
    use crate::test_utils::init_test_environment;
    use chrono::Utc;

    #[derive(Debug, PartialEq)]
    pub struct TestError(String);

    impl CacheErrorConversion<TestError> for TestError {
        fn convert_storage_error(error: StorageError) -> TestError {
            TestError(error.to_string())
        }
    }

    impl TryFrom<CacheData> for String {
        type Error = TestError;

        fn try_from(cache_data: CacheData) -> Result<Self, Self::Error> {
            Ok(cache_data.value)
        }
    }

    impl From<String> for CacheData {
        fn from(value: String) -> Self {
            CacheData {
                value,
                expires_at: Utc::now() + chrono::Duration::hours(1),
            }
        }
    }

    #[tokio::test]
    async fn test_store_data_with_explicit_key() {
        init_test_environment().await;

        let test_data = "test_value".to_string();
        let result =
            store_data::<_, TestError>(Some("test_key"), test_data.clone(), 3600, None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None); // Explicit key returns None

        // Verify data can be retrieved
        let retrieved = get_data_by_category::<String, TestError>(
            CachePrefix::new("data".to_string()).unwrap(),
            CacheKey::new("test_key".to_string()).unwrap(),
        )
        .await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));
    }

    #[tokio::test]
    async fn test_store_data_with_auto_generated_key() {
        init_test_environment().await;

        let test_data = "test_value".to_string();
        let result = store_data::<_, TestError>(None, test_data.clone(), 3600, Some(1)).await;

        assert!(result.is_ok());
        let generated_key = result.unwrap().unwrap(); // Auto-generated key returns Some(key)
        assert!(!generated_key.is_empty());

        // Verify data can be retrieved with the generated key
        let retrieved = get_data_by_category::<String, TestError>(
            CachePrefix::new("data".to_string()).unwrap(),
            CacheKey::new(generated_key.clone()).unwrap(),
        )
        .await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));
    }

    #[tokio::test]
    async fn test_store_data_with_category() {
        init_test_environment().await;

        let test_data = "test_value".to_string();
        let result = store_data_with_category::<_, TestError>(
            CachePrefix::new("test_category".to_string()).unwrap(),
            Some(CacheKey::new("test_key".to_string()).unwrap()),
            test_data.clone(),
            3600,
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);

        // Verify data can be retrieved
        let retrieved = get_data_by_category::<String, TestError>(
            CachePrefix::new("test_category".to_string()).unwrap(),
            CacheKey::new("test_key".to_string()).unwrap(),
        )
        .await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));
    }

    #[tokio::test]
    async fn test_remove_data() {
        init_test_environment().await;

        let test_data = "test_value".to_string();

        // Store data
        store_data::<_, TestError>(Some("test_key"), test_data.clone(), 3600, None)
            .await
            .unwrap();

        // Verify it exists
        let retrieved = get_data_by_category::<String, TestError>(
            CachePrefix::new("data".to_string()).unwrap(),
            CacheKey::new("test_key".to_string()).unwrap(),
        )
        .await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));

        // Remove data
        let result = remove_data_by_category::<TestError>(
            CachePrefix::new("data".to_string()).unwrap(),
            CacheKey::new("test_key".to_string()).unwrap(),
        )
        .await;
        assert!(result.is_ok());

        // Verify it's gone
        let retrieved = get_data_by_category::<String, TestError>(
            CachePrefix::new("data".to_string()).unwrap(),
            CacheKey::new("test_key".to_string()).unwrap(),
        )
        .await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), None);
    }

    #[tokio::test]
    async fn test_truly_unified_cache_operations_with_validation() {
        init_test_environment().await;

        // Test that we have truly unified cache operations:
        // 1. All operations use the same typed interface
        // 2. Validation happens at caller boundary
        // 3. No validation inside wrappers

        // Valid typed arguments should work for all operations
        let prefix = CachePrefix::session();
        let key = CacheKey::new("test_unified_key".to_string()).unwrap();
        let data = "unified_test_data".to_string();

        // Store using typed arguments
        let store_result = store_data_with_category::<_, TestError>(
            prefix.clone(),
            Some(key.clone()),
            data.clone(),
            300,
            None,
        )
        .await;
        assert!(store_result.is_ok());

        // Retrieve using same typed arguments
        let get_result =
            get_data_by_category::<String, TestError>(prefix.clone(), key.clone()).await;
        assert!(get_result.is_ok());
        assert_eq!(get_result.unwrap(), Some(data));

        // Remove using same typed arguments
        let remove_result = remove_data_by_category::<TestError>(prefix.clone(), key.clone()).await;
        assert!(remove_result.is_ok());

        // Verify removal
        let verify_result = get_data_by_category::<String, TestError>(prefix, key).await;
        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), None);

        // Test validation at caller boundary - malicious inputs should be rejected
        // BEFORE reaching any cache operations
        let malicious_key_result = CacheKey::new("malicious\nSET attack".to_string());
        assert!(
            malicious_key_result.is_err(),
            "Malicious key should be rejected at construction"
        );

        let malicious_prefix_result = CachePrefix::new("SET attack".to_string());
        assert!(
            malicious_prefix_result.is_err(),
            "Malicious prefix should be rejected at construction"
        );

        // This proves we have truly unified cache operations with validation at the right boundary
    }
}
