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
/// ## Cache Retrieval Functions
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

/// Simple cache operations for auto-generated keys (90% of usage)
///
/// This function covers the most common cache pattern: storing data with
/// an auto-generated unique key. The key is returned for later retrieval.
///
/// Uses 20 collision detection attempts for high reliability. With 32-character
/// random keys (~192 bits entropy), collisions are extremely rare in practice.
///
/// # Arguments
/// * `prefix` - Cache prefix (e.g., CachePrefix::session(), CachePrefix::oauth2())
/// * `data` - Data to store (must implement Into<CacheData>)
/// * `ttl` - Time to live in seconds
///
/// # Returns
/// * `Ok(String)` - Generated key for later retrieval
/// * `Err(E)` - Storage error converted to module-specific error type
///
/// # Common Usage Patterns
/// - Session storage: Store user session data with auto-generated session ID
/// - OAuth2 token storage: Store temporary tokens (CSRF, nonce, PKCE) with auto-generated IDs  
/// - Passkey challenge storage: Store WebAuthn challenges with auto-generated challenge IDs
pub async fn store_cache_auto<T, E>(prefix: CachePrefix, data: T, ttl: u64) -> Result<String, E>
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

    // Auto-generate key with collision detection (fixed high default for reliability)
    let max_attempts = 20;

    for attempt in 1..=max_attempts {
        let generated_key_str = gen_random_string_with_entropy_validation(32).map_err(|e| {
            E::convert_storage_error(StorageError::InvalidInput(format!(
                "Key generation failed: {e}"
            )))
        })?;

        // Create typed key from generated string
        let cache_key =
            CacheKey::new(generated_key_str.clone()).map_err(E::convert_storage_error)?;

        let inserted = GENERIC_CACHE_STORE
            .lock()
            .await
            .put_if_not_exists(prefix.clone(), cache_key, cache_data.clone(), ttl_usize)
            .await
            .map_err(E::convert_storage_error)?;

        if inserted {
            return Ok(generated_key_str);
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

/// Simple cache operations for meaningful external keys (10% of usage)
///
/// This function covers the less common but important pattern: storing data
/// with a meaningful external identifier as the key.
///
/// # Arguments
/// * `prefix` - Cache prefix (e.g., CachePrefix::aaguid(), CachePrefix::jwks())
/// * `key` - Meaningful external key (e.g., AAGUID, JWKS URL)
/// * `data` - Data to store (must implement Into<CacheData>)
/// * `ttl` - Time to live in seconds
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(E)` - Storage error converted to module-specific error type
///
/// # Common Usage Patterns
/// - AAGUID metadata storage: Cache authenticator metadata using AAGUID as the key
/// - JWKS URL caching: Cache JSON Web Key Sets using the JWKS URL as the key
pub async fn store_cache_keyed<T, E>(
    prefix: CachePrefix,
    key: CacheKey,
    data: T,
    ttl: u64,
) -> Result<(), E>
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

    // Store with explicit meaningful key - direct to cache store
    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(prefix, key, cache_data, ttl_usize)
        .await
        .map_err(E::convert_storage_error)
}

/// Retrieve data from cache (works with both auto-generated and meaningful keys)
///
/// # Arguments
/// * `prefix` - Cache prefix used when storing
/// * `key` - Cache key (either auto-generated or meaningful)
///
/// # Returns
/// * `Ok(Some(T))` - Data found and successfully converted
/// * `Ok(None)` - Data not found or expired
/// * `Err(E)` - Storage or conversion error
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
    async fn test_store_cache_keyed_legacy_compatibility() {
        init_test_environment().await;

        let test_data = "test_value".to_string();
        let prefix = CachePrefix::new("data".to_string()).unwrap();
        let key = CacheKey::new("test_key".to_string()).unwrap();

        let result =
            store_cache_keyed::<_, TestError>(prefix.clone(), key.clone(), test_data.clone(), 3600)
                .await;
        assert!(result.is_ok());

        // Verify data can be retrieved
        let retrieved = get_data::<String, TestError>(prefix, key).await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));
    }

    #[tokio::test]
    async fn test_store_cache_auto_legacy_compatibility() {
        init_test_environment().await;

        let test_data = "test_value".to_string();
        let prefix = CachePrefix::new("data".to_string()).unwrap();

        let result =
            store_cache_auto::<_, TestError>(prefix.clone(), test_data.clone(), 3600).await;
        assert!(result.is_ok());
        let generated_key = result.unwrap();
        assert!(!generated_key.is_empty());

        // Verify data can be retrieved with the generated key
        let key = CacheKey::new(generated_key).unwrap();
        let retrieved = get_data::<String, TestError>(prefix, key).await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));
    }

    #[tokio::test]
    async fn test_remove_data() {
        init_test_environment().await;

        let test_data = "test_value".to_string();
        let prefix = CachePrefix::new("data".to_string()).unwrap();
        let key = CacheKey::new("test_key".to_string()).unwrap();

        // Store data using simplified API
        store_cache_keyed::<_, TestError>(prefix.clone(), key.clone(), test_data.clone(), 3600)
            .await
            .unwrap();

        // Verify it exists using simplified API
        let retrieved = get_data::<String, TestError>(prefix.clone(), key.clone()).await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));

        // Remove data using simplified API
        let result = remove_data::<TestError>(prefix.clone(), key.clone()).await;
        assert!(result.is_ok());

        // Verify it's gone using simplified API
        let retrieved = get_data::<String, TestError>(prefix, key).await;
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

        // Store using typed arguments with simplified API
        let store_result =
            store_cache_keyed::<_, TestError>(prefix.clone(), key.clone(), data.clone(), 300).await;
        assert!(store_result.is_ok());

        // Retrieve using same typed arguments
        let get_result = get_data::<String, TestError>(prefix.clone(), key.clone()).await;
        assert!(get_result.is_ok());
        assert_eq!(get_result.unwrap(), Some(data));

        // Remove using same typed arguments
        let remove_result = remove_data::<TestError>(prefix.clone(), key.clone()).await;
        assert!(remove_result.is_ok());

        // Verify removal
        let verify_result = get_data::<String, TestError>(prefix, key).await;
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

    #[tokio::test]
    async fn test_store_cache_auto_simple_api() {
        init_test_environment().await;

        let test_data = "auto_generated_test_data".to_string();
        let prefix = CachePrefix::new("test_auto".to_string()).unwrap();

        // Store with auto-generated key
        let result = store_cache_auto::<_, TestError>(prefix.clone(), test_data.clone(), 300).await;
        assert!(result.is_ok());

        let generated_key = result.unwrap();
        assert!(!generated_key.is_empty());
        assert!(generated_key.len() >= 32); // Should be at least 32 chars for good entropy

        // Retrieve using the generated key
        let cache_key = CacheKey::new(generated_key.clone()).unwrap();
        let retrieved = get_data::<String, TestError>(prefix.clone(), cache_key.clone()).await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));

        // Clean up
        let remove_result = remove_data::<TestError>(prefix, cache_key).await;
        assert!(remove_result.is_ok());
    }

    #[tokio::test]
    async fn test_store_cache_keyed_simple_api() {
        init_test_environment().await;

        let test_data = "meaningful_key_test_data".to_string();
        let prefix = CachePrefix::new("test_keyed".to_string()).unwrap();
        let meaningful_key = CacheKey::new("aaguid_12345678".to_string()).unwrap();

        // Store with meaningful key
        let result = store_cache_keyed::<_, TestError>(
            prefix.clone(),
            meaningful_key.clone(),
            test_data.clone(),
            300,
        )
        .await;
        assert!(result.is_ok());

        // Retrieve using the meaningful key
        let retrieved = get_data::<String, TestError>(prefix.clone(), meaningful_key.clone()).await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_data));

        // Clean up
        let remove_result = remove_data::<TestError>(prefix, meaningful_key).await;
        assert!(remove_result.is_ok());
    }

    #[tokio::test]
    async fn test_simplified_api_demonstration() {
        init_test_environment().await;

        // This test demonstrates the simplified cache API design

        let test_data = "api_demo_test_data".to_string();
        let prefix = CachePrefix::new("api_demo".to_string()).unwrap();

        // SIMPLE AUTO-GENERATED KEY API (most common case - 90% of usage)
        let auto_result =
            store_cache_auto::<_, TestError>(prefix.clone(), test_data.clone(), 300).await;
        assert!(auto_result.is_ok());
        let generated_key: String = auto_result.unwrap(); // Type inference works!

        // SIMPLE MEANINGFUL KEY API (less common case - 10% of usage)
        let meaningful_key = CacheKey::new("meaningful_identifier".to_string()).unwrap();
        let keyed_result = store_cache_keyed::<_, TestError>(
            prefix.clone(),
            meaningful_key.clone(),
            test_data.clone(),
            300,
        )
        .await;
        assert!(keyed_result.is_ok());

        // Verify both approaches work correctly
        let auto_key = CacheKey::new(generated_key).unwrap();
        let auto_retrieved = get_data::<String, TestError>(prefix.clone(), auto_key).await;
        let keyed_retrieved = get_data::<String, TestError>(prefix, meaningful_key).await;

        assert!(auto_retrieved.is_ok());
        assert!(keyed_retrieved.is_ok());
        assert_eq!(auto_retrieved.unwrap(), Some(test_data.clone()));
        assert_eq!(keyed_retrieved.unwrap(), Some(test_data));
    }
}
