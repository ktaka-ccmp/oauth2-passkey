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
/// * `Ok(CacheKey)` - Generated key for later retrieval
/// * `Err(E)` - Storage error converted to module-specific error type
///
/// # Common Usage Patterns
/// - Session storage: Store user session data with auto-generated session ID
/// - OAuth2 token storage: Store temporary tokens (CSRF, nonce, PKCE) with auto-generated IDs  
/// - Passkey challenge storage: Store WebAuthn challenges with auto-generated challenge IDs
pub async fn store_cache_auto<T, E>(prefix: CachePrefix, data: T, ttl: u64) -> Result<CacheKey, E>
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
            let cache_key = CacheKey::new(generated_key_str).map_err(E::convert_storage_error)?;
            return Ok(cache_key);
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
mod tests;
