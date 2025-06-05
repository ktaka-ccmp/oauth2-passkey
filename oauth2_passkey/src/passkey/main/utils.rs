use crate::storage::{CacheData, CacheStore, GENERIC_CACHE_STORE};

use crate::passkey::PasskeyError;
use crate::passkey::PasskeyStore;
use crate::passkey::{CredentialSearchField, types::UserIdCredentialIdStr};

async fn get_credential_id_strs_by(
    field: CredentialSearchField,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    let stored_credentials = PasskeyStore::get_credentials_by(field).await?;

    let credential_id_strs = stored_credentials
        .into_iter()
        .map(|cred| UserIdCredentialIdStr {
            user_id: cred.user_id,
            credential_id: cred.credential_id,
        })
        .collect();

    Ok(credential_id_strs)
}

pub(super) async fn name2cid_str_vec(
    name: &str,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    get_credential_id_strs_by(CredentialSearchField::UserName(name.to_string())).await
}

/// Helper function to store data in the cache with optional custom cache store
pub(super) async fn store_in_cache_with_store<T>(
    cache_store: Option<&tokio::sync::Mutex<Box<dyn CacheStore>>>,
    category: &str,
    key: &str,
    data: T,
    ttl: usize,
) -> Result<(), PasskeyError>
where
    T: Into<CacheData>,
{
    let store = cache_store.unwrap_or(&GENERIC_CACHE_STORE);
    store
        .lock()
        .await
        .put_with_ttl(category, key, data.into(), ttl)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Helper function to retrieve data from the cache with optional custom cache store
pub(super) async fn get_from_cache_with_store<T>(
    cache_store: Option<&tokio::sync::Mutex<Box<dyn CacheStore>>>,
    category: &str,
    key: &str,
) -> Result<Option<T>, PasskeyError>
where
    T: TryFrom<CacheData, Error = PasskeyError>,
{
    let store = cache_store.unwrap_or(&GENERIC_CACHE_STORE);
    let data = store
        .lock()
        .await
        .get(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    match data {
        Some(value) => Ok(Some(value.try_into()?)),
        None => Ok(None),
    }
}

/// Helper function to remove data from the cache with optional custom cache store
pub(super) async fn remove_from_cache_with_store(
    cache_store: Option<&tokio::sync::Mutex<Box<dyn CacheStore>>>,
    category: &str,
    key: &str,
) -> Result<(), PasskeyError> {
    let store = cache_store.unwrap_or(&GENERIC_CACHE_STORE);
    store
        .lock()
        .await
        .remove(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Helper function to store data in the cache
pub(super) async fn store_in_cache<T>(
    category: &str,
    key: &str,
    data: T,
    ttl: usize,
) -> Result<(), PasskeyError>
where
    T: Into<CacheData>,
{
    store_in_cache_with_store(None, category, key, data, ttl).await
}

/// Helper function to retrieve data from the cache
pub(super) async fn get_from_cache<T>(category: &str, key: &str) -> Result<Option<T>, PasskeyError>
where
    T: TryFrom<CacheData, Error = PasskeyError>,
{
    get_from_cache_with_store(None, category, key).await
}

/// Helper function to remove data from the cache
pub(super) async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {
    remove_from_cache_with_store(None, category, key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::types::PublicKeyCredentialUserEntity;
    use crate::passkey::types::StoredOptions;
    use crate::storage::{CacheStore, InMemoryCacheStore};
    use tokio::sync::Mutex;

    /// Helper function to create a test cache store
    fn create_test_cache() -> Mutex<Box<dyn CacheStore>> {
        Mutex::new(Box::new(InMemoryCacheStore::new()))
    }

    // Test the CacheData conversion for StoredOptions
    #[test]
    fn test_stored_options_cache_data_conversion() {
        // Create a test StoredOptions
        let options = StoredOptions {
            challenge: "test_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "test_user_handle".to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: 1622505600, // June 1, 2021
            ttl: 300,              // 5 minutes
        };

        // Convert to CacheData
        let cache_data: CacheData = options.clone().into();

        // Verify the conversion worked
        assert!(!cache_data.value.is_empty());
        assert!(cache_data.value.contains("test_challenge"));
        assert!(cache_data.value.contains("test_user_handle"));

        // Convert back to StoredOptions
        let converted_options: Result<StoredOptions, _> = cache_data.try_into();
        assert!(converted_options.is_ok());

        let converted = converted_options.unwrap();
        assert_eq!(converted.challenge, options.challenge);
        assert_eq!(converted.user.user_handle, options.user.user_handle);
        assert_eq!(converted.timestamp, options.timestamp);
        assert_eq!(converted.ttl, options.ttl);
    }

    // Test CacheData conversion with edge cases (empty strings, special characters)
    #[test]
    fn test_stored_options_cache_data_conversion_edge_cases() {
        // Create StoredOptions with edge case values
        let options = StoredOptions {
            challenge: "".to_string(), // Empty challenge
            user: PublicKeyCredentialUserEntity {
                user_handle: "user@example.com".to_string(), // Email-like handle
                name: "".to_string(),                        // Empty name
                display_name: "User with Special Chars: !@#$%^&*()".to_string(), // Special characters
            },
            timestamp: 0, // Zero timestamp
            ttl: 1,       // Minimum TTL
        };

        // Convert to CacheData and back
        let cache_data: CacheData = options.clone().into();
        let converted_options: Result<StoredOptions, _> = cache_data.try_into();

        assert!(converted_options.is_ok());
        let converted = converted_options.unwrap();

        // Verify all fields are preserved correctly
        assert_eq!(converted.challenge, options.challenge);
        assert_eq!(converted.user.user_handle, options.user.user_handle);
        assert_eq!(converted.user.name, options.user.name);
        assert_eq!(converted.user.display_name, options.user.display_name);
        assert_eq!(converted.timestamp, options.timestamp);
        assert_eq!(converted.ttl, options.ttl);
    }

    // Test cache operations with dependency injection (NEW FUNCTIONALITY)
    #[tokio::test]
    async fn test_cache_operations_with_dependency_injection() {
        let test_cache = create_test_cache();
        let category = "test_category";
        let key = "test_key";

        // Create test data
        let options = StoredOptions {
            challenge: "injection_test_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "injection_user_handle".to_string(),
                name: "injection_user".to_string(),
                display_name: "Injection Test User".to_string(),
            },
            timestamp: 1622505600,
            ttl: 300,
        };

        // Test storing data with custom cache store
        let store_result =
            store_in_cache_with_store(Some(&test_cache), category, key, options.clone(), 300).await;
        assert!(store_result.is_ok());

        // Test retrieving data with custom cache store
        let retrieved: Result<Option<StoredOptions>, _> =
            get_from_cache_with_store(Some(&test_cache), category, key).await;
        assert!(retrieved.is_ok());

        let retrieved_options = retrieved.unwrap();
        assert!(retrieved_options.is_some());

        let retrieved_data = retrieved_options.unwrap();
        assert_eq!(retrieved_data.challenge, options.challenge);
        assert_eq!(retrieved_data.user.user_handle, options.user.user_handle);
        assert_eq!(retrieved_data.timestamp, options.timestamp);

        // Test removing data with custom cache store
        let remove_result = remove_from_cache_with_store(Some(&test_cache), category, key).await;
        assert!(remove_result.is_ok());

        // Verify data is gone
        let after_remove: Result<Option<StoredOptions>, _> =
            get_from_cache_with_store(Some(&test_cache), category, key).await;
        assert!(after_remove.is_ok());
        assert!(after_remove.unwrap().is_none());
    }

    // Test that different cache stores are isolated
    #[tokio::test]
    async fn test_cache_store_isolation() {
        let cache1 = create_test_cache();
        let cache2 = create_test_cache();
        let category = "isolation_test";
        let key = "same_key";

        let data1 = StoredOptions {
            challenge: "cache1_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "cache1_user".to_string(),
                name: "cache1".to_string(),
                display_name: "Cache 1 User".to_string(),
            },
            timestamp: 1111,
            ttl: 100,
        };

        let data2 = StoredOptions {
            challenge: "cache2_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "cache2_user".to_string(),
                name: "cache2".to_string(),
                display_name: "Cache 2 User".to_string(),
            },
            timestamp: 2222,
            ttl: 200,
        };

        // Store different data in different cache stores with same key
        let _ = store_in_cache_with_store(Some(&cache1), category, key, data1.clone(), 100).await;
        let _ = store_in_cache_with_store(Some(&cache2), category, key, data2.clone(), 200).await;

        // Verify each cache returns its own data
        let retrieved1: Option<StoredOptions> =
            get_from_cache_with_store(Some(&cache1), category, key)
                .await
                .unwrap();
        let retrieved2: Option<StoredOptions> =
            get_from_cache_with_store(Some(&cache2), category, key)
                .await
                .unwrap();

        assert!(retrieved1.is_some());
        assert!(retrieved2.is_some());

        let data_from_cache1 = retrieved1.unwrap();
        let data_from_cache2 = retrieved2.unwrap();

        assert_eq!(data_from_cache1.challenge, "cache1_challenge");
        assert_eq!(data_from_cache2.challenge, "cache2_challenge");
        assert_eq!(data_from_cache1.timestamp, 1111);
        assert_eq!(data_from_cache2.timestamp, 2222);
    }

    // Test fallback to global cache when None is passed
    #[tokio::test]
    async fn test_fallback_to_global_cache() {
        // Set required environment variables for global cache
        unsafe {
            std::env::set_var("GENERIC_CACHE_STORE_TYPE", "memory");
            std::env::set_var("GENERIC_CACHE_STORE_URL", "memory://test");
        }

        let category = "fallback_test";
        let key = "fallback_key";

        let options = StoredOptions {
            challenge: "fallback_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "fallback_user".to_string(),
                name: "fallback".to_string(),
                display_name: "Fallback Test User".to_string(),
            },
            timestamp: 9999,
            ttl: 500,
        };

        // Test with explicit None - should use global cache
        let store_result =
            store_in_cache_with_store(None, category, key, options.clone(), 500).await;
        assert!(store_result.is_ok());

        // Verify using original function (which should also use global cache)
        let retrieved: Result<Option<StoredOptions>, _> = get_from_cache(category, key).await;
        assert!(retrieved.is_ok());

        let retrieved_data = retrieved.unwrap();
        assert!(retrieved_data.is_some());
        assert_eq!(retrieved_data.unwrap().challenge, "fallback_challenge");

        // Clean up
        let _ = remove_from_cache(category, key).await;
    }

    // Test cache operations (store, get, remove) - EXISTING TEST (for global cache)
    #[tokio::test]
    async fn test_cache_operations() {
        // Set required environment variables for cache
        unsafe {
            std::env::set_var("GENERIC_CACHE_STORE_TYPE", "memory");
            std::env::set_var("GENERIC_CACHE_STORE_URL", "memory://test");
        }

        let category = "test_category";
        let key = "test_key";

        // Create test data
        let options = StoredOptions {
            challenge: "cache_test_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "cache_user_handle".to_string(),
                name: "cache_user".to_string(),
                display_name: "Cache Test User".to_string(),
            },
            timestamp: 1622505600,
            ttl: 300,
        };

        // Test storing data
        let store_result = store_in_cache(category, key, options.clone(), 300).await;
        assert!(store_result.is_ok());

        // Test retrieving data
        let retrieved: Result<Option<StoredOptions>, _> = get_from_cache(category, key).await;
        assert!(retrieved.is_ok());

        let retrieved_options = retrieved.unwrap();
        assert!(retrieved_options.is_some());

        let retrieved_data = retrieved_options.unwrap();
        assert_eq!(retrieved_data.challenge, options.challenge);
        assert_eq!(retrieved_data.user.user_handle, options.user.user_handle);
        assert_eq!(retrieved_data.timestamp, options.timestamp);

        // Test removing data
        let remove_result = remove_from_cache(category, key).await;
        assert!(remove_result.is_ok());

        // Verify data is gone
        let after_remove: Result<Option<StoredOptions>, _> = get_from_cache(category, key).await;
        assert!(after_remove.is_ok());
        assert!(after_remove.unwrap().is_none());
    }
}
