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
    get_credential_id_strs_by(CredentialSearchField::UserName(
        crate::passkey::UserName::new(name.to_string()),
    ))
    .await
}

#[cfg(test)]
mod tests {
    // Test imports
    use crate::passkey::types::PublicKeyCredentialUserEntity;
    use crate::passkey::types::StoredOptions;
    use crate::storage::CacheData;
    use crate::test_utils::init_test_environment;

    /// Test the CacheData conversion for StoredOptions
    /// This test verifies that StoredOptions can be correctly converted to and from CacheData.
    /// It performs the following steps:
    /// 1. Creates test StoredOptions with challenge, user data, timestamp, and TTL
    /// 2. Converts StoredOptions to CacheData and verifies serialization
    /// 3. Converts back to StoredOptions and confirms round-trip conversion integrity
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

    /// Test CacheData conversion with edge cases (empty strings, special characters)
    /// This test verifies that StoredOptions CacheData conversion handles edge cases correctly.
    /// It performs the following steps:
    /// 1. Creates StoredOptions with edge case values (empty strings, special characters, zero values)
    /// 2. Converts to CacheData and back to verify serialization/deserialization
    /// 3. Confirms that all edge case values are preserved correctly through the conversion
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

    /// Test cache operations
    /// This test verifies that cache storage and retrieval operations work correctly.
    /// It performs the following steps:
    /// 1. Creates test StoredOptions and stores them in cache with TTL
    /// 2. Retrieves the stored data and verifies it matches original values
    /// 3. Tests cache removal and confirms data is no longer accessible
    #[tokio::test]
    async fn test_cache_operations() {
        init_test_environment().await;
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

        // Test storing data using unified cache operations
        use crate::storage::{CacheKey, CachePrefix, get_data, remove_data, store_cache_keyed};
        let cache_prefix =
            CachePrefix::new(category.to_string()).expect("Failed to create cache prefix");
        let cache_key = CacheKey::new(key.to_string()).expect("Failed to create cache key");
        let store_result = store_cache_keyed::<_, crate::passkey::PasskeyError>(
            cache_prefix,
            cache_key,
            options.clone(),
            300,
        )
        .await;
        assert!(store_result.is_ok());

        // Test retrieving data using unified cache operations
        let cache_prefix = CachePrefix::new(category.to_string()).unwrap();
        let cache_key = CacheKey::new(key.to_string()).unwrap();
        let retrieved: Result<Option<StoredOptions>, _> =
            get_data::<_, crate::passkey::PasskeyError>(cache_prefix.clone(), cache_key.clone())
                .await;
        assert!(retrieved.is_ok());

        let retrieved_options = retrieved.unwrap();
        assert!(retrieved_options.is_some());

        let retrieved_data = retrieved_options.unwrap();
        assert_eq!(retrieved_data.challenge, options.challenge);
        assert_eq!(retrieved_data.user.user_handle, options.user.user_handle);
        assert_eq!(retrieved_data.timestamp, options.timestamp);

        // Test removing data using unified cache operations
        let remove_result =
            remove_data::<crate::passkey::PasskeyError>(cache_prefix, cache_key).await;
        assert!(remove_result.is_ok());

        // Verify data is gone
        let cache_prefix2 = CachePrefix::new(category.to_string()).unwrap();
        let cache_key2 = CacheKey::new(key.to_string()).unwrap();
        let after_remove: Result<Option<StoredOptions>, _> =
            get_data::<_, crate::passkey::PasskeyError>(cache_prefix2, cache_key2).await;
        assert!(after_remove.is_ok());
        assert!(after_remove.unwrap().is_none());
    }

    /// Test cache operations with different keys
    /// This test verifies that cache operations correctly isolate data between different keys.
    /// It performs the following steps:
    /// 1. Stores different StoredOptions data under two separate cache keys
    /// 2. Retrieves data by each key and verifies correct data isolation
    /// 3. Confirms that operations on one key don't affect data stored under other keys
    #[tokio::test]
    async fn test_cache_operations_different_keys() {
        init_test_environment().await;
        let category = "isolation_test";
        let key1 = "key1";
        let key2 = "key2";

        let data1 = StoredOptions {
            challenge: "challenge1".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "user1".to_string(),
                name: "user1".to_string(),
                display_name: "User 1".to_string(),
            },
            timestamp: 1111,
            ttl: 100,
        };

        let data2 = StoredOptions {
            challenge: "challenge2".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "user2".to_string(),
                name: "user2".to_string(),
                display_name: "User 2".to_string(),
            },
            timestamp: 2222,
            ttl: 200,
        };

        // Store different data with different keys using unified cache operations
        use crate::storage::{CacheKey, CachePrefix, get_data, store_cache_keyed};
        let cache_prefix1 =
            CachePrefix::new(category.to_string()).expect("Failed to create cache prefix");
        let cache_key1 = CacheKey::new(key1.to_string()).expect("Failed to create cache key");
        let _ = store_cache_keyed::<_, crate::passkey::PasskeyError>(
            cache_prefix1,
            cache_key1,
            data1.clone(),
            100,
        )
        .await;

        let cache_prefix2 =
            CachePrefix::new(category.to_string()).expect("Failed to create cache prefix");
        let cache_key2 = CacheKey::new(key2.to_string()).expect("Failed to create cache key");
        let _ = store_cache_keyed::<_, crate::passkey::PasskeyError>(
            cache_prefix2,
            cache_key2,
            data2.clone(),
            200,
        )
        .await;

        // Verify each key returns its own data using unified cache operations
        let (cache_prefix1, cache_key1) = (
            CachePrefix::new(category.to_string()).unwrap(),
            CacheKey::new(key1.to_string()).unwrap(),
        );
        let cache_prefix2 = CachePrefix::new(category.to_string()).unwrap();
        let cache_key2 = CacheKey::new(key2.to_string()).unwrap();
        let retrieved1: Option<StoredOptions> =
            get_data::<_, crate::passkey::PasskeyError>(cache_prefix1, cache_key1)
                .await
                .unwrap();
        let retrieved2: Option<StoredOptions> =
            get_data::<_, crate::passkey::PasskeyError>(cache_prefix2, cache_key2)
                .await
                .unwrap();

        assert!(retrieved1.is_some());
        assert!(retrieved2.is_some());

        let data_from_key1 = retrieved1.unwrap();
        let data_from_key2 = retrieved2.unwrap();

        assert_eq!(data_from_key1.challenge, "challenge1");
        assert_eq!(data_from_key2.challenge, "challenge2");
        assert_eq!(data_from_key1.timestamp, 1111);
        assert_eq!(data_from_key2.timestamp, 2222);
    }

    /// Test cache operations - comprehensive test (was EXISTING TEST)
    /// This test verifies comprehensive cache functionality including storage, retrieval, and cleanup.
    /// It performs the following steps:
    /// 1. Stores test StoredOptions in cache and verifies successful storage
    /// 2. Retrieves and validates that stored data matches original values exactly
    /// 3. Tests cache removal and confirms data is properly cleaned up
    #[tokio::test]
    async fn test_comprehensive_cache_operations() {
        init_test_environment().await;
        let category = "comprehensive_test";
        let key = "comprehensive_key";

        // Create test data
        let options = StoredOptions {
            challenge: "comprehensive_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "comprehensive_user_handle".to_string(),
                name: "comprehensive_user".to_string(),
                display_name: "Comprehensive Test User".to_string(),
            },
            timestamp: 1622505600,
            ttl: 300,
        };

        // Test storing data using unified cache operations
        use crate::storage::{CacheKey, CachePrefix, get_data, remove_data, store_cache_keyed};
        let cache_prefix =
            CachePrefix::new(category.to_string()).expect("Failed to create cache prefix");
        let cache_key = CacheKey::new(key.to_string()).expect("Failed to create cache key");
        let store_result = store_cache_keyed::<_, crate::passkey::PasskeyError>(
            cache_prefix,
            cache_key,
            options.clone(),
            300,
        )
        .await;
        assert!(store_result.is_ok());

        // Test retrieving data using unified cache operations
        let cache_prefix = CachePrefix::new(category.to_string()).unwrap();
        let cache_key = CacheKey::new(key.to_string()).unwrap();
        let retrieved: Result<Option<StoredOptions>, _> =
            get_data::<_, crate::passkey::PasskeyError>(cache_prefix.clone(), cache_key.clone())
                .await;
        assert!(retrieved.is_ok());

        let retrieved_options = retrieved.unwrap();
        assert!(retrieved_options.is_some());

        let retrieved_data = retrieved_options.unwrap();
        assert_eq!(retrieved_data.challenge, options.challenge);
        assert_eq!(retrieved_data.user.user_handle, options.user.user_handle);
        assert_eq!(retrieved_data.timestamp, options.timestamp);

        // Test removing data using unified cache operations
        let remove_result =
            remove_data::<crate::passkey::PasskeyError>(cache_prefix, cache_key).await;
        assert!(remove_result.is_ok());

        // Verify data is gone
        let cache_prefix2 = CachePrefix::new(category.to_string()).unwrap();
        let cache_key2 = CacheKey::new(key.to_string()).unwrap();
        let after_remove: Result<Option<StoredOptions>, _> =
            get_data::<_, crate::passkey::PasskeyError>(cache_prefix2, cache_key2).await;
        assert!(after_remove.is_ok());
        assert!(after_remove.unwrap().is_none());
    }
}
