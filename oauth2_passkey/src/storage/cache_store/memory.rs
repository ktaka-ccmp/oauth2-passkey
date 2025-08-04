use async_trait::async_trait;
use std::collections::HashMap;

use crate::storage::errors::StorageError;
use crate::storage::types::CacheData;

use super::types::{CacheStore, InMemoryCacheStore};

const CACHE_PREFIX: &str = "cache";

impl InMemoryCacheStore {
    pub(crate) fn new() -> Self {
        tracing::info!("Creating new in-memory generic cache store");
        Self {
            entry: HashMap::new(),
        }
    }

    fn make_key(prefix: &str, key: &str) -> String {
        format!("{CACHE_PREFIX}:{prefix}:{key}")
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(key, value);
        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        _ttl: usize,
    ) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(key, value);
        Ok(())
    }

    async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError> {
        let key = Self::make_key(prefix, key);
        Ok(self.entry.get(&key).cloned())
    }

    async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.remove(&key);
        Ok(())
    }

    async fn put_if_not_exists(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        _ttl: usize,
    ) -> Result<bool, StorageError> {
        let key = Self::make_key(prefix, key);

        // Atomic check-and-set: only insert if key doesn't exist
        // Note: In-memory cache doesn't implement TTL expiration yet,
        // but maintains interface consistency with Redis implementation
        if let std::collections::hash_map::Entry::Vacant(e) = self.entry.entry(key) {
            e.insert(value);
            Ok(true) // Successfully inserted
        } else {
            Ok(false) // Key already exists
        }
    }

    async fn get_and_delete_if_expired(
        &mut self,
        prefix: &str,
        key: &str,
    ) -> Result<Option<CacheData>, StorageError> {
        use chrono::Utc;

        let key = Self::make_key(prefix, key);

        // Get the entry to check expiration
        if let Some(cache_data) = self.entry.get(&key) {
            // Check if expired
            if cache_data.expires_at < Utc::now() {
                // Atomically remove the expired entry
                self.entry.remove(&key);
                Ok(None) // Return None for expired entries
            } else {
                // Return a clone of the non-expired entry (don't remove it)
                Ok(Some(cache_data.clone()))
            }
        } else {
            Ok(None) // Entry doesn't exist
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_key() {
        // Given a prefix and key
        let prefix = "session";
        let key = "user123";

        // When creating a key
        let result = InMemoryCacheStore::make_key(prefix, key);

        // Then it should be formatted correctly
        assert_eq!(result, "cache:session:user123");
    }

    #[tokio::test]
    async fn test_init() {
        // Given an in-memory cache store
        let store = InMemoryCacheStore::new();

        // When initializing it
        let result = store.init().await;

        // Then it should succeed
        assert!(result.is_ok());
    }

    /// Test for putting and getting a value in the in-memory cache store.
    /// This test checks that a value can be stored and retrieved correctly.
    #[tokio::test]
    async fn test_put_and_get() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key1";
        let value = CacheData {
            value: "test value".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // When putting a value
        let put_result = store.put(prefix, key, value.clone()).await;

        // Then it should succeed
        assert!(put_result.is_ok());

        // And when getting the value
        let get_result = store.get(prefix, key).await;

        // Then it should return the stored value
        assert!(get_result.is_ok());
        let retrieved = get_result.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, "test value");
    }

    /// Test for putting a value with TTL in the in-memory cache store.
    /// This test checks that a value can be stored with a TTL, even though the in-memory store ignores TTL.
    /// It verifies that the value can still be retrieved after the put operation.
    #[tokio::test]
    async fn test_put_with_ttl() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key2";
        let value = CacheData {
            value: "test value with ttl".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // When putting a value with TTL
        let put_result = store.put_with_ttl(prefix, key, value.clone(), 60).await;

        // Then it should succeed (note: in-memory store ignores TTL)
        assert!(put_result.is_ok());

        // And when getting the value
        let get_result = store.get(prefix, key).await;

        // Then it should return the stored value
        assert!(get_result.is_ok());
        let retrieved = get_result.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, "test value with ttl");
    }

    /// Test for removing a value from the in-memory cache store.
    /// This test checks that a value can be removed successfully and that subsequent retrieval returns None.
    #[tokio::test]
    async fn test_remove() {
        // Given an in-memory cache store with a stored value
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key3";
        let value = CacheData {
            value: "value to remove".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // When storing and then removing a value
        let _ = store.put(prefix, key, value).await;
        let remove_result = store.remove(prefix, key).await;

        // Then the removal should succeed
        assert!(remove_result.is_ok());

        // And when getting the removed value
        let get_result = store.get(prefix, key).await;

        // Then it should return None
        assert!(get_result.is_ok());
        let retrieved = get_result.unwrap();
        assert!(retrieved.is_none());
    }

    /// Test for getting a non-existent key from the in-memory cache store.
    /// This test checks that attempting to retrieve a key that does not exist returns None without error.
    #[tokio::test]
    async fn test_get_nonexistent_key() {
        // Given an in-memory cache store
        let store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "nonexistent";

        // When getting a non-existent key
        let get_result = store.get(prefix, key).await;

        // Then it should return None without error
        assert!(get_result.is_ok());
        let retrieved = get_result.unwrap();
        assert!(retrieved.is_none());
    }

    /// Test for removing a key that does not exist in the in-memory cache store.
    /// This test checks that removing a non-existent key does not result in an error.
    #[tokio::test]
    async fn test_multiple_prefixes() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();

        // When storing values with different prefixes but same key
        let key = "same_key";
        let value1 = CacheData {
            value: "value for prefix1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        let value2 = CacheData {
            value: "value for prefix2".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        let _ = store.put("prefix1", key, value1).await;
        let _ = store.put("prefix2", key, value2).await;

        // Then retrieving with different prefixes should get different values
        let get1 = store.get("prefix1", key).await.unwrap().unwrap();
        let get2 = store.get("prefix2", key).await.unwrap().unwrap();

        assert_eq!(get1.value, "value for prefix1");
        assert_eq!(get2.value, "value for prefix2");
    }

    /// Test for overwriting an existing key in the in-memory cache store.
    /// This test checks that when a key is overwritten, the new value is returned upon retrieval.
    #[tokio::test]
    async fn test_overwrite_existing_key() {
        // Given an in-memory cache store with an existing value
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key1";

        let original_value = CacheData {
            value: "original value".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        let new_value = CacheData {
            value: "new value".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // When storing the original value and then overwriting it
        let _ = store.put(prefix, key, original_value).await;
        let _ = store.put(prefix, key, new_value).await;

        // Then the retrieved value should be the new one
        let retrieved = store.get(prefix, key).await.unwrap().unwrap();
        assert_eq!(retrieved.value, "new value");
    }

    /// Test for removing a non-existent key from the in-memory cache store.
    /// This test checks that attempting to remove a key that does not exist does not result in an error.
    #[tokio::test]
    async fn test_remove_nonexistent_key() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();

        // When removing a non-existent key
        let result = store.remove("test", "nonexistent").await;

        // Then it should succeed without error
        assert!(result.is_ok());
    }

    /// Test for using empty strings as prefix and key in the in-memory cache store.
    /// This test checks that the store can handle empty strings correctly.
    #[tokio::test]
    async fn test_empty_prefix_and_key() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();

        let value = CacheData {
            value: "test with empty strings".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // When using empty strings for prefix and key
        let put_result = store.put("", "", value.clone()).await;

        // Then it should work correctly
        assert!(put_result.is_ok());

        let get_result = store.get("", "").await.unwrap().unwrap();
        assert_eq!(get_result.value, "test with empty strings");
    }

    // Integration tests for the global GENERIC_CACHE_STORE
    mod integration_tests {
        use crate::storage::{CacheData, GENERIC_CACHE_STORE};
        use crate::test_utils::init_test_environment;

        /// Test for the global GENERIC_CACHE_STORE integration.
        /// This test checks that the global cache store can be used to put, get, and remove data.
        /// It verifies that data can be stored and retrieved correctly, and that removing data works as expected.
        #[tokio::test]
        async fn test_cache_store_integration() {
            // Initialize test environment with in-memory stores
            init_test_environment().await;

            let prefix = "integration_test";
            let key = "test_key";
            let value = CacheData {
                value: "integration test value".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };

            // Test storing data in the global cache store
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                let put_result = cache.put(prefix, key, value.clone()).await;
                assert!(put_result.is_ok(), "Should be able to store data in cache");
            }

            // Test retrieving data from the global cache store
            {
                let cache = GENERIC_CACHE_STORE.lock().await;
                let get_result = cache.get(prefix, key).await;
                assert!(
                    get_result.is_ok(),
                    "Should be able to retrieve data from cache"
                );

                let retrieved = get_result.unwrap();
                assert!(retrieved.is_some(), "Data should exist in cache");
                assert_eq!(retrieved.unwrap().value, "integration test value");
            }

            // Test removing data from the global cache store
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                let remove_result = cache.remove(prefix, key).await;
                assert!(
                    remove_result.is_ok(),
                    "Should be able to remove data from cache"
                );
            }

            // Verify data was actually removed
            {
                let cache = GENERIC_CACHE_STORE.lock().await;
                let get_result = cache.get(prefix, key).await;
                assert!(get_result.is_ok(), "Get operation should succeed");
                assert!(
                    get_result.unwrap().is_none(),
                    "Data should be removed from cache"
                );
            }
        }

        /// Test for concurrent access to the global GENERIC_CACHE_STORE.
        /// This test checks that multiple tasks can access the cache concurrently without issues.
        /// It verifies that data can be stored and retrieved correctly from multiple concurrent tasks.
        #[tokio::test]
        async fn test_cache_store_concurrent_access() {
            // Initialize test environment
            init_test_environment().await;

            let prefix = "concurrent_test";

            // Create multiple concurrent tasks that access the cache
            let mut handles = vec![];

            for i in 0..5 {
                let task_key = format!("key_{i}");
                let task_value = CacheData {
                    value: format!("concurrent_value_{i}"),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                };

                let handle = tokio::spawn(async move {
                    // Store data
                    {
                        let mut cache = GENERIC_CACHE_STORE.lock().await;
                        cache.put(prefix, &task_key, task_value).await.unwrap();
                    }

                    // Retrieve data
                    {
                        let cache = GENERIC_CACHE_STORE.lock().await;
                        let result = cache.get(prefix, &task_key).await.unwrap();
                        assert!(result.is_some());
                        result.unwrap().value
                    }
                });

                handles.push(handle);
            }

            // Wait for all tasks to complete and verify results
            for (i, handle) in handles.into_iter().enumerate() {
                let result = handle.await.unwrap();
                assert_eq!(result, format!("concurrent_value_{i}"));
            }
        }

        /// Test for prefix isolation in the global GENERIC_CACHE_STORE.
        /// This test checks that different prefixes do not interfere with each other.
        /// It verifies that values stored under different prefixes can coexist without conflict.
        #[tokio::test]
        async fn test_cache_store_prefix_isolation() {
            // Initialize test environment
            init_test_environment().await;

            let key = "shared_key";
            let value1 = CacheData {
                value: "value_for_prefix1".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };
            let value2 = CacheData {
                value: "value_for_prefix2".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };
            let value3 = CacheData {
                value: "value_for_prefix3".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };

            // Store values with different prefixes
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                cache.put("prefix1", key, value1).await.unwrap();
                cache.put("prefix2", key, value2).await.unwrap();
                cache.put("prefix3", key, value3).await.unwrap();
            }

            // Verify each prefix maintains its own value
            {
                let cache = GENERIC_CACHE_STORE.lock().await;

                let result1 = cache.get("prefix1", key).await.unwrap().unwrap();
                assert_eq!(result1.value, "value_for_prefix1");

                let result2 = cache.get("prefix2", key).await.unwrap().unwrap();
                assert_eq!(result2.value, "value_for_prefix2");

                let result3 = cache.get("prefix3", key).await.unwrap().unwrap();
                assert_eq!(result3.value, "value_for_prefix3");
            }

            // Remove from one prefix and verify others are unaffected
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                cache.remove("prefix2", key).await.unwrap();
            }

            {
                let cache = GENERIC_CACHE_STORE.lock().await;

                // prefix1 and prefix3 should still exist
                assert!(cache.get("prefix1", key).await.unwrap().is_some());
                assert!(cache.get("prefix3", key).await.unwrap().is_some());

                // prefix2 should be removed
                assert!(cache.get("prefix2", key).await.unwrap().is_none());
            }
        }

        /// Test for the TTL behavior in the in-memory cache store.
        /// This test checks that the in-memory store can handle TTL values correctly,
        /// even though it does not enforce expiration.
        /// It verifies that values can be stored with TTL and retrieved immediately after.
        #[tokio::test]
        async fn test_cache_store_ttl_behavior() {
            // Initialize test environment
            init_test_environment().await;

            let prefix = "ttl_test";
            let key = "ttl_key";
            let value = CacheData {
                value: "ttl test value".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };

            // Test put_with_ttl (in-memory store ignores TTL but should still work)
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                let put_result = cache.put_with_ttl(prefix, key, value.clone(), 300).await;
                assert!(put_result.is_ok(), "put_with_ttl should succeed");
            }

            // Verify the value was stored (even though TTL is ignored in memory store)
            {
                let cache = GENERIC_CACHE_STORE.lock().await;
                let get_result = cache.get(prefix, key).await.unwrap();
                assert!(get_result.is_some(), "Value should be stored despite TTL");
                assert_eq!(get_result.unwrap().value, "ttl test value");
            }

            // Test with zero TTL
            let zero_ttl_value = CacheData {
                value: "zero ttl value".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };

            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                let put_result = cache
                    .put_with_ttl(prefix, "zero_ttl_key", zero_ttl_value, 0)
                    .await;
                assert!(
                    put_result.is_ok(),
                    "put_with_ttl with zero TTL should succeed"
                );
            }

            {
                let cache = GENERIC_CACHE_STORE.lock().await;
                let get_result = cache.get(prefix, "zero_ttl_key").await.unwrap();
                assert!(
                    get_result.is_some(),
                    "Value should be stored even with zero TTL in memory store"
                );
            }
        }

        /// Test for storing and retrieving large data in the in-memory cache store.
        /// This test checks that the in-memory store can handle large data sizes without issues.
        #[tokio::test]
        async fn test_cache_store_large_data() {
            // Initialize test environment
            init_test_environment().await;

            let prefix = "large_data_test";
            let key = "large_key";

            // Create a large value (1MB of data)
            let large_content = "x".repeat(1024 * 1024);
            let large_value = CacheData {
                value: large_content.clone(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };

            // Store large data
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                let put_result = cache.put(prefix, key, large_value).await;
                assert!(put_result.is_ok(), "Should be able to store large data");
            }

            // Retrieve and verify large data
            {
                let cache = GENERIC_CACHE_STORE.lock().await;
                let get_result = cache.get(prefix, key).await.unwrap();
                assert!(get_result.is_some(), "Large data should be retrievable");

                let retrieved = get_result.unwrap();
                assert_eq!(
                    retrieved.value.len(),
                    1024 * 1024,
                    "Large data should maintain size"
                );
                assert_eq!(
                    retrieved.value, large_content,
                    "Large data should maintain content"
                );
            }
        }

        /// Test for storing and retrieving special characters in keys and values.
        /// This test checks that the in-memory cache store can handle special characters correctly.
        #[tokio::test]
        async fn test_cache_store_special_characters() {
            // Initialize test environment
            init_test_environment().await;

            let prefix = "special_chars_test";

            // Test with various special characters in keys and values
            let test_cases = vec![
                ("key_with_spaces", "value with spaces"),
                ("key-with-dashes", "value-with-dashes"),
                ("key_with_émojis", "value with émojis 🚀🔐"),
                ("key/with/slashes", "value/with/slashes"),
                ("key:with:colons", "value:with:colons"),
                ("", "empty_key_test"),  // Empty key
                ("empty_value_key", ""), // Empty value
            ];

            // Store all test cases
            {
                let mut cache = GENERIC_CACHE_STORE.lock().await;
                for (test_key, test_value) in &test_cases {
                    let cache_data = CacheData {
                        value: test_value.to_string(),
                        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    };
                    let put_result = cache.put(prefix, test_key, cache_data).await;
                    assert!(
                        put_result.is_ok(),
                        "Should handle special characters in key: {test_key}"
                    );
                }
            }

            // Retrieve and verify all test cases
            {
                let cache = GENERIC_CACHE_STORE.lock().await;
                for (test_key, expected_value) in &test_cases {
                    let get_result = cache.get(prefix, test_key).await.unwrap();
                    assert!(
                        get_result.is_some(),
                        "Should retrieve value for key: {test_key}"
                    );

                    let retrieved = get_result.unwrap();
                    assert_eq!(
                        &retrieved.value, expected_value,
                        "Value should match for key: {test_key}"
                    );
                }
            }
        }
    }
}
