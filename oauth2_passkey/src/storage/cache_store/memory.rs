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

    #[tokio::test]
    async fn test_put_and_get() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key1";
        let value = CacheData {
            value: "test value".to_string(),
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

    #[tokio::test]
    async fn test_put_with_ttl() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key2";
        let value = CacheData {
            value: "test value with ttl".to_string(),
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

    #[tokio::test]
    async fn test_remove() {
        // Given an in-memory cache store with a stored value
        let mut store = InMemoryCacheStore::new();
        let prefix = "test";
        let key = "key3";
        let value = CacheData {
            value: "value to remove".to_string(),
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

    #[tokio::test]
    async fn test_multiple_prefixes() {
        // Given an in-memory cache store
        let mut store = InMemoryCacheStore::new();

        // When storing values with different prefixes but same key
        let key = "same_key";
        let value1 = CacheData {
            value: "value for prefix1".to_string(),
        };
        let value2 = CacheData {
            value: "value for prefix2".to_string(),
        };

        let _ = store.put("prefix1", key, value1).await;
        let _ = store.put("prefix2", key, value2).await;

        // Then retrieving with different prefixes should get different values
        let get1 = store.get("prefix1", key).await.unwrap().unwrap();
        let get2 = store.get("prefix2", key).await.unwrap().unwrap();

        assert_eq!(get1.value, "value for prefix1");
        assert_eq!(get2.value, "value for prefix2");
    }
}
