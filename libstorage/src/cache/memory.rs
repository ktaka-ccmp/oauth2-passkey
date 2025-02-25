use async_trait::async_trait;
use std::collections::HashMap;

use super::traits::CacheStore;
use super::types::InMemoryCacheStore;

use crate::errors::StorageError;
use crate::types::CacheData;

impl InMemoryCacheStore {
    pub(crate) fn new() -> Self {
        println!("Creating new in-memory cache store");
        Self {
            entry: HashMap::new(),
        }
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), StorageError> {
        self.entry.insert(key.to_owned(), value);
        Ok(())
    }

    // No TTL in memory store
    async fn put_with_ttl(
        &mut self,
        key: &str,
        value: CacheData,
        _ttl: usize,
    ) -> Result<(), StorageError> {
        self.entry.insert(key.to_owned(), value);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, StorageError> {
        Ok(self.entry.get(key).cloned())
    }

    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, StorageError> {
        let matching_entries = self
            .entry
            .iter()
            .filter_map(|(k, v)| if k == key { Some(v.clone()) } else { None })
            .collect();
        Ok(matching_entries)
    }

    async fn remove(&mut self, key: &str) -> Result<(), StorageError> {
        self.entry.remove(key);
        Ok(())
    }
}
