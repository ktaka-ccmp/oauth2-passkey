use async_trait::async_trait;
use std::collections::HashMap;

use crate::storage::errors::StorageError;
use crate::storage::types::{CacheData, CacheKey, CachePrefix};

use super::types::{CacheStore, InMemoryCacheStore};

const CACHE_PREFIX: &str = "cache";

impl InMemoryCacheStore {
    pub(crate) fn new() -> Self {
        tracing::info!("Creating new in-memory generic cache store");
        Self {
            entry: HashMap::new(),
        }
    }

    fn make_key(prefix: CachePrefix, key: CacheKey) -> String {
        format!("{CACHE_PREFIX}:{}:{}", prefix.as_str(), key.as_str())
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn put(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
    ) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(key, value);
        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
        _ttl: usize,
    ) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(key, value);
        Ok(())
    }

    async fn get(
        &self,
        prefix: CachePrefix,
        key: CacheKey,
    ) -> Result<Option<CacheData>, StorageError> {
        let key = Self::make_key(prefix, key);
        Ok(self.entry.get(&key).cloned())
    }

    async fn remove(&mut self, prefix: CachePrefix, key: CacheKey) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.remove(&key);
        Ok(())
    }

    async fn put_if_not_exists(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
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
        prefix: CachePrefix,
        key: CacheKey,
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
mod tests;
