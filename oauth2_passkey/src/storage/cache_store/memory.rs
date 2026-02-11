use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::storage::errors::StorageError;
use crate::storage::types::{CacheData, CacheKey, CachePrefix};

use super::types::{CacheEntry, CacheStore, InMemoryCacheStore};

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

    /// Compute the expiration instant from a TTL value.
    /// TTL=0 means "no expiration" (returns None).
    fn compute_expires_at(ttl: usize) -> Option<Instant> {
        match ttl {
            0 => None,
            ttl => Some(Instant::now() + Duration::from_secs(ttl as u64)),
        }
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn put(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
    ) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(
            key,
            CacheEntry {
                data: value,
                expires_at: None,
            },
        );
        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
        ttl: usize,
    ) -> Result<(), StorageError> {
        let key = Self::make_key(prefix, key);
        self.entry.insert(
            key,
            CacheEntry {
                data: value,
                expires_at: Self::compute_expires_at(ttl),
            },
        );
        Ok(())
    }

    async fn get(
        &self,
        prefix: CachePrefix,
        key: CacheKey,
    ) -> Result<Option<CacheData>, StorageError> {
        let key = Self::make_key(prefix, key);
        match self.entry.get(&key) {
            Some(entry) if !entry.is_expired() => Ok(Some(entry.data.clone())),
            _ => Ok(None),
        }
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
        ttl: usize,
    ) -> Result<bool, StorageError> {
        let key = Self::make_key(prefix, key);

        // Treat expired entries as non-existent (consistent with Redis TTL behavior)
        let is_occupied = self
            .entry
            .get(&key)
            .is_some_and(|entry| !entry.is_expired());

        if is_occupied {
            Ok(false) // Key exists and is not expired
        } else {
            self.entry.insert(
                key,
                CacheEntry {
                    data: value,
                    expires_at: Self::compute_expires_at(ttl),
                },
            );
            Ok(true) // Successfully inserted (or replaced expired entry)
        }
    }
}

#[cfg(test)]
mod tests;
