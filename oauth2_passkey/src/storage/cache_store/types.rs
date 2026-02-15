use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Instant;

use crate::storage::errors::StorageError;
use crate::storage::types::{CacheData, CacheKey, CachePrefix};

/// A cache entry with optional TTL expiration.
///
/// When `expires_at` is `Some`, the entry is considered expired after that instant.
/// When `expires_at` is `None`, the entry never expires (used by `put()` without TTL).
pub(super) struct CacheEntry {
    pub(super) data: CacheData,
    pub(super) expires_at: Option<Instant>,
}

impl CacheEntry {
    /// Returns true if the entry has expired.
    pub(super) fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => Instant::now() > expires_at,
            None => false,
        }
    }
}

pub(crate) struct InMemoryCacheStore {
    pub(super) entry: HashMap<String, CacheEntry>,
}

pub(crate) struct RedisCacheStore {
    pub(super) client: redis::Client,
}

// Trait
#[async_trait]
pub(crate) trait CacheStore: Send + Sync + 'static {
    /// Put a token into the store.
    #[allow(dead_code)] // Used in tests
    async fn put(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
    ) -> Result<(), StorageError>;

    /// Put a token into the store with a TTL.
    async fn put_with_ttl(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
        ttl: usize,
    ) -> Result<(), StorageError>;

    /// Get a token from the store.
    async fn get(
        &self,
        prefix: CachePrefix,
        key: CacheKey,
    ) -> Result<Option<CacheData>, StorageError>;

    /// Remove a token from the store.
    async fn remove(&mut self, prefix: CachePrefix, key: CacheKey) -> Result<(), StorageError>;

    /// Put a token into the store only if it doesn't already exist (atomic check-and-set).
    /// Returns true if the token was stored, false if it already existed.
    async fn put_if_not_exists(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
        ttl: usize,
    ) -> Result<bool, StorageError>;
}
