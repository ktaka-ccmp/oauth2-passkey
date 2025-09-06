use async_trait::async_trait;
use std::collections::HashMap;

use crate::storage::errors::StorageError;
use crate::storage::types::{CacheData, CacheKey, CachePrefix};

pub(crate) struct InMemoryCacheStore {
    pub(super) entry: HashMap<String, CacheData>,
}

pub(crate) struct RedisCacheStore {
    pub(super) client: redis::Client,
}

// Trait
#[async_trait]
pub(crate) trait CacheStore: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), StorageError>;

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

    /// Atomically get a token and delete it if it's expired.
    /// Returns the token if it exists and is not expired, None if it doesn't exist or is expired.
    /// This prevents race conditions between expiration check and deletion.
    async fn get_and_delete_if_expired(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
    ) -> Result<Option<CacheData>, StorageError>;
}
