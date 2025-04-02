use async_trait::async_trait;
use std::collections::HashMap;

use crate::storage::errors::StorageError;
use crate::storage::types::CacheData;

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
    async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError>;

    /// Put a token into the store with a TTL.
    async fn put_with_ttl(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        ttl: usize,
    ) -> Result<(), StorageError>;

    /// Get a token from the store.
    async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError>;

    /// Gets multiple tokens from the store.
    async fn gets(&self, prefix: &str, key: &str) -> Result<Vec<CacheData>, StorageError>;

    /// Remove a token from the store.
    async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError>;
}
