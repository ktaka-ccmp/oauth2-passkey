use async_trait::async_trait;
use redis::{self, AsyncCommands};

use crate::storage::errors::StorageError;
use crate::storage::types::CacheData;

use super::types::{CacheStore, RedisCacheStore};

const CACHE_PREFIX: &str = "cache";

impl RedisCacheStore {
    fn make_key(prefix: &str, key: &str) -> String {
        format!("{CACHE_PREFIX}:{prefix}:{key}")
    }
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        // Verify the connection works
        let _conn = self.client.get_multiplexed_async_connection().await?;
        Ok(())
    }

    async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        ttl: usize,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        let _: () = conn.expire(&key, ttl as i64).await?;

        Ok(())
    }

    async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }

    async fn put_if_not_exists(
        &mut self,
        prefix: &str,
        key: &str,
        value: CacheData,
        ttl: usize,
    ) -> Result<bool, StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let value = serde_json::to_string(&value)?;

        // Use Redis SETNX (set if not exists) for atomic operation
        let result: bool = conn.set_nx(&key, &value).await?;

        if result && ttl > 0 {
            // If we successfully set the key and TTL is specified, set expiration
            let _: () = conn.expire(&key, ttl as i64).await?;
        }

        Ok(result)
    }
}
