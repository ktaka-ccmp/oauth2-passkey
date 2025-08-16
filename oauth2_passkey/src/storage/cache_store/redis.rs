use async_trait::async_trait;
use redis::{self, AsyncCommands};

use crate::storage::errors::StorageError;
use crate::storage::types::{CacheData, CacheKey, CachePrefix};

use super::types::{CacheStore, RedisCacheStore};

const CACHE_PREFIX: &str = "cache";

impl RedisCacheStore {
    fn make_key(prefix: CachePrefix, key: CacheKey) -> String {
        // No validation needed - types guarantee validity
        format!("{CACHE_PREFIX}:{}:{}", prefix.as_str(), key.as_str())
    }
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        // Verify the connection works
        let _conn = self.client.get_multiplexed_async_connection().await?;
        Ok(())
    }

    async fn put(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
        value: CacheData,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
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

    async fn get(
        &self,
        prefix: CachePrefix,
        key: CacheKey,
    ) -> Result<Option<CacheData>, StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn remove(&mut self, prefix: CachePrefix, key: CacheKey) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }

    async fn put_if_not_exists(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
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

    async fn get_and_delete_if_expired(
        &mut self,
        prefix: CachePrefix,
        key: CacheKey,
    ) -> Result<Option<CacheData>, StorageError> {
        use chrono::Utc;

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::make_key(prefix, key);

        // Use Redis Lua script for atomic get-and-delete-if-expired operation
        let lua_script = r#"
            local key = KEYS[1]
            local current_time = tonumber(ARGV[1])

            local value = redis.call('GET', key)
            if not value then
                return nil
            end

            local data = cjson.decode(value)
            local expires_at = tonumber(data.expires_at)

            if expires_at < current_time then
                redis.call('DEL', key)
                return nil
            else
                return value
            end
        "#;

        let current_timestamp = Utc::now().timestamp();
        let result: Option<String> = redis::Script::new(lua_script)
            .key(&key)
            .arg(current_timestamp)
            .invoke_async(&mut conn)
            .await?;

        match result {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }
}
