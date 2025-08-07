use async_trait::async_trait;
use redis::{self, AsyncCommands};

use crate::storage::errors::StorageError;
use crate::storage::types::CacheData;

use super::types::{CacheStore, RedisCacheStore};

const CACHE_PREFIX: &str = "cache";

impl RedisCacheStore {
    fn make_key(prefix: &str, key: &str) -> Result<String, StorageError> {
        // Validate prefix and key to prevent Redis command injection
        Self::validate_key_component(prefix, "prefix")?;
        Self::validate_key_component(key, "key")?;
        Ok(format!("{CACHE_PREFIX}:{prefix}:{key}"))
    }

    fn validate_key_component(component: &str, component_name: &str) -> Result<(), StorageError> {
        // Check for empty components
        if component.is_empty() {
            // Allow empty components but log it
            tracing::debug!("Empty {} component in Redis key", component_name);
        }

        // Check length limit (Redis keys can be up to 512MB, but we'll use a reasonable limit)
        if component.len() > 250 {
            return Err(StorageError::InvalidInput(format!(
                "Redis key {} component too long: {} bytes (max 250)",
                component_name,
                component.len()
            )));
        }

        // Check for dangerous characters that could cause Redis command injection
        let dangerous_chars = ['\n', '\r', ' ', '\t'];
        if component.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput(format!(
                "Redis key {component_name} component contains unsafe characters (whitespace/newlines): '{component}'"
            )));
        }

        // Check for Redis command keywords (basic protection)
        let component_upper = component.to_uppercase();
        let redis_commands = [
            "SET", "GET", "DEL", "FLUSHDB", "FLUSHALL", "EVAL", "SCRIPT", "SHUTDOWN", "CONFIG",
            "CLIENT", "DEBUG", "MONITOR", "SYNC",
        ];

        for cmd in &redis_commands {
            if component_upper.contains(cmd) {
                return Err(StorageError::InvalidInput(format!(
                    "Redis key {component_name} component contains potentially dangerous command keyword: '{component}'"
                )));
            }
        }

        Ok(())
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

        let key = Self::make_key(prefix, key)?;
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

        let key = Self::make_key(prefix, key)?;
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        let _: () = conn.expire(&key, ttl as i64).await?;

        Ok(())
    }

    async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key)?;
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = Self::make_key(prefix, key)?;
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

        let key = Self::make_key(prefix, key)?;
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
        prefix: &str,
        key: &str,
    ) -> Result<Option<CacheData>, StorageError> {
        use chrono::Utc;

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = Self::make_key(prefix, key)?;

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
