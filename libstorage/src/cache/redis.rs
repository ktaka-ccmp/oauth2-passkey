use async_trait::async_trait;
use redis::{self, AsyncCommands};

use super::traits::CacheStore;
use super::types::RedisCacheStore;

use crate::errors::StorageError;
use crate::types::CacheData;

const CACHE_PREFIX: &str = "new_cache:";

impl RedisCacheStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, StorageError> {
        println!("Connecting to Redis at {} for tokens", url);
        let client = redis::Client::open(url).map_err(|e| StorageError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        // Verify the connection works
        let _conn = self.client.get_multiplexed_async_connection().await?;
        Ok(())
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        // let ttl = 600; // 10 minute for testing
        // let _: () = conn.expire(&key, ttl).await?;
        // let _: () = conn.set_ex(&key, value, ttl).await?;

        Ok(())
    }

    async fn put_with_ttl(
        &mut self,
        key: &str,
        value: CacheData,
        ttl: usize,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let value = serde_json::to_string(&value)?;
        let _: () = conn.set(&key, value).await?;
        let _: () = conn.expire(&key, ttl as i64).await?;
        // let _: () = conn.set_ex(&key, value, ttl).await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let keys: Vec<String> = conn.keys(&key).await?;

        let mut results = Vec::new();
        for key in keys {
            let value: Option<String> = conn.get(&key).await?;

            if let Some(v) = value {
                let data: CacheData = serde_json::from_str(&v)?;
                results.push(data);
            }
        }
        Ok(results)
    }

    async fn remove(&mut self, key: &str) -> Result<(), StorageError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let key = format!("{}{}", CACHE_PREFIX, key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }
}
