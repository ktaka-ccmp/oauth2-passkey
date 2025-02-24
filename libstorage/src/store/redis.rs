use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, AsyncCommands, Client};

use crate::{
    store::traits::{RawCacheStore, RawPermanentStore, Store},
    types::{CacheDataKind, PermanentDataKind, QueryField, StorageError},
};

pub struct RedisStore {
    client: Client,
}

impl RedisStore {
    pub fn new(url: &str) -> Result<Self, StorageError> {
        let client = Client::open(url)?;
        Ok(Self { client })
    }

    async fn get_connection(&self) -> Result<MultiplexedConnection, redis::RedisError> {
        self.client.get_multiplexed_async_connection().await
    }
}

#[async_trait]
impl Store for RedisStore {
    fn requires_schema(&self) -> bool {
        false
    }

    async fn init(&self) -> Result<(), StorageError> {
        // Test connection
        self.get_connection().await?;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[async_trait]
impl RawCacheStore for RedisStore {
    async fn put_raw(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: Vec<u8>,
        ttl: Option<u64>,
    ) -> Result<(), StorageError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", kind.to_string(), key);

        if let Some(ttl) = ttl {
            let _: () = conn.set_ex(&key, value, ttl).await?;
        } else {
            let _: () = conn.set(&key, value).await?;
        }

        Ok(())
    }

    async fn get_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", kind.to_string(), key);
        let value: Option<Vec<u8>> = conn.get(&key).await?;
        Ok(value)
    }

    async fn query_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut conn = self.get_connection().await?;
        let pattern = format!("{}:{}*", kind.to_string(), key);
        let keys: Vec<String> = conn.keys(&pattern).await?;
        let mut values = Vec::new();

        for key in keys {
            let value: Option<Vec<u8>> = conn.get(&key).await?;
            if let Some(value) = value {
                values.push(value);
            }
        }

        Ok(values)
    }

    async fn delete(&mut self, kind: CacheDataKind, key: &str) -> Result<(), StorageError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", kind.to_string(), key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }
}

#[async_trait]
impl RawPermanentStore for RedisStore {
    async fn store_raw(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", kind.to_string(), key);
        let _: () = conn.set(&key, value).await?;
        Ok(())
    }

    async fn get_raw(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", kind.to_string(), key);
        let value: Option<Vec<u8>> = conn.get(&key).await?;
        Ok(value)
    }

    async fn query_raw(
        &self,
        kind: PermanentDataKind,
        field: QueryField,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut conn = self.get_connection().await?;
        let pattern = match field {
            QueryField::Email(email) => format!("{}:*:email:{}", kind.to_string(), email),
            QueryField::UserHandle(handle) => format!("{}:*:handle:{}", kind.to_string(), handle),
        };

        let keys: Vec<String> = conn.keys(&pattern).await?;
        let mut values = Vec::new();

        for key in keys {
            let value: Option<Vec<u8>> = conn.get(&key).await?;
            if let Some(value) = value {
                values.push(value);
            }
        }

        Ok(values)
    }

    async fn delete(&mut self, kind: PermanentDataKind, key: &str) -> Result<(), StorageError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", kind.to_string(), key);
        let _: () = conn.del(&key).await?;
        Ok(())
    }
}
