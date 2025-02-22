use async_trait::async_trait;
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    CacheDataKind, PermanentDataKind, QueryField, QueryRelation,
    Store, CacheStore, PermanentStore, StorageError,
};

pub struct RedisCacheStore {
    client: redis::Client,
}

impl RedisCacheStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Store for RedisCacheStore {
    fn requires_schema(&self) -> bool {
        false
    }

    async fn init(&self) -> Result<(), StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        conn.ping().await?;
        Ok(())
    }
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn put<T: Serialize + Send + Sync>(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: &T,
        ttl_secs: Option<u64>,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let prefixed_key = format!("{}{}", kind.prefix(), key);
        let json = serde_json::to_string(value)?;

        if let Some(ttl) = ttl_secs {
            conn.set_ex(&prefixed_key, json, ttl as usize).await?;
        } else {
            conn.set(&prefixed_key, json).await?;
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let prefixed_key = format!("{}{}", kind.prefix(), key);
        let json: Option<String> = conn.get(&prefixed_key).await?;
        
        match json {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn delete(
        &mut self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let prefixed_key = format!("{}{}", kind.prefix(), key);
        conn.del(&prefixed_key).await?;
        Ok(())
    }
}

pub struct RedisPermanentStore {
    client: redis::Client,
}

impl RedisPermanentStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }

    async fn maintain_index(
        &self,
        conn: &mut redis::aio::Connection,
        index_key: &str,
        value_key: &str,
    ) -> Result<(), StorageError> {
        conn.sadd(index_key, value_key).await?;
        Ok(())
    }
}

#[async_trait]
impl Store for RedisPermanentStore {
    fn requires_schema(&self) -> bool {
        false
    }

    async fn init(&self) -> Result<(), StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        conn.ping().await?;
        Ok(())
    }
}

#[async_trait]
impl PermanentStore for RedisPermanentStore {
    async fn store<T: Serialize + Send + Sync>(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let value_key = format!("{:?}:{}", kind, key);
        let json = serde_json::to_string(value)?;

        // Store main data
        conn.set(&value_key, &json).await?;

        // Update indexes based on the data type
        let value_json: serde_json::Value = serde_json::from_str(&json)?;
        match kind {
            PermanentDataKind::User => {
                if let Some(email) = value_json.get("email") {
                    let index_key = format!("email:{}", email.as_str().unwrap());
                    self.maintain_index(&mut conn, &index_key, &value_key).await?;
                }
            }
            PermanentDataKind::Credential => {
                if let Some(user_handle) = value_json.get("user_handle") {
                    let index_key = format!("user:{}:credentials", user_handle.as_str().unwrap());
                    self.maintain_index(&mut conn, &index_key, &value_key).await?;
                }
            }
        }

        Ok(())
    }

    async fn get<T: DeserializeOwned>(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let value_key = format!("{:?}:{}", kind, key);
        let json: Option<String> = conn.get(&value_key).await?;
        
        match json {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn delete(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<(), StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let value_key = format!("{:?}:{}", kind, key);
        conn.del(&value_key).await?;
        Ok(())
    }

    async fn query<T: DeserializeOwned>(
        &self,
        relation: QueryRelation,
        field: QueryField,
    ) -> Result<Vec<T>, StorageError> {
        let mut conn = self.client.get_async_connection().await?;
        let index_key = relation.redis_key_pattern(&field);
        
        let value_keys: Vec<String> = conn.smembers(&index_key).await?;
        let mut results = Vec::new();
        
        for key in value_keys {
            if let Some(json) = conn.get::<_, Option<String>>(&key).await? {
                results.push(serde_json::from_str(&json)?);
            }
        }
        
        Ok(results)
    }
}
