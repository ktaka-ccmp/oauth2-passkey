use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::any::Any;

use crate::types::{CacheDataKind, PermanentDataKind, QueryField, StorageError};

#[async_trait]
pub trait Store: Send + Sync + Any + 'static {
    fn requires_schema(&self) -> bool;
    async fn init(&self) -> Result<(), StorageError>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

#[async_trait]
pub trait RawCacheStore: Store {
    async fn put_raw(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: Vec<u8>,
        ttl: Option<u64>,
    ) -> Result<(), StorageError>;

    async fn get_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError>;

    async fn query_raw(&self, kind: CacheDataKind, key: &str)
        -> Result<Vec<Vec<u8>>, StorageError>;

    async fn delete(&mut self, kind: CacheDataKind, key: &str) -> Result<(), StorageError>;
}

#[async_trait]
pub trait RawPermanentStore: Store {
    async fn store_raw(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), StorageError>;

    async fn get_raw(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError>;

    async fn query_raw(
        &self,
        kind: PermanentDataKind,
        field: QueryField,
    ) -> Result<Vec<Vec<u8>>, StorageError>;

    async fn delete(&mut self, kind: PermanentDataKind, key: &str) -> Result<(), StorageError>;
}

#[async_trait]
pub trait CacheStore: RawCacheStore {
    async fn put<T: Serialize + Send + Sync>(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: &T,
        ttl: Option<u64>,
    ) -> Result<(), StorageError> {
        let value = serde_json::to_vec(value)?;
        self.put_raw(kind, key, value, ttl).await
    }

    async fn get<T: DeserializeOwned + Send>(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        if let Some(value) = self.get_raw(kind, key).await? {
            Ok(Some(serde_json::from_slice(&value)?))
        } else {
            Ok(None)
        }
    }

    async fn query<T: DeserializeOwned + Send>(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Vec<T>, StorageError> {
        let values = self.query_raw(kind, key).await?;
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            result.push(serde_json::from_slice(&value)?);
        }
        Ok(result)
    }
}

#[async_trait]
pub trait PermanentStore: RawPermanentStore {
    async fn store<T: Serialize + Send + Sync>(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        let value = serde_json::to_vec(value)?;
        self.store_raw(kind, key, value).await
    }

    async fn get<T: DeserializeOwned + Send>(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        if let Some(value) = self.get_raw(kind, key).await? {
            Ok(Some(serde_json::from_slice(&value)?))
        } else {
            Ok(None)
        }
    }

    async fn query<T: DeserializeOwned + Send>(
        &self,
        kind: PermanentDataKind,
        field: QueryField,
    ) -> Result<Vec<T>, StorageError> {
        let values = self.query_raw(kind, field).await?;
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            result.push(serde_json::from_slice(&value)?);
        }
        Ok(result)
    }
}
