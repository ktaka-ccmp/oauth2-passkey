use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use crate::{CacheDataKind, PermanentDataKind, QueryField, QueryRelation, StorageError};

#[async_trait]
pub trait Store: Send + Sync {
    /// Returns true if this store requires schema initialization
    fn requires_schema(&self) -> bool;

    /// Initialize the store (create tables for SQL databases)
    async fn init(&self) -> Result<(), StorageError>;
}

#[async_trait]
pub trait CacheStore: Store {
    /// Store a value with its type
    async fn put<T: Serialize + Send + Sync>(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: &T,
        ttl_secs: Option<u64>,
    ) -> Result<(), StorageError>;

    /// Retrieve a value by its type and key
    async fn get<T: DeserializeOwned>(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError>;

    /// Delete a value by its type and key
    async fn delete(
        &mut self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait PermanentStore: Store {
    /// Store a value with its type
    async fn store<T: Serialize + Send + Sync>(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError>;

    /// Retrieve a value by its type and key
    async fn get<T: DeserializeOwned>(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError>;

    /// Delete a value by its type and key
    async fn delete(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<(), StorageError>;

    /// Query relationships between data
    async fn query<T: DeserializeOwned>(
        &self,
        relation: QueryRelation,
        field: QueryField,
    ) -> Result<Vec<T>, StorageError>;
}
