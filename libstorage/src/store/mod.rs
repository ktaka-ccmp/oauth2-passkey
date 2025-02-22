mod memory;
mod postgres;
mod redis;
mod sqlite;
mod traits;

pub use memory::{InMemoryCacheStore, InMemoryPermanentStore};
pub use postgres::{PostgresCacheStore, PostgresPermanentStore};
pub use redis::{RedisCacheStore, RedisPermanentStore};
pub use sqlite::{SqliteCacheStore, SqlitePermanentStore};
pub use traits::{CacheStore, PermanentStore, Store};

use crate::{StorageError, StorageKind, StorageType};

pub(crate) struct StorageFactory;

impl StorageFactory {
    pub async fn create_cache(storage_type: StorageType) -> Result<Box<dyn CacheStore>, StorageError> {
        match storage_type {
            StorageType::Memory => Ok(Box::new(InMemoryCacheStore::new())),
            StorageType::Redis { url } => {
                let store = RedisCacheStore::connect(&url).await?;
                Ok(Box::new(store))
            }
            StorageType::Postgres { url } => {
                let store = PostgresCacheStore::connect(&url).await?;
                Ok(Box::new(store))
            }
            StorageType::Sqlite { path } => {
                let store = SqliteCacheStore::connect(&path).await?;
                Ok(Box::new(store))
            }
        }
    }

    pub async fn create_permanent(storage_type: StorageType) -> Result<Box<dyn PermanentStore>, StorageError> {
        match storage_type {
            StorageType::Memory => Ok(Box::new(InMemoryPermanentStore::new())),
            StorageType::Redis { url } => {
                let store = RedisPermanentStore::connect(&url).await?;
                Ok(Box::new(store))
            }
            StorageType::Postgres { url } => {
                let store = PostgresPermanentStore::connect(&url).await?;
                Ok(Box::new(store))
            }
            StorageType::Sqlite { path } => {
                let store = SqlitePermanentStore::connect(&path).await?;
                Ok(Box::new(store))
            }
        }
    }
}
