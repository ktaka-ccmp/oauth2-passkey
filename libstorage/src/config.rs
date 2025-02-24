use std::env;

use crate::{
    store::{init_store, Store},
    types::{StorageError, StorageType},
};

pub struct StorageConfig {
    pub storage_type: StorageType,
}

impl StorageConfig {
    pub fn from_env() -> Result<Self, StorageError> {
        let storage_type = env::var("CACHE_STORAGE_TYPE").unwrap_or_else(|_| "memory".to_string());
        let storage_url = env::var("CACHE_STORAGE_URL").ok();

        let storage_type = match storage_type.as_str() {
            "memory" => StorageType::Memory,
            "redis" => {
                let url = storage_url
                    .ok_or_else(|| StorageError::ConfigError("Redis requires URL".into()))?;
                StorageType::Redis(url)
            }
            "postgres" => {
                let url = storage_url
                    .ok_or_else(|| StorageError::ConfigError("Postgres requires URL".into()))?;
                StorageType::Postgres(url)
            }
            "sqlite" => {
                let url = storage_url
                    .ok_or_else(|| StorageError::ConfigError("SQLite requires path".into()))?;
                StorageType::Sqlite(url)
            }
            _ => {
                return Err(StorageError::ConfigError(format!(
                    "Unknown storage type: {}",
                    storage_type
                )))
            }
        };

        Ok(Self { storage_type })
    }

    pub async fn init_store(&self) -> Result<Box<dyn Store>, StorageError> {
        match &self.storage_type {
            StorageType::Memory => init_store(StorageType::Memory, "").await,
            StorageType::Redis(url) => init_store(StorageType::Redis(url.clone()), url).await,
            StorageType::Postgres(url) => init_store(StorageType::Postgres(url.clone()), url).await,
            StorageType::Sqlite(url) => init_store(StorageType::Sqlite(url.clone()), url).await,
        }
    }
}
