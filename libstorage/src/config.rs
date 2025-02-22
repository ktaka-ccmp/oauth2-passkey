use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::{
    store::StorageFactory,
    types::{StorageKind, StorageType},
    CacheStore, PermanentStore, StorageError,
};

pub struct StorageConfig {
    storage_type: StorageType,
    url: String,
}

impl StorageConfig {
    pub fn from_env() -> Result<Self, StorageError> {
        dotenvy::dotenv().ok();

        let storage_type = std::env::var("STORAGE_TYPE")
            .unwrap_or_else(|_| "memory".to_string());
        
        let url = std::env::var("STORAGE_URL")
            .unwrap_or_else(|_| "".to_string());

        let storage_type = match storage_type.as_str() {
            "memory" => StorageType::Memory,
            "redis" => StorageType::Redis { url: url.clone() },
            "postgres" => StorageType::Postgres { url: url.clone() },
            "sqlite" => StorageType::Sqlite { path: url.clone() },
            _ => return Err(StorageError::Config("Invalid storage type".into())),
        };

        Ok(Self {
            storage_type,
            url,
        })
    }
}

pub static CACHE_STORE: Lazy<Mutex<Box<dyn CacheStore>>> = Lazy::new(|| {
    let config = StorageConfig::from_env()
        .expect("Failed to load storage config");
    
    let store = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime")
        .block_on(async {
            StorageFactory::create_cache(config.storage_type)
                .await
                .expect("Failed to create cache store")
        });

    Mutex::new(store)
});

pub static PERMANENT_STORE: Lazy<Mutex<Box<dyn PermanentStore>>> = Lazy::new(|| {
    let config = StorageConfig::from_env()
        .expect("Failed to load storage config");
    
    let store = tokio::runtime::Runtime::new()
        .expect("Failed to create runtime")
        .block_on(async {
            StorageFactory::create_permanent(config.storage_type)
                .await
                .expect("Failed to create permanent store")
        });

    Mutex::new(store)
});
