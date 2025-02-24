use crate::errors::PasskeyError;
use crate::types::{CacheData, StoredChallenge, StoredCredential};
use libstorage::{StorageConfig, Store};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum ChallengeStoreType {
    Memory,
    Redis { url: String },
    Postgres { url: String },
    Sqlite { url: String },
}

#[derive(Clone, Debug)]
pub enum CredentialStoreType {
    Memory,
    Redis { url: String },
    Postgres { url: String },
    Sqlite { url: String },
}

#[derive(Clone, Debug)]
pub enum CacheStoreType {
    LibStorage,            // New variant for libstorage
    Redis { url: String }, // Redis variant with URL
}

pub struct InMemoryChallengeStore {
    pub challenges: HashMap<String, StoredChallenge>,
}

pub struct InMemoryCredentialStore {
    pub credentials: HashMap<String, StoredCredential>,
}

#[derive(Default)]
pub struct InMemoryCacheStore {
    pub cache: HashMap<String, CacheData>,
}

pub struct PostgresChallengeStore {
    pub pool: sqlx::PgPool,
}

pub struct PostgresCredentialStore {
    pub pool: sqlx::PgPool,
}

pub struct RedisChallengeStore {
    pub client: redis::Client,
}

pub struct RedisCredentialStore {
    pub client: redis::Client,
}

pub struct RedisCacheStore {
    pub client: redis::Client,
}

pub struct SqliteChallengeStore {
    pub pool: sqlx::SqlitePool,
}

pub struct SqliteCredentialStore {
    pub pool: sqlx::SqlitePool,
}

pub struct LibStorageCacheStore {
    pub store: Box<dyn Store>,
}

impl LibStorageCacheStore {
    pub async fn new(config: StorageConfig) -> Result<Self, PasskeyError> {
        let store = config
            .init_store()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { store })
    }
}
