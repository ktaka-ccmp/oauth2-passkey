use async_trait::async_trait;
use libstorage::store::redis::RedisStore;
use libstorage::{CacheDataKind, RawCacheStore, StorageConfig, Store};
use std::any::Any;
use std::env;

use crate::errors::PasskeyError;
use crate::types::{CacheData, StoredChallenge, StoredCredential};

use super::types::{
    CacheStoreType, ChallengeStoreType, CredentialStoreType, InMemoryChallengeStore,
    InMemoryCredentialStore, LibStorageCacheStore, PostgresChallengeStore, PostgresCredentialStore,
    RedisCacheStore, RedisChallengeStore, RedisCredentialStore, SqliteChallengeStore,
    SqliteCredentialStore,
};

#[async_trait]
pub trait ChallengeStore: Send + Sync + 'static {
    async fn init(&self) -> Result<(), PasskeyError>;
    async fn store_challenge(
        &mut self,
        challenge_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError>;
    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<StoredChallenge>, PasskeyError>;
    async fn remove_challenge(&mut self, challenge_id: &str) -> Result<(), PasskeyError>;
}

#[async_trait]
pub trait CredentialStore: Send + Sync + 'static {
    async fn init(&self) -> Result<(), PasskeyError>;
    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError>;
    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError>;
    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError>;
    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError>;
    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError>;
}

#[async_trait]
pub trait CacheStore: Send + Sync + 'static {
    async fn init(&self) -> Result<(), PasskeyError>;
    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), PasskeyError>;
    async fn get(&self, key: &str) -> Result<Option<CacheData>, PasskeyError>;
    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, PasskeyError>;
    async fn remove(&mut self, key: &str) -> Result<(), PasskeyError>;
}

pub async fn create_challenge_store(
    store_type: ChallengeStoreType,
) -> Result<Box<dyn ChallengeStore>, PasskeyError> {
    let store: Box<dyn ChallengeStore> = match store_type {
        ChallengeStoreType::Memory => Box::new(InMemoryChallengeStore::new()),
        ChallengeStoreType::Sqlite { url } => Box::new(SqliteChallengeStore::connect(&url).await?),
        ChallengeStoreType::Postgres { url } => {
            Box::new(PostgresChallengeStore::connect(&url).await?)
        }
        ChallengeStoreType::Redis { url } => Box::new(RedisChallengeStore::connect(&url).await?),
    };
    store.init().await?;
    Ok(store)
}

pub async fn create_credential_store(
    store_type: CredentialStoreType,
) -> Result<Box<dyn CredentialStore>, PasskeyError> {
    let store: Box<dyn CredentialStore> = match store_type {
        CredentialStoreType::Memory => Box::new(InMemoryCredentialStore::new()),
        CredentialStoreType::Sqlite { url } => {
            Box::new(SqliteCredentialStore::connect(&url).await?)
        }
        CredentialStoreType::Postgres { url } => {
            Box::new(PostgresCredentialStore::connect(&url).await?)
        }
        CredentialStoreType::Redis { url } => Box::new(RedisCredentialStore::connect(&url).await?),
    };
    store.init().await?;
    Ok(store)
}

pub async fn create_cache_store(
    store_type: CacheStoreType,
    config: StorageConfig,
) -> Result<Box<dyn CacheStore>, PasskeyError> {
    let store: Box<dyn CacheStore> = match store_type {
        CacheStoreType::LibStorage => Box::new(LibStorageCacheStore::new(config).await?),
        CacheStoreType::Redis { url } => Box::new(RedisCacheStore::connect(&url).await?),
    };
    store.init().await?;
    Ok(store)
}

impl ChallengeStoreType {
    pub fn from_env() -> Result<Self, PasskeyError> {
        let store_type = env::var("PASSKEY_CHALLENGE_STORE")
            .map_err(|_| PasskeyError::Storage("PASSKEY_CHALLENGE_STORE not set".into()))?;

        match store_type.as_str() {
            "memory" => Ok(ChallengeStoreType::Memory),
            "sqlite" => {
                let url = env::var("PASSKEY_CHALLENGE_SQLITE_URL").map_err(|_| {
                    PasskeyError::Storage("PASSKEY_CHALLENGE_SQLITE_URL not set".into())
                })?;
                Ok(ChallengeStoreType::Sqlite { url })
            }
            "postgres" => {
                let url = env::var("PASSKEY_CHALLENGE_POSTGRES_URL").map_err(|_| {
                    PasskeyError::Storage("PASSKEY_CHALLENGE_POSTGRES_URL not set".into())
                })?;
                Ok(ChallengeStoreType::Postgres { url })
            }
            "redis" => {
                let url = env::var("PASSKEY_CHALLENGE_REDIS_URL").map_err(|_| {
                    PasskeyError::Storage("PASSKEY_CHALLENGE_REDIS_URL not set".into())
                })?;
                Ok(ChallengeStoreType::Redis { url })
            }
            _ => Err(PasskeyError::Storage(
                "Invalid PASSKEY_CHALLENGE_STORE value".into(),
            )),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn ChallengeStore>, PasskeyError> {
        let store: Box<dyn ChallengeStore> = match self {
            ChallengeStoreType::Memory => Box::new(InMemoryChallengeStore::new()),
            ChallengeStoreType::Sqlite { url } => {
                Box::new(SqliteChallengeStore::connect(url).await?)
            }
            ChallengeStoreType::Postgres { url } => {
                Box::new(PostgresChallengeStore::connect(url).await?)
            }
            ChallengeStoreType::Redis { url } => Box::new(RedisChallengeStore::connect(url).await?),
        };
        store.init().await?;
        Ok(store)
    }
}

impl CredentialStoreType {
    pub fn from_env() -> Result<Self, PasskeyError> {
        let store_type = env::var("PASSKEY_CREDENTIAL_STORE")
            .map_err(|_| PasskeyError::Storage("PASSKEY_CREDENTIAL_STORE not set".into()))?;

        match store_type.as_str() {
            "memory" => Ok(CredentialStoreType::Memory),
            "sqlite" => {
                let url = env::var("PASSKEY_CREDENTIAL_SQLITE_URL").map_err(|_| {
                    PasskeyError::Storage("PASSKEY_CREDENTIAL_SQLITE_URL not set".into())
                })?;
                Ok(CredentialStoreType::Sqlite { url })
            }
            "postgres" => {
                let url = env::var("PASSKEY_CREDENTIAL_POSTGRES_URL").map_err(|_| {
                    PasskeyError::Storage("PASSKEY_CREDENTIAL_POSTGRES_URL not set".into())
                })?;
                Ok(CredentialStoreType::Postgres { url })
            }
            "redis" => {
                let url = env::var("PASSKEY_CREDENTIAL_REDIS_URL").map_err(|_| {
                    PasskeyError::Storage("PASSKEY_CREDENTIAL_REDIS_URL not set".into())
                })?;
                Ok(CredentialStoreType::Redis { url })
            }
            _ => Err(PasskeyError::Storage(
                "Invalid PASSKEY_CREDENTIAL_STORE value".into(),
            )),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn CredentialStore>, PasskeyError> {
        let store: Box<dyn CredentialStore> = match self {
            CredentialStoreType::Memory => Box::new(InMemoryCredentialStore::new()),
            CredentialStoreType::Sqlite { url } => {
                Box::new(SqliteCredentialStore::connect(url).await?)
            }
            CredentialStoreType::Postgres { url } => {
                Box::new(PostgresCredentialStore::connect(url).await?)
            }
            CredentialStoreType::Redis { url } => {
                Box::new(RedisCredentialStore::connect(url).await?)
            }
        };
        store.init().await?;
        Ok(store)
    }
}

impl CacheStoreType {
    pub fn from_env() -> Result<Self, PasskeyError> {
        Ok(CacheStoreType::LibStorage)
    }

    pub async fn create_store(
        &self,
        config: StorageConfig,
    ) -> Result<Box<dyn CacheStore>, PasskeyError> {
        let store: Box<dyn CacheStore> = match self {
            CacheStoreType::LibStorage => Box::new(LibStorageCacheStore::new(config).await?),
            CacheStoreType::Redis { url } => Box::new(RedisCacheStore::connect(url).await?),
        };
        store.init().await?;
        Ok(store)
    }
}

#[async_trait]
impl RawCacheStore for LibStorageCacheStore {
    async fn put_raw(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: Vec<u8>,
        ttl: Option<u64>,
    ) -> Result<(), libstorage::types::StorageError> {
        if let Some(store) = self.store.as_any_mut().downcast_mut::<RedisStore>() {
            store.put_raw(kind, key, value, ttl).await
        } else {
            Err(libstorage::types::StorageError::ConfigError(
                "Store does not implement RawCacheStore".to_string(),
            ))
        }
    }

    async fn get_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, libstorage::types::StorageError> {
        if let Some(store) = self.store.as_any().downcast_ref::<RedisStore>() {
            store.get_raw(kind, key).await
        } else {
            Err(libstorage::types::StorageError::ConfigError(
                "Store does not implement RawCacheStore".to_string(),
            ))
        }
    }

    async fn query_raw(
        &self,
        kind: CacheDataKind,
        prefix: &str,
    ) -> Result<Vec<Vec<u8>>, libstorage::types::StorageError> {
        if let Some(store) = self.store.as_any().downcast_ref::<RedisStore>() {
            store.query_raw(kind, prefix).await
        } else {
            Err(libstorage::types::StorageError::ConfigError(
                "Store does not implement RawCacheStore".to_string(),
            ))
        }
    }

    async fn delete(
        &mut self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<(), libstorage::types::StorageError> {
        if let Some(store) = self.store.as_any_mut().downcast_mut::<RedisStore>() {
            store.delete(kind, key).await
        } else {
            Err(libstorage::types::StorageError::ConfigError(
                "Store does not implement RawCacheStore".to_string(),
            ))
        }
    }
}

#[async_trait]
impl Store for LibStorageCacheStore {
    async fn init(&self) -> Result<(), libstorage::types::StorageError> {
        self.store.init().await
    }

    fn requires_schema(&self) -> bool {
        self.store.requires_schema()
    }

    fn as_any(&self) -> &(dyn Any + 'static) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + 'static) {
        self
    }
}

#[async_trait]
impl CacheStore for LibStorageCacheStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        self.store
            .init()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), PasskeyError> {
        let store = self
            .store
            .as_any_mut()
            .downcast_mut::<RedisStore>()
            .ok_or_else(|| {
                PasskeyError::Storage("Store does not implement RawCacheStore".into())
            })?;
        let bytes = serde_json::to_vec(&value).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        RawCacheStore::put_raw(store, CacheDataKind::Session, key, bytes, Some(3600))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, PasskeyError> {
        let store = self
            .store
            .as_any()
            .downcast_ref::<RedisStore>()
            .ok_or_else(|| {
                PasskeyError::Storage("Store does not implement RawCacheStore".into())
            })?;
        let bytes = RawCacheStore::get_raw(store, CacheDataKind::Session, key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        match bytes {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, PasskeyError> {
        let store = self
            .store
            .as_any()
            .downcast_ref::<RedisStore>()
            .ok_or_else(|| {
                PasskeyError::Storage("Store does not implement RawCacheStore".into())
            })?;
        let data = RawCacheStore::query_raw(store, CacheDataKind::Session, key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        data.into_iter()
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| PasskeyError::Storage(e.to_string()))
            })
            .collect()
    }

    async fn remove(&mut self, key: &str) -> Result<(), PasskeyError> {
        let store = self
            .store
            .as_any_mut()
            .downcast_mut::<RedisStore>()
            .ok_or_else(|| {
                PasskeyError::Storage("Store does not implement RawCacheStore".into())
            })?;
        RawCacheStore::delete(store, CacheDataKind::Session, key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}
