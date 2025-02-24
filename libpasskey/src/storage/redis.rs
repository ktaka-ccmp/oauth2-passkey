use async_trait::async_trait;
use libstorage::types::StorageError;
use libstorage::{CacheDataKind, RawCacheStore, Store};
use redis::{AsyncCommands, Client};
use std::any::Any;

use crate::errors::PasskeyError;
use crate::types::{CacheData, StoredChallenge, StoredCredential};

use super::traits::{CacheStore, ChallengeStore, CredentialStore};
use super::types::{RedisCacheStore, RedisChallengeStore, RedisCredentialStore};

impl RedisChallengeStore {
    pub async fn connect(url: &str) -> Result<Self, PasskeyError> {
        let client = Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

impl RedisCredentialStore {
    pub async fn connect(url: &str) -> Result<Self, PasskeyError> {
        let client = Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

impl RedisCacheStore {
    pub async fn connect(url: &str) -> Result<Self, PasskeyError> {
        let client = Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

const CHALLENGE_PREFIX: &str = "challenge:";
const CREDENTIAL_PREFIX: &str = "credential:";
const CACHE_PREFIX: &str = "cache:";

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_challenge(
        &mut self,
        challenge_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let json =
            serde_json::to_string(&challenge).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set_ex(&format!("{}{}", CHALLENGE_PREFIX, challenge_id), json, 300)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<StoredChallenge>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let json: Option<String> = conn
            .get(&format!("{}{}", CHALLENGE_PREFIX, challenge_id))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn remove_challenge(&mut self, challenge_id: &str) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .del(&format!("{}{}", CHALLENGE_PREFIX, challenge_id))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl CredentialStore for RedisCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let json =
            serde_json::to_string(&credential).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set(&format!("{}{}", CREDENTIAL_PREFIX, credential_id), json)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let json: Option<String> = conn
            .get(&format!("{}{}", CREDENTIAL_PREFIX, credential_id))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let keys: Vec<String> = conn
            .keys(&format!("{}*", CREDENTIAL_PREFIX))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut credentials = Vec::new();
        for key in keys {
            if let Ok(Some(credential)) = self.get_credential(&key).await {
                if credential.user.name == username {
                    credentials.push(credential);
                }
            }
        }

        Ok(credentials)
    }

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        if let Some(mut credential) = self.get_credential(credential_id).await? {
            credential.counter = new_counter;
            self.store_credential(credential_id.to_string(), credential)
                .await?;
        }
        Ok(())
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let keys: Vec<String> = conn
            .keys(&format!("{}*", CREDENTIAL_PREFIX))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut credentials = Vec::new();
        for key in keys {
            if let Ok(Some(credential)) = self.get_credential(&key).await {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }
}

#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let json =
            serde_json::to_string(&value).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set(&format!("{}{}", CACHE_PREFIX, key), json)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let json: Option<String> = conn
            .get(&format!("{}{}", CACHE_PREFIX, key))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match json {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn gets(&self, _key: &str) -> Result<Vec<CacheData>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let keys: Vec<String> = conn
            .keys(&format!("{}*", CACHE_PREFIX))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut results = Vec::new();
        for key in keys {
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| PasskeyError::Storage(e.to_string()))?;

            if let Some(json) = json {
                let data: CacheData = serde_json::from_str(&json)
                    .map_err(|e| PasskeyError::Storage(e.to_string()))?;
                results.push(data);
            }
        }

        Ok(results)
    }

    async fn remove(&mut self, key: &str) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .del(&format!("{}{}", CACHE_PREFIX, key))
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl Store for RedisCacheStore {
    async fn init(&self) -> Result<(), StorageError> {
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(StorageError::RedisError)?;
        Ok(())
    }

    fn requires_schema(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + 'static) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + 'static) {
        self
    }
}

#[async_trait]
impl RawCacheStore for RedisCacheStore {
    async fn put_raw(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: Vec<u8>,
        ttl: Option<u64>,
    ) -> Result<(), StorageError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(StorageError::RedisError)?;
        let key = format!("{}{}", CACHE_PREFIX, key);
        let _: () = conn
            .set(&key, value)
            .await
            .map_err(StorageError::RedisError)?;
        if let Some(ttl) = ttl {
            let _: () = conn
                .expire(&key, ttl as i64)
                .await
                .map_err(StorageError::RedisError)?;
        }
        Ok(())
    }

    async fn get_raw(
        &self,
        _kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(StorageError::RedisError)?;
        let key = format!("{}{}", CACHE_PREFIX, key);
        let value: Option<Vec<u8>> = conn.get(&key).await.map_err(StorageError::RedisError)?;
        Ok(value)
    }

    async fn query_raw(
        &self,
        _kind: CacheDataKind,
        prefix: &str,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(StorageError::RedisError)?;
        let pattern = format!("{}{}*", CACHE_PREFIX, prefix);
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(StorageError::RedisError)?;
        let mut values = Vec::new();
        for key in keys {
            let value: Option<Vec<u8>> = conn.get(&key).await.map_err(StorageError::RedisError)?;
            if let Some(value) = value {
                values.push(value);
            }
        }
        Ok(values)
    }

    async fn delete(&mut self, _kind: CacheDataKind, key: &str) -> Result<(), StorageError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(StorageError::RedisError)?;
        let key = format!("{}{}", CACHE_PREFIX, key);
        let _: () = conn.del(&key).await.map_err(StorageError::RedisError)?;
        Ok(())
    }
}
