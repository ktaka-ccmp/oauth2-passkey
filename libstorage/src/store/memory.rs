use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::{
    store::traits::{RawCacheStore, RawPermanentStore, Store},
    types::{CacheDataKind, PermanentDataKind, QueryField, StorageError},
};

#[derive(Default)]
pub struct MemoryStore {
    cache: RwLock<HashMap<String, Vec<u8>>>,
    permanent: RwLock<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn make_cache_key(kind: CacheDataKind, key: &str) -> String {
        format!("{}:{}", kind, key)
    }

    fn make_permanent_key(kind: PermanentDataKind, key: &str) -> String {
        format!("{}:{}", kind, key)
    }
}

#[async_trait]
impl Store for MemoryStore {
    fn requires_schema(&self) -> bool {
        false
    }

    async fn init(&self) -> Result<(), StorageError> {
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
impl RawCacheStore for MemoryStore {
    async fn put_raw(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: Vec<u8>,
        _ttl: Option<u64>,
    ) -> Result<(), StorageError> {
        let key = Self::make_cache_key(kind, key);
        self.cache.write().unwrap().insert(key, value);
        Ok(())
    }

    async fn get_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let key = Self::make_cache_key(kind, key);
        Ok(self.cache.read().unwrap().get(&key).cloned())
    }

    async fn query_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let prefix = Self::make_cache_key(kind, key);
        let cache = self.cache.read().unwrap();
        let results: Vec<Vec<u8>> = cache
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(results)
    }

    async fn delete(&mut self, kind: CacheDataKind, key: &str) -> Result<(), StorageError> {
        let key = Self::make_cache_key(kind, key);
        self.cache.write().unwrap().remove(&key);
        Ok(())
    }
}

#[async_trait]
impl RawPermanentStore for MemoryStore {
    async fn store_raw(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        let key = Self::make_permanent_key(kind, key);
        self.permanent.write().unwrap().insert(key, value);
        Ok(())
    }

    async fn get_raw(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let key = Self::make_permanent_key(kind, key);
        Ok(self.permanent.read().unwrap().get(&key).cloned())
    }

    async fn query_raw(
        &self,
        kind: PermanentDataKind,
        field: QueryField,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let prefix = match (kind, field) {
            (PermanentDataKind::User, QueryField::Email(email)) => {
                format!("user:*:email:{}", email)
            }
            (PermanentDataKind::Credential, QueryField::UserHandle(handle)) => {
                format!("credential:*:user_handle:{}", handle)
            }
            _ => return Ok(Vec::new()),
        };

        let permanent = self.permanent.read().unwrap();
        let results: Vec<Vec<u8>> = permanent
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(results)
    }

    async fn delete(&mut self, kind: PermanentDataKind, key: &str) -> Result<(), StorageError> {
        let key = Self::make_permanent_key(kind, key);
        self.permanent.write().unwrap().remove(&key);
        Ok(())
    }
}
