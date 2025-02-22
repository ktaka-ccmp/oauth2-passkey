use std::collections::HashMap;
use std::sync::Mutex;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    CacheDataKind, PermanentDataKind, QueryField, QueryRelation,
    Store, CacheStore, PermanentStore, StorageError,
};

pub struct InMemoryCacheStore {
    data: Mutex<HashMap<String, (String, Option<std::time::Instant>)>>,
}

impl InMemoryCacheStore {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Store for InMemoryCacheStore {
    fn requires_schema(&self) -> bool {
        false
    }

    async fn init(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn put<T: Serialize + Send + Sync>(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: &T,
        ttl_secs: Option<u64>,
    ) -> Result<(), StorageError> {
        let prefixed_key = format!("{}{}", kind.prefix(), key);
        let json = serde_json::to_string(value)?;
        let expiry = ttl_secs.map(|secs| {
            std::time::Instant::now() + std::time::Duration::from_secs(secs)
        });
        
        let mut data = self.data.lock().unwrap();
        data.insert(prefixed_key, (json, expiry));
        Ok(())
    }

    async fn get<T: DeserializeOwned>(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let prefixed_key = format!("{}{}", kind.prefix(), key);
        let data = self.data.lock().unwrap();
        
        if let Some((json, expiry)) = data.get(&prefixed_key) {
            // Check if expired
            if let Some(expiry) = expiry {
                if expiry < &std::time::Instant::now() {
                    return Ok(None);
                }
            }
            Ok(Some(serde_json::from_str(json)?))
        } else {
            Ok(None)
        }
    }

    async fn delete(
        &mut self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<(), StorageError> {
        let prefixed_key = format!("{}{}", kind.prefix(), key);
        let mut data = self.data.lock().unwrap();
        data.remove(&prefixed_key);
        Ok(())
    }
}

pub struct InMemoryPermanentStore {
    data: Mutex<HashMap<String, String>>,
    indexes: Mutex<HashMap<String, Vec<String>>>,
}

impl InMemoryPermanentStore {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
            indexes: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Store for InMemoryPermanentStore {
    fn requires_schema(&self) -> bool {
        false
    }

    async fn init(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[async_trait]
impl PermanentStore for InMemoryPermanentStore {
    async fn store<T: Serialize + Send + Sync>(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        let json = serde_json::to_string(value)?;
        let mut data = self.data.lock().unwrap();
        let mut indexes = self.indexes.lock().unwrap();

        // Store main data
        data.insert(format!("{:?}:{}", kind, key), json.clone());

        // Update indexes based on the data type
        let value_json: serde_json::Value = serde_json::from_str(&json)?;
        match kind {
            PermanentDataKind::User => {
                if let Some(email) = value_json.get("email") {
                    let index_key = format!("email:{}", email.as_str().unwrap());
                    indexes.insert(index_key, vec![key.to_string()]);
                }
            }
            PermanentDataKind::Credential => {
                if let Some(user_handle) = value_json.get("user_handle") {
                    let index_key = format!("user:{}:credentials", user_handle.as_str().unwrap());
                    let entry = indexes.entry(index_key).or_insert_with(Vec::new);
                    entry.push(key.to_string());
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
        let data = self.data.lock().unwrap();
        if let Some(json) = data.get(&format!("{:?}:{}", kind, key)) {
            Ok(Some(serde_json::from_str(json)?))
        } else {
            Ok(None)
        }
    }

    async fn delete(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<(), StorageError> {
        let mut data = self.data.lock().unwrap();
        data.remove(&format!("{:?}:{}", kind, key));
        Ok(())
    }

    async fn query<T: DeserializeOwned>(
        &self,
        relation: QueryRelation,
        field: QueryField,
    ) -> Result<Vec<T>, StorageError> {
        let indexes = self.indexes.lock().unwrap();
        let data = self.data.lock().unwrap();
        
        let index_key = relation.redis_key_pattern(&field);
        let keys = indexes.get(&index_key).cloned().unwrap_or_default();
        
        let mut results = Vec::new();
        for key in keys {
            if let Some(json) = data.get(&key) {
                results.push(serde_json::from_str(json)?);
            }
        }
        
        Ok(results)
    }
}
