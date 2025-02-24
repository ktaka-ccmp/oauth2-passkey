use async_trait::async_trait;
use std::collections::HashMap;

use crate::errors::PasskeyError;
use crate::types::{CacheData, StoredChallenge, StoredCredential};

use super::traits::{CacheStore, ChallengeStore, CredentialStore};
use super::types::{InMemoryCacheStore, InMemoryChallengeStore, InMemoryCredentialStore};

impl InMemoryChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }
}

impl InMemoryCredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }
}

impl InMemoryCacheStore {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(())
    }

    async fn store_challenge(
        &mut self,
        challenge_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError> {
        self.challenges.insert(challenge_id, challenge);
        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<StoredChallenge>, PasskeyError> {
        Ok(self.challenges.get(challenge_id).cloned())
    }

    async fn remove_challenge(&mut self, challenge_id: &str) -> Result<(), PasskeyError> {
        self.challenges.remove(challenge_id);
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(())
    }

    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        self.credentials.insert(credential_id, credential);
        Ok(())
    }

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        Ok(self.credentials.get(credential_id).cloned())
    }

    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        Ok(self
            .credentials
            .values()
            .filter(|c| c.user.name == username)
            .cloned()
            .collect())
    }

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        if let Some(credential) = self.credentials.get_mut(credential_id) {
            credential.counter = new_counter;
            Ok(())
        } else {
            Err(PasskeyError::Storage("Credential not found".into()))
        }
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        Ok(self.credentials.values().cloned().collect())
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(())
    }

    async fn put(&mut self, key: &str, value: CacheData) -> Result<(), PasskeyError> {
        self.cache.insert(key.to_string(), value);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<CacheData>, PasskeyError> {
        Ok(self.cache.get(key).cloned())
    }

    async fn gets(&self, key: &str) -> Result<Vec<CacheData>, PasskeyError> {
        let mut results = Vec::new();
        for (k, v) in self.cache.iter() {
            if k.starts_with(key) {
                results.push(v.clone());
            }
        }
        Ok(results)
    }

    async fn remove(&mut self, key: &str) -> Result<(), PasskeyError> {
        self.cache.remove(key);
        Ok(())
    }
}
