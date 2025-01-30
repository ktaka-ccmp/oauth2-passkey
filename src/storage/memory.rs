use super::{ChallengeStore, CredentialStore};
use crate::errors::PasskeyError;
use crate::passkey::{StoredChallenge, StoredCredential};
use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Default)]
pub struct InMemoryChallengeStore {
    challenges: HashMap<String, StoredChallenge>,
}

#[derive(Default)]
pub struct InMemoryCredentialStore {
    credentials: HashMap<String, StoredCredential>,
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn store_challenge(
        &mut self,
        user_id: String,
        challenge: StoredChallenge,
    ) -> Result<(), PasskeyError> {
        self.challenges.insert(user_id, challenge);
        Ok(())
    }

    async fn get_challenge(&self, user_id: &str) -> Result<Option<StoredChallenge>, PasskeyError> {
        Ok(self.challenges.get(user_id).cloned())
    }

    async fn remove_challenge(&mut self, user_id: &str) -> Result<(), PasskeyError> {
        self.challenges.remove(user_id);
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        Ok(()) // Nothing to initialize for in-memory store
    }

    async fn store_credential(
        &mut self,
        user_id: String,
        credential: StoredCredential,
    ) -> Result<(), PasskeyError> {
        self.credentials.insert(user_id, credential);
        Ok(())
    }

    async fn get_credential(
        &self,
        user_id: &str,
    ) -> Result<Option<StoredCredential>, PasskeyError> {
        Ok(self.credentials.get(user_id).cloned())
    }

    async fn update_credential_counter(
        &mut self,
        user_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        if let Some(credential) = self.credentials.get_mut(user_id) {
            credential.counter = new_counter;
            Ok(())
        } else {
            Err(PasskeyError::NotFound("Credential not found".to_string()))
        }
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        Ok(self.credentials.values().cloned().collect())
    }
}
