use crate::errors::PasskeyError;
use crate::passkey::{StoredChallenge, StoredCredential};
use crate::storage::{ChallengeStore, CredentialStore};
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
        Ok(()) // Nothing to initialize for in-memory store
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

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        if let Some(credential) = self.credentials.get_mut(credential_id) {
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
