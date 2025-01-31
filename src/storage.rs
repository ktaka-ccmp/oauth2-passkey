use crate::errors::PasskeyError;
use crate::passkey::{StoredChallenge, StoredCredential};
use async_trait::async_trait;

mod memory;
mod postgres;
mod redis;
mod sqlite;

#[derive(Clone, Debug)]
pub enum ChallengeStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

#[derive(Clone, Debug)]
pub enum CredentialStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}

impl ChallengeStoreType {
    pub(crate) async fn create_store(&self) -> Result<Box<dyn ChallengeStore>, PasskeyError> {
        match self {
            ChallengeStoreType::Memory => Ok(Box::new(memory::InMemoryChallengeStore::default())),
            ChallengeStoreType::Sqlite { url } => {
                Ok(Box::new(sqlite::SqliteChallengeStore::connect(url).await?))
            }
            ChallengeStoreType::Postgres { url } => Ok(Box::new(
                postgres::PostgresChallengeStore::connect(url).await?,
            )),
            ChallengeStoreType::Redis { url } => {
                Ok(Box::new(redis::RedisChallengeStore::connect(url).await?))
            }
        }
    }
}

impl CredentialStoreType {
    pub(crate) async fn create_store(&self) -> Result<Box<dyn CredentialStore>, PasskeyError> {
        match self {
            CredentialStoreType::Memory => Ok(Box::new(memory::InMemoryCredentialStore::default())),
            CredentialStoreType::Sqlite { url } => {
                Ok(Box::new(sqlite::SqliteCredentialStore::connect(url).await?))
            }
            CredentialStoreType::Postgres { url } => Ok(Box::new(
                postgres::PostgresCredentialStore::connect(url).await?,
            )),
            CredentialStoreType::Redis { url } => {
                Ok(Box::new(redis::RedisCredentialStore::connect(url).await?))
            }
        }
    }
}

#[async_trait]
pub(crate) trait ChallengeStore: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
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
pub(crate) trait CredentialStore: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
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

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError>;

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError>;
}
