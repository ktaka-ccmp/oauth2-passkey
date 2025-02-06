use redis::{self, AsyncCommands};

use crate::oauth2::AppError;
use crate::types::{StoredToken, StoredSession};

const CHALLENGE_PREFIX: &str = "challenge:";
const CREDENTIAL_PREFIX: &str = "credential:";

pub(crate) struct RedisChallengeStore {
    client: redis::Client,
}

impl RedisChallengeStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, PasskeyError> {
        println!("Connecting to Redis at {} for challenges", url);
        let client = redis::Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

impl super::ChallengeStore for RedisChallengeStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        // Verify the connection works
        let _conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(format!("Redis connection error: {}", e)))?;
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

        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let value =
            serde_json::to_string(&challenge).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, value, challenge.ttl)
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

        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match value {
            Some(v) => Ok(Some(
                serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?,
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

        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(())
    }
}

pub(crate) struct RedisCredentialStore {
    client: redis::Client,
}

impl RedisCredentialStore {
    pub(crate) async fn connect(url: &str) -> Result<Self, PasskeyError> {
        println!("Connecting to Redis at {} for credentials", url);
        let client = redis::Client::open(url).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        Ok(Self { client })
    }
}

impl super::CredentialStore for RedisCredentialStore {
    async fn init(&self) -> Result<(), PasskeyError> {
        // Verify the connection works
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

        let key = format!("{}{}", CREDENTIAL_PREFIX, credential_id);
        let value =
            serde_json::to_string(&credential).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let _: () = conn
            .set(&key, value)
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

        let key = format!("{}{}", CREDENTIAL_PREFIX, credential_id);
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        match value {
            Some(v) => Ok(Some(
                serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    async fn update_credential_counter(
        &mut self,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<(), PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let key = format!("{}{}", CREDENTIAL_PREFIX, credential_id);

        // Get the existing credential
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut credential: StoredCredential = match value {
            Some(v) => {
                serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?
            }
            None => return Err(PasskeyError::Storage("Credential not found".to_string())),
        };

        // Update the counter
        credential.counter = new_counter;

        // Save back to Redis
        let value =
            serde_json::to_string(&credential).map_err(|e| PasskeyError::Storage(e.to_string()))?;
        let _: () = conn
            .set(&key, value)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_credentials_by_username(
        &self,
        username: &str,
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
        let all_credentials = self.get_all_credentials().await?;
        Ok(all_credentials
            .into_iter()
            .filter(|credential| credential.user.name == username)
            .collect())
    }

    async fn get_all_credentials(&self) -> Result<Vec<StoredCredential>, PasskeyError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let pattern = format!("{}*", CREDENTIAL_PREFIX);
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| PasskeyError::Storage(e.to_string()))?;

        let mut credentials = Vec::new();
        for key in keys {
            let value: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| PasskeyError::Storage(e.to_string()))?;

            if let Some(v) = value {
                let credential: StoredCredential =
                    serde_json::from_str(&v).map_err(|e| PasskeyError::Storage(e.to_string()))?;
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }
}
