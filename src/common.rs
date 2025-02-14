use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::rand::SecureRandom;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::errors::PasskeyError;
use crate::passkey::Config;
use crate::storage::{ChallengeStoreType, CredentialStoreType};
use crate::types::AppState;

pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, PasskeyError> {
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    let decoded = URL_SAFE
        .decode(padded)
        .map_err(|_| PasskeyError::Format("Failed to decode base64url".to_string()))?;
    Ok(decoded)
}

pub(crate) fn generate_challenge() -> Result<Vec<u8>, PasskeyError> {
    let rng = ring::rand::SystemRandom::new();
    let mut challenge = vec![0u8; 32];
    rng.fill(&mut challenge)
        .map_err(|_| PasskeyError::Crypto("Failed to generate random challenge".to_string()))?;
    Ok(challenge)
}

// Public things
impl AppState {
    pub async fn new() -> Result<Self, PasskeyError> {
        let config = Config::from_env()?;
        config.validate()?;

        let challenge_store = ChallengeStoreType::from_env()?.create_store().await?;
        let credential_store = CredentialStoreType::from_env()?.create_store().await?;

        // Initialize the stores
        challenge_store.init().await?;
        credential_store.init().await?;

        Ok(Self {
            challenge_store: Arc::new(Mutex::new(challenge_store)),
            credential_store: Arc::new(Mutex::new(credential_store)),
            config,
        })
    }
}
