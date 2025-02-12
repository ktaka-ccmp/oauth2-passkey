use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::Value as CborValue;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::errors::PasskeyError;
use crate::storage::{ChallengeStore, ChallengeStoreType, CredentialStore, CredentialStoreType};

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub(crate) struct PublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct StoredChallenge {
    pub challenge: Vec<u8>,
    pub user: PublicKeyCredentialUserEntity,
    pub timestamp: u64,
    pub ttl: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub user: PublicKeyCredentialUserEntity,
}

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

#[derive(Debug)]
pub(crate) struct AttestationObject {
    pub(crate) fmt: String,
    pub(crate) auth_data: Vec<u8>,
    pub(crate) att_stmt: Vec<(CborValue, CborValue)>,
}

// Public things
#[derive(Clone)]
pub struct AppState {
    pub(crate) challenge_store: Arc<Mutex<Box<dyn ChallengeStore>>>,
    pub(crate) credential_store: Arc<Mutex<Box<dyn CredentialStore>>>,
    pub(crate) config: Config,
}

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
