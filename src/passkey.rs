use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::Value as CborValue;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::errors::PasskeyError;

pub(crate) mod attestation;
pub mod auth;
pub mod register;

#[derive(Default)]
struct AuthStore {
    challenges: HashMap<String, StoredChallenge>,
    credentials: HashMap<String, StoredCredential>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredChallenge {
    challenge: Vec<u8>,
    user: PublicKeyCredentialUserEntity,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicKeyCredentialUserEntity {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    counter: u32,
    user: PublicKeyCredentialUserEntity,
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, PasskeyError> {
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    let decoded = URL_SAFE.decode(padded)
        .map_err(|_| PasskeyError::Format("Failed to decode base64url".to_string()))?;
    Ok(decoded)
}

fn generate_challenge() -> Result<Vec<u8>, PasskeyError> {
    let rng = ring::rand::SystemRandom::new();
    let mut challenge = vec![0u8; 32];
    rng.fill(&mut challenge)
        .map_err(|_| PasskeyError::Crypto("Failed to generate random challenge".to_string()))?;
    Ok(challenge)
}

#[derive(Debug)]
struct AttestationObject {
    fmt: String,
    auth_data: Vec<u8>,
    att_stmt: Vec<(CborValue, CborValue)>,
}

// Public things
#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<AuthStore>>,
    config: Config,
}

pub async fn app_state() -> Result<AppState, PasskeyError> {
    let config = Config::from_env()?;
    config.validate()?;

    Ok(AppState {
        store: Arc::new(Mutex::new(AuthStore::default())),
        config,
    })
}
