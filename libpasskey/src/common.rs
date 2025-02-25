use base64::engine::{Engine, general_purpose::URL_SAFE};
use ring::rand::SecureRandom;

use libstorage::GENERIC_CACHE_STORE;

use crate::errors::PasskeyError;
use crate::types::EmailUserId;

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

pub(crate) fn gen_random_string(len: usize) -> Result<String, PasskeyError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| PasskeyError::Crypto("Failed to generate random string".to_string()))?;
    Ok(URL_SAFE.encode(session_id))
}

pub async fn email_to_user_id(username: String) -> Result<String, PasskeyError> {
    let email_user_id: EmailUserId = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get("email", &username)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?
        .ok_or_else(|| PasskeyError::NotFound("User not found".to_string()))?
        .try_into()?;

    Ok(email_user_id.user_id)
}

// libpasskey/src/types.rs
impl From<EmailUserId> for libstorage::CacheData {
    fn from(data: EmailUserId) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize EmailUserId"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for EmailUserId {
    type Error = PasskeyError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}
