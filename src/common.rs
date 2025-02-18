use base64::engine::{general_purpose::URL_SAFE, Engine};
use ring::rand::SecureRandom;

use crate::errors::PasskeyError;

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
