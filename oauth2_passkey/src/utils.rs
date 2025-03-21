use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use http::header::{HeaderMap, SET_COOKIE};
use ring::rand::SecureRandom;

// use crate::session::SessionError;
// use crate::passkey::PasskeyError;

// pub(crate) fn gen_random_string(len: usize) -> Result<String, SessionError> {
//     let rng = ring::rand::SystemRandom::new();
//     let mut session_id = vec![0u8; len];
//     rng.fill(&mut session_id)
//         .map_err(|_| SessionError::Crypto("Failed to generate random string".to_string()))?;
//     Ok(URL_SAFE_NO_PAD.encode(session_id))
// }

pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, UtilError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| UtilError::Format("Failed to decode base64url".to_string()))?;
    Ok(decoded)
}

pub(crate) fn base64url_encode(input: Vec<u8>) -> Result<String, UtilError> {
    Ok(URL_SAFE_NO_PAD.encode(input))
}

pub fn gen_random_string(len: usize) -> Result<String, UtilError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| UtilError::Crypto("Failed to generate random string".to_string()))?;
    let encoded = base64url_encode(session_id)
        .map_err(|_| UtilError::Crypto("Failed to encode random string".to_string()))?;
    Ok(encoded)
}

pub(crate) fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, UtilError> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| UtilError::Cookie("Failed to parse cookie".to_string()))?,
    );
    Ok(headers)
}

use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum UtilError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Invalid format: {0}")]
    Format(String),
}
