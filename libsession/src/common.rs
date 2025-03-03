use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{DateTime, Utc};
use http::header::{HeaderMap, SET_COOKIE};
use ring::rand::SecureRandom;

use crate::{errors::SessionError, types::StoredSession};

pub(crate) fn gen_random_string(len: usize) -> Result<String, SessionError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| SessionError::Crypto("Failed to generate random string".to_string()))?;
    Ok(URL_SAFE.encode(session_id))
}

pub(crate) fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, SessionError> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .context("failed to parse cookie")
            .map_err(|_| SessionError::Cookie("Failed to parse cookie".to_string()))?,
    );
    Ok(headers)
}

impl From<StoredSession> for libstorage::CacheData {
    fn from(data: StoredSession) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize StoredSession"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for StoredSession {
    type Error = SessionError;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| SessionError::Storage(e.to_string()))
    }
}
