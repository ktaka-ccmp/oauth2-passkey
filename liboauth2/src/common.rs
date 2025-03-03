use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{DateTime, Utc};
use http::header::{HeaderMap, SET_COOKIE};
use ring::rand::SecureRandom;

use crate::errors::OAuth2Error;
use crate::types::StoredToken;

pub(crate) fn gen_random_string(len: usize) -> Result<String, OAuth2Error> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| OAuth2Error::Crypto("Failed to generate random string".to_string()))?;
    Ok(URL_SAFE.encode(session_id))
}

pub fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, OAuth2Error> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| OAuth2Error::Cookie("Failed to parse cookie".to_string()))?,
    );
    Ok(headers)
}

impl From<StoredToken> for libstorage::CacheData {
    fn from(data: StoredToken) -> Self {
        Self {
            value: serde_json::to_vec(&data).expect("Failed to serialize StoredToken"),
        }
    }
}

impl TryFrom<libstorage::CacheData> for StoredToken {
    type Error = OAuth2Error;

    fn try_from(data: libstorage::CacheData) -> Result<Self, Self::Error> {
        serde_json::from_slice(&data.value).map_err(|e| OAuth2Error::Storage(e.to_string()))
    }
}
