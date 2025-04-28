use crate::storage::GENERIC_CACHE_STORE;
use crate::utils::gen_random_string;
use crate::utils::header_set_cookie;
use chrono::{DateTime, Duration, Utc};
use headers::Cookie;
use headers::HeaderMap;

use serde::{Deserialize, Serialize};

use super::super::config::{O2P_CSRF_COOKIE_MAX_AGE, O2P_CSRF_COOKIE_NAME};
use super::super::errors::SessionError;
use crate::storage::CacheData;

#[derive(Serialize, Clone, Deserialize, Debug)]
pub(crate) struct CsrfToken {
    pub(crate) user_id: String,
    pub(crate) session_id: String,
    pub(crate) token: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) ttl: u64,
}

impl From<CsrfToken> for CacheData {
    fn from(data: CsrfToken) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize CsrfToken"),
        }
    }
}

impl TryFrom<CacheData> for CsrfToken {
    type Error = SessionError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| SessionError::Storage(e.to_string()))
    }
}

pub(super) async fn add_csrf_token_to_header(
    user_id: &str,
    session_id: &str,
    headers: &mut HeaderMap,
) -> Result<(), SessionError> {
    let context_headers = create_csrf_token(user_id, session_id).await?;

    context_headers.iter().for_each(|(key, value)| {
        headers.append(key, value.clone());
    });
    Ok(())
}

async fn create_csrf_token(user_id: &str, session_id: &str) -> Result<HeaderMap, SessionError> {
    let expires_at = Utc::now() + Duration::seconds(*O2P_CSRF_COOKIE_MAX_AGE as i64);
    let ttl = *O2P_CSRF_COOKIE_MAX_AGE;

    let csrf_token = gen_random_string(32)?;
    let csrf_id = gen_random_string(32)?;

    let token_data = CsrfToken {
        user_id: user_id.to_string(),
        session_id: session_id.to_string(),
        token: csrf_token.to_string(),
        expires_at,
        ttl,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl("csrf", &csrf_id, token_data.into(), ttl.try_into().unwrap())
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        O2P_CSRF_COOKIE_NAME.to_string(),
        csrf_id.to_string(),
        expires_at,
        ttl as i64,
    )?;

    tracing::debug!("Headers: {:#?}", headers);
    Ok(headers)
}

pub async fn verify_csrf_token(cookies: Cookie, csrf_token: &str) -> Result<(), SessionError> {
    let csrf_id = cookies
        .get(O2P_CSRF_COOKIE_NAME.as_str())
        .ok_or_else(|| SessionError::Storage("No CSRF session cookie found".to_string()))?;

    let cached_csrf_token = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("csrf", csrf_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::Storage("CSRF Token Not Found".to_string()))?;

    let stored_csrf_token: CsrfToken = cached_csrf_token.try_into()?;

    tracing::debug!("CSRF Session: {:#?}", stored_csrf_token);

    if csrf_token != stored_csrf_token.token {
        tracing::error!(
            "CSRF Token mismatch, received: {:?}, expected: {:?}",
            csrf_token,
            stored_csrf_token.token
        );
        return Err(SessionError::Storage("CSRF Token Mismatch".to_string()));
    }

    if Utc::now() > stored_csrf_token.expires_at {
        tracing::error!("CSRF Token expired");
        return Err(SessionError::Storage("CSRF Token Expired".to_string()));
    }

    Ok(())
}
