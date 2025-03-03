use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{DateTime, Utc};
use http::header::HeaderMap;
use ring::rand::SecureRandom;
use std::time::Duration;
use url::Url;

use crate::config::OAUTH2_CSRF_COOKIE_MAX_AGE;
use crate::errors::OAuth2Error;
use crate::types::{StateParams, StoredToken};

use libstorage::GENERIC_CACHE_STORE;

pub(super) fn gen_random_string(len: usize) -> Result<String, OAuth2Error> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| OAuth2Error::Crypto("Failed to generate random string".to_string()))?;
    Ok(URL_SAFE.encode(session_id))
}

pub fn encode_state(csrf_token: String, nonce_id: String, pkce_id: String) -> String {
    let state_params = StateParams {
        csrf_token,
        nonce_id,
        pkce_id,
    };

    let state_json = serde_json::json!(state_params).to_string();
    URL_SAFE.encode(state_json)
}

pub async fn generate_store_token(
    token_type: &str,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
) -> Result<(String, String), OAuth2Error> {
    let token = gen_random_string(32)?;
    let token_id = gen_random_string(32)?;

    let token_data = StoredToken {
        token: token.clone(),
        expires_at,
        user_agent,
        ttl: *OAUTH2_CSRF_COOKIE_MAX_AGE,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .put(token_type, &token_id, token_data.into())
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok((token, token_id))
}

pub(crate) async fn get_token_from_store<T>(
    token_type: &str,
    token_id: &str,
) -> Result<T, OAuth2Error>
where
    T: TryFrom<libstorage::CacheData, Error = OAuth2Error>,
{
    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get(token_type, token_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?
        .ok_or_else(|| {
            OAuth2Error::SecurityTokenNotFound(format!("{}-session not found", token_type))
        })?
        .try_into()
}

pub(crate) async fn remove_token_from_store(
    token_type: &str,
    token_id: &str,
) -> Result<(), OAuth2Error> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove(token_type, token_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub async fn validate_origin(headers: &HeaderMap, auth_url: &str) -> Result<(), OAuth2Error> {
    let parsed_url = Url::parse(auth_url).expect("Invalid URL");
    let scheme = parsed_url.scheme();
    let host = parsed_url.host_str().unwrap_or_default();
    let port = parsed_url
        .port()
        .map_or("".to_string(), |p| format!(":{}", p));
    let expected_origin = format!("{}://{}{}", scheme, host, port);

    let origin = headers
        .get("Origin")
        .or_else(|| headers.get("Referer"))
        .and_then(|h| h.to_str().ok());

    match origin {
        Some(origin) if origin.starts_with(&expected_origin) => Ok(()),
        _ => {
            tracing::error!("Expected Origin: {:#?}", expected_origin);
            tracing::error!("Actual Origin: {:#?}", origin);
            Err(OAuth2Error::InvalidOrigin(format!(
                "Expected Origin: {:#?}, Actual Origin: {:#?}",
                expected_origin, origin
            )))
        }
    }
}

/// Creates a configured HTTP client for OAuth2 operations with the following settings:
///
/// - `timeout`: Set to 30 seconds to prevent indefinite hanging of requests.
///   OAuth2 operations should complete quickly, and hanging requests could block resources.
///
/// - `pool_idle_timeout`: Set to default (90 seconds). This controls how long an idle
///   connection can stay in the connection pool before being removed.
///
/// - `pool_max_idle_per_host`: Set to 32 (default). This controls the maximum number of idle
///   connections that can be maintained per host in the connection pool. The default value
///   provides good balance for parallel OAuth2 operations while being memory efficient.
pub(crate) fn get_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .build()
        .expect("Failed to create reqwest client")
}
