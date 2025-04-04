use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use http::header::HeaderMap;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

use crate::oauth2::{OAuth2Error, OAuth2Mode, StateParams, StoredToken};

use crate::session::{
    User as SessionUser, delete_session_from_store_by_session_id, get_user_from_session,
};
use crate::storage::{CacheData, GENERIC_CACHE_STORE};
use crate::utils::gen_random_string;

pub(super) fn encode_state(state_params: StateParams) -> Result<String, OAuth2Error> {
    let state_json =
        serde_json::to_string(&state_params).map_err(|e| OAuth2Error::Serde(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(state_json))
}

pub(crate) fn decode_state(state: &str) -> Result<StateParams, OAuth2Error> {
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(state)
        .map_err(|e| OAuth2Error::DecodeState(format!("Failed to decode base64: {}", e)))?;
    let decoded_state_string = String::from_utf8(decoded_bytes)
        .map_err(|e| OAuth2Error::DecodeState(format!("Failed to decode UTF-8: {}", e)))?;
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .map_err(|e| OAuth2Error::Serde(e.to_string()))?;
    Ok(state_in_response)
}

/// Store OAuth2-related tokens in the cache store
///
/// This function:
/// 1. Generates a unique token ID
/// 2. Creates a StoredToken struct with the token data and TTL
/// 3. Stores the token in the cache using the provided token type and token ID
///
/// The token is stored with a TTL based on OAUTH2_CSRF_COOKIE_MAX_AGE
/// and can be retrieved later using the token_type and token_id
///
/// # Arguments
/// * `token_type` - Type identifier for the token (e.g., "access_token", "refresh_token")
/// * `token` - The actual token string to store
/// * `expires_at` - The expiration time of the token
/// * `user_agent` - Optional user agent string for tracking
///
/// # Returns
/// * `Ok(token_id)` - The generated token ID that can be used to retrieve the token
/// * `Err(OAuth2Error)` - If token generation or storage fails
pub(super) async fn store_token_in_cache(
    token_type: &str,
    token: &str,
    ttl: u64,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
) -> Result<String, OAuth2Error> {
    let token_id = gen_random_string(32)?;

    let token_data = StoredToken {
        token: token.to_string(),
        expires_at,
        user_agent,
        ttl,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        // .put(token_type, &token_id, token_data.into())
        .put_with_ttl(
            token_type,
            &token_id,
            token_data.into(),
            ttl.try_into().unwrap(),
        )
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(token_id)
}

pub(super) async fn generate_store_token(
    token_type: &str,
    ttl: u64,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
) -> Result<(String, String), OAuth2Error> {
    let token = gen_random_string(32)?;
    let token_id = store_token_in_cache(token_type, &token, ttl, expires_at, user_agent).await?;

    Ok((token, token_id))
}

pub(super) async fn get_token_from_store<T>(
    token_type: &str,
    token_id: &str,
) -> Result<T, OAuth2Error>
where
    T: TryFrom<CacheData, Error = OAuth2Error>,
{
    GENERIC_CACHE_STORE
        .lock()
        .await
        .get(token_type, token_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?
        .ok_or_else(|| {
            OAuth2Error::SecurityTokenNotFound(format!("{}-session not found", token_type))
        })?
        .try_into()
}

pub(super) async fn remove_token_from_store(
    token_type: &str,
    token_id: &str,
) -> Result<(), OAuth2Error> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(token_type, token_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(crate) async fn validate_origin(
    headers: &HeaderMap,
    auth_url: &str,
) -> Result<(), OAuth2Error> {
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
pub(super) fn get_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .build()
        .expect("Failed to create reqwest client")
}

/// Extract user ID from a stored session if it exists in the state parameters.
/// Returns None if:
/// - No misc_id in state parameters
/// - Session not found in cache
/// - Error getting user from session
pub(crate) async fn get_uid_from_stored_session_by_state_param(
    state_params: &StateParams,
) -> Result<Option<SessionUser>, OAuth2Error> {
    let Some(misc_id) = &state_params.misc_id else {
        tracing::debug!("No misc_id in state");
        return Ok(None);
    };

    tracing::debug!("misc_id: {:#?}", misc_id);

    let Ok(token) = get_token_from_store::<StoredToken>("misc_session", misc_id).await else {
        tracing::debug!("Failed to get session from cache");
        return Ok(None);
    };

    tracing::debug!("Token: {:#?}", token);

    // Clean up the misc session after use
    // remove_token_from_store("misc_session", misc_id).await?;

    match get_user_from_session(&token.token).await {
        Ok(user) => {
            tracing::debug!("Found user ID: {}", user.id);
            Ok(Some(user))
        }
        Err(e) => {
            tracing::debug!("Failed to get user from session: {}", e);
            Ok(None)
        }
    }
}

pub(crate) async fn delete_session_and_misc_token_from_store(
    state_params: &StateParams,
) -> Result<(), OAuth2Error> {
    if let Some(misc_id) = &state_params.misc_id {
        let Ok(token) = get_token_from_store::<StoredToken>("misc_session", misc_id).await else {
            tracing::debug!("Failed to get session from cache");
            return Ok(());
        };

        delete_session_from_store_by_session_id(&token.token)
            .await
            .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

        remove_token_from_store("misc_session", misc_id).await?;
    }

    Ok(())
}

pub(crate) async fn get_mode_from_stored_session(
    mode_id: &str,
) -> Result<Option<OAuth2Mode>, OAuth2Error> {
    let Ok(token) = get_token_from_store::<StoredToken>("mode", mode_id).await else {
        tracing::debug!("Failed to get mode from cache");
        return Ok(None);
    };

    // Convert the string to OAuth2Mode enum
    match OAuth2Mode::from_str(&token.token) {
        Ok(mode) => Ok(Some(mode)),
        Err(_) => {
            tracing::warn!("Invalid mode value in cache: {}", token.token);
            Ok(None)
        }
    }
}
