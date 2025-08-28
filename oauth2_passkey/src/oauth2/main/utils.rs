use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use http::header::HeaderMap;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

use crate::oauth2::{OAuth2Error, OAuth2Mode, StateParams, StoredToken, TokenType};

use crate::session::{
    SessionId, User as SessionUser, delete_session_from_store_by_session_id, get_user_from_session,
};
use crate::storage::{
    CacheErrorConversion, CacheKey, CachePrefix, get_data, remove_data, store_cache_auto,
};

use crate::utils::gen_random_string_with_entropy_validation;

pub(super) fn encode_state(
    state_params: StateParams,
) -> Result<crate::oauth2::types::OAuth2State, OAuth2Error> {
    let state_json =
        serde_json::to_string(&state_params).map_err(|e| OAuth2Error::Serde(e.to_string()))?;
    let encoded = URL_SAFE_NO_PAD.encode(state_json);
    crate::oauth2::types::OAuth2State::new(encoded)
}

pub(crate) fn decode_state(
    state: &crate::oauth2::types::OAuth2State,
) -> Result<StateParams, OAuth2Error> {
    // Since OAuth2State is validated during construction, we know these operations will succeed
    // This is safe because validation in OAuth2State::new() already verified:
    // 1. Valid base64url encoding
    // 2. Valid UTF-8 content
    // 3. Valid JSON structure
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(state.as_str())
        .expect("OAuth2State should contain valid base64url");
    let decoded_state_string =
        String::from_utf8(decoded_bytes).expect("OAuth2State should contain valid UTF-8");
    let state_in_response: StateParams =
        serde_json::from_str(&decoded_state_string).expect("OAuth2State should contain valid JSON");
    Ok(state_in_response)
}

pub(super) async fn generate_store_token(
    token_type: TokenType,
    ttl: u64,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
) -> Result<(String, String), OAuth2Error> {
    let token = gen_random_string_with_entropy_validation(32)?;

    let stored_token = StoredToken {
        token: token.clone(),
        expires_at,
        user_agent,
        ttl,
    };

    let cache_prefix =
        CachePrefix::new(token_type.to_string()).map_err(OAuth2Error::convert_storage_error)?;

    let token_id = store_cache_auto::<_, OAuth2Error>(cache_prefix, stored_token, ttl).await?;

    Ok((token, token_id))
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
        .map_or("".to_string(), |p| format!(":{p}"));
    let expected_origin = format!("{scheme}://{host}{port}");

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
                "Expected Origin: {expected_origin:#?}, Actual Origin: {origin:#?}"
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

    let misc_cache_key = match CacheKey::new(misc_id.clone()) {
        Ok(key) => key,
        Err(e) => {
            tracing::debug!("Failed to create cache key: {}", e);
            return Ok(None);
        }
    };
    let Ok(Some(token)) =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::misc_session(), misc_cache_key).await
    else {
        tracing::debug!("Failed to get session from cache");
        return Ok(None);
    };

    tracing::debug!("Token: {:#?}", token);

    // Clean up the misc session after use
    // remove_token_from_store("misc_session", misc_id).await?;

    let session_cookie = crate::SessionCookie::new(token.token.clone())
        .map_err(|e| OAuth2Error::Storage(format!("Invalid session cookie: {e}")))?;
    match get_user_from_session(&session_cookie).await {
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
        let misc_cache_key = match CacheKey::new(misc_id.clone()) {
            Ok(key) => key,
            Err(e) => {
                tracing::debug!("Failed to create cache key: {}", e);
                return Ok(());
            }
        };
        let Ok(Some(token)) = get_data::<StoredToken, OAuth2Error>(
            CachePrefix::misc_session(),
            misc_cache_key.clone(),
        )
        .await
        else {
            tracing::debug!("Failed to get session from cache");
            return Ok(());
        };

        delete_session_from_store_by_session_id(SessionId::new(token.token))
            .await
            .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

        remove_data::<OAuth2Error>(CachePrefix::misc_session(), misc_cache_key).await?;
    }

    Ok(())
}

pub(crate) async fn get_mode_from_stored_session(
    mode_id: &str,
) -> Result<Option<OAuth2Mode>, OAuth2Error> {
    let mode_cache_key = match CacheKey::new(mode_id.to_string()) {
        Ok(key) => key,
        Err(e) => {
            tracing::debug!("Failed to create cache key: {}", e);
            return Ok(None);
        }
    };
    let Ok(Some(token)) =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::mode(), mode_cache_key).await
    else {
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

#[cfg(test)]
mod tests;
