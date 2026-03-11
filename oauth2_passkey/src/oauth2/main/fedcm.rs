use chrono::{Duration, Utc};

use super::idtoken::{IdInfo, verify_idtoken_with_algorithm};
use super::utils::generate_store_token;

use crate::oauth2::config::get_google_client_id;
use crate::oauth2::types::{FedCMNonceResponse, StoredToken, TokenType};
use crate::oauth2::{OAuth2Error, OAuth2Mode};
use crate::storage::{CacheErrorConversion, CacheKey, CachePrefix, get_data, remove_data};

/// TTL for FedCM nonce tokens (seconds)
const FEDCM_NONCE_TTL: u64 = 120;

/// Prepare a FedCM nonce for use with `navigator.credentials.get()`.
///
/// Generates a random nonce, stores it in the cache, and optionally stores
/// the OAuth2 mode. Returns the nonce and cache IDs for the frontend.
pub async fn prepare_fedcm_nonce(mode: Option<&str>) -> Result<FedCMNonceResponse, OAuth2Error> {
    let expires_at = Utc::now() + Duration::seconds(FEDCM_NONCE_TTL as i64);

    // Generate and store nonce
    let (nonce_token, nonce_id) =
        generate_store_token(TokenType::Nonce, FEDCM_NONCE_TTL, expires_at, None).await?;

    // Store mode if provided
    let mode_id = match mode {
        Some(mode_str) => {
            // Validate mode string
            let _: OAuth2Mode = mode_str
                .parse()
                .map_err(|_| OAuth2Error::InvalidMode(mode_str.to_string()))?;

            let stored_token = StoredToken {
                token: mode_str.to_string(),
                expires_at,
                user_agent: None,
                ttl: FEDCM_NONCE_TTL,
            };
            let cache_prefix = CachePrefix::mode();
            let key = crate::storage::store_cache_auto::<_, OAuth2Error>(
                cache_prefix,
                stored_token,
                FEDCM_NONCE_TTL,
            )
            .await?;
            Some(key.as_str().to_string())
        }
        None => None,
    };

    Ok(FedCMNonceResponse {
        nonce: nonce_token,
        nonce_id,
        mode_id,
    })
}

/// Validate a FedCM ID token and verify its nonce.
///
/// This performs:
/// 1. JWT signature verification using JWKS
/// 2. Audience, issuer, and expiration validation
/// 3. Nonce verification against the cached value (single-use: removed after verification)
pub(crate) async fn validate_fedcm_token(
    token: &str,
    nonce_id: &str,
) -> Result<IdInfo, OAuth2Error> {
    // 1. Verify JWT signature, audience, issuer, expiration
    let (idinfo, _algorithm) =
        verify_idtoken_with_algorithm(token.to_string(), get_google_client_id().to_string())
            .await
            .map_err(|e| OAuth2Error::IdToken(e.to_string()))?;

    // 2. Retrieve stored nonce from cache
    let nonce_cache_key =
        CacheKey::new(nonce_id.to_string()).map_err(OAuth2Error::convert_storage_error)?;
    let nonce_session: StoredToken =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::nonce(), nonce_cache_key.clone())
            .await?
            .ok_or_else(|| {
                OAuth2Error::SecurityTokenNotFound("FedCM nonce not found in cache".to_string())
            })?;

    // 3. Check nonce expiration
    if Utc::now() > nonce_session.expires_at {
        tracing::error!("FedCM nonce expired: {:?}", nonce_session.expires_at);
        return Err(OAuth2Error::NonceExpired);
    }

    // 4. Verify nonce matches ID token claim
    if idinfo.nonce != Some(nonce_session.token.clone()) {
        tracing::error!(
            "FedCM nonce mismatch: id_token={:?}, stored={:?}",
            idinfo.nonce,
            nonce_session.token
        );
        return Err(OAuth2Error::NonceMismatch);
    }

    // 5. Remove nonce from cache (single-use)
    remove_data::<OAuth2Error>(CachePrefix::nonce(), nonce_cache_key).await?;

    Ok(idinfo)
}

/// Clean up cached FedCM tokens (nonce, mode) after callback processing.
pub(crate) async fn cleanup_fedcm_tokens(mode_id: &Option<String>) -> Result<(), OAuth2Error> {
    // Clean up mode token if present
    if let Some(mode_id) = mode_id
        && let Ok(cache_key) = CacheKey::new(mode_id.clone())
    {
        let _ = remove_data::<OAuth2Error>(CachePrefix::mode(), cache_key).await;
    }

    Ok(())
}
