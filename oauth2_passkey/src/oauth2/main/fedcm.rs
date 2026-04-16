use chrono::{Duration, Utc};

use super::idtoken::{OidcIdInfo, verify_idtoken_with_algorithm};
use super::utils::{generate_store_token, verify_and_consume_nonce};

use crate::oauth2::OAuth2Error;
use crate::oauth2::provider::ProviderConfig;
use crate::oauth2::types::{FedCMNonceResponse, TokenType};

/// TTL for FedCM nonce tokens (seconds)
const FEDCM_NONCE_TTL: u64 = 120;

/// Prepare a FedCM nonce for use with `navigator.credentials.get()`.
///
/// Generates a random nonce, stores it in the cache, and returns
/// the nonce and its cache ID for the frontend.
pub async fn prepare_fedcm_nonce() -> Result<FedCMNonceResponse, OAuth2Error> {
    let expires_at = Utc::now() + Duration::seconds(FEDCM_NONCE_TTL as i64);

    // Generate and store nonce
    let (nonce_token, nonce_id) =
        generate_store_token(TokenType::Nonce, FEDCM_NONCE_TTL, expires_at, None).await?;

    Ok(FedCMNonceResponse {
        nonce: nonce_token,
        nonce_id,
    })
}

/// Validate a FedCM ID token and verify its nonce.
///
/// This performs:
/// 1. JWT signature verification using JWKS
/// 2. Audience, issuer, and expiration validation
/// 3. Nonce verification against the cached value (single-use: removed after verification)
pub(crate) async fn validate_fedcm_token(
    ctx: &ProviderConfig,
    token: &str,
    nonce_id: &str,
) -> Result<OidcIdInfo, OAuth2Error> {
    // 1. Verify JWT signature, audience, issuer, expiration
    let (idinfo, _algorithm) = verify_idtoken_with_algorithm(ctx, token.to_string())
        .await
        .map_err(|e| OAuth2Error::IdToken(e.to_string()))?;

    // 2. Verify and consume nonce (single-use)
    verify_and_consume_nonce(nonce_id, idinfo.nonce.as_deref()).await?;

    Ok(idinfo)
}
