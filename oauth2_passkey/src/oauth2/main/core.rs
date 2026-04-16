use headers::Cookie;
use http::header::{HeaderMap, SET_COOKIE};

use chrono::{Duration, Utc};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::oauth2::config::{OAUTH2_CSRF_COOKIE_MAX_AGE, OAUTH2_CSRF_COOKIE_NAME};
use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::provider::{ProviderConfig, ProviderKind, provider_for};
use crate::oauth2::types::{AuthResponse, OidcUserInfo, StateParams, StoredToken, TokenType};
use crate::session::get_session_id_from_headers;
use crate::utils::base64url_encode;

use super::idtoken::{OidcIdInfo, verify_idtoken_with_algorithm};
use super::oidc::{exchange_code_for_token, fetch_userinfo};
use super::utils::{decode_state, encode_state, generate_store_token, verify_and_consume_nonce};
use crate::storage::{
    CacheErrorConversion, CacheKey, CachePrefix, get_data, remove_data, store_cache_auto,
};

/// Prepares an OAuth2 authentication request URL and necessary headers.
///
/// Resolves the provider configuration from `provider` (URL path segment),
/// then builds the authorization URL and sets the CSRF cookie.
///
/// # Arguments
///
/// * `provider` - Provider identifier from the URL path (e.g. "google")
/// * `headers` - HTTP headers from the client request
/// * `mode` - Optional authentication mode (e.g. "login", "create_user")
///
/// # Returns
///
/// * `Ok((String, HeaderMap))` - The authorization URL and response headers
/// * `Err(OAuth2Error)` - If the provider is unknown or an error occurs
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::prepare_oauth2_auth_request;
/// use http::HeaderMap;
///
/// async fn start_oauth_flow(request_headers: HeaderMap) -> Result<(String, HeaderMap), Box<dyn std::error::Error>> {
///     let (auth_url, response_headers) = prepare_oauth2_auth_request("google", request_headers, Some("login")).await?;
///     Ok((auth_url, response_headers))
/// }
/// ```
pub async fn prepare_oauth2_auth_request(
    provider: &str,
    headers: HeaderMap,
    mode: Option<&str>,
) -> Result<(String, HeaderMap), OAuth2Error> {
    let kind = ProviderKind::from_path_segment(provider)
        .ok_or_else(|| OAuth2Error::Validation(format!("Unknown provider: {provider}")))?;
    let ctx = provider_for(kind)
        .ok_or_else(|| OAuth2Error::Validation(format!("Provider not enabled: {provider}")))?;
    prepare_oauth2_auth_request_inner(ctx, headers, mode).await
}

/// Internal function that builds the OAuth2 authorization request.
///
/// Separated from the public entry point so tests can inject a `ProviderConfig`
/// constructed directly (without touching `LazyLock` globals or env vars).
pub(crate) async fn prepare_oauth2_auth_request_inner(
    ctx: &ProviderConfig,
    headers: HeaderMap,
    mode: Option<&str>,
) -> Result<(String, HeaderMap), OAuth2Error> {
    let auth_base_url = ctx.auth_url().await?;
    let response_mode = ctx.response_mode.as_str();
    let provider_name = ctx.kind.as_str();

    let expires_at = Utc::now() + Duration::seconds((*OAUTH2_CSRF_COOKIE_MAX_AGE) as i64);
    let ttl = *OAUTH2_CSRF_COOKIE_MAX_AGE;
    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let (csrf_token, csrf_id) =
        generate_store_token(TokenType::Csrf, ttl, expires_at, Some(user_agent)).await?;
    let (nonce_token, nonce_id) =
        generate_store_token(TokenType::Nonce, ttl, expires_at, None).await?;
    let (pkce_token, pkce_id) =
        generate_store_token(TokenType::Pkce, ttl, expires_at, None).await?;

    let misc_id = if let Some(session_id) = get_session_id_from_headers(&headers)? {
        tracing::info!("Session ID found: {}", session_id);
        let stored_token = StoredToken {
            token: session_id.to_string(),
            expires_at,
            user_agent: None,
            ttl,
        };
        let cache_prefix = CachePrefix::misc_session();
        Some(
            store_cache_auto::<_, OAuth2Error>(cache_prefix, stored_token, ttl)
                .await?
                .as_str()
                .to_string(),
        )
    } else {
        tracing::debug!("No session ID found");
        None
    };

    let mode_id = if let Some(mode) = mode {
        let stored_token = StoredToken {
            token: mode.to_string(),
            expires_at,
            user_agent: None,
            ttl,
        };
        let cache_prefix = CachePrefix::mode();
        Some(
            store_cache_auto::<_, OAuth2Error>(cache_prefix, stored_token, ttl)
                .await?
                .as_str()
                .to_string(),
        )
    } else {
        None
    };

    tracing::debug!("PKCE ID: {:?}, PKCE verifier: {:?}", pkce_id, pkce_token);
    let pkce_challenge = base64url_encode(Sha256::digest(pkce_token.as_bytes()).to_vec())?;

    tracing::debug!("PKCE Challenge: {:#?}", pkce_challenge);
    let state_params = StateParams {
        csrf_id,
        nonce_id,
        pkce_id,
        misc_id,
        mode_id,
        provider: provider_name.to_string(),
    };

    let encoded_state = encode_state(state_params)?;

    let auth_url = format!(
        "{}?{}&client_id={}&redirect_uri={}&state={}&nonce={}\
        &code_challenge={}&code_challenge_method={}",
        auth_base_url,
        ctx.query_string.as_str(),
        ctx.client_id.as_str(),
        ctx.redirect_uri.as_str(),
        encoded_state,
        nonce_token,
        pkce_challenge,
        "S256"
    );

    tracing::debug!("Auth URL: {:#?}", auth_url);

    let mut response_headers = HeaderMap::new();

    // Set SameSite attribute based on response mode.
    // form_post requires SameSite=None because it's a cross-site POST.
    // query (redirect) can use SameSite=Lax for better security.
    let samesite = match response_mode.to_lowercase().as_str() {
        "form_post" => "None",
        "query" => "Lax",
        _ => "Lax",
    };

    let cookie = format!(
        "{}={}; SameSite={}; Secure; HttpOnly; Path=/; Max-Age={}",
        *OAUTH2_CSRF_COOKIE_NAME, csrf_token, samesite, *OAUTH2_CSRF_COOKIE_MAX_AGE as i64
    );

    response_headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| OAuth2Error::Cookie("Failed to parse cookie".to_string()))?,
    );

    tracing::debug!("Headers: {:#?}", response_headers);

    Ok((auth_url, response_headers))
}

pub(crate) async fn get_idinfo_userinfo(
    ctx: &ProviderConfig,
    auth_response: &AuthResponse,
) -> Result<(OidcIdInfo, OidcUserInfo), OAuth2Error> {
    let pkce_verifier = get_pkce_verifier(auth_response).await?;
    let (access_token, id_token) =
        exchange_code_for_token(ctx, auth_response.code.clone(), pkce_verifier).await?;

    let (idinfo, algorithm) = verify_idtoken_with_algorithm(ctx, id_token)
        .await
        .map_err(|e| OAuth2Error::IdToken(e.to_string()))?;

    verify_at_hash(&idinfo, &access_token, algorithm)?;

    verify_nonce(auth_response, idinfo.clone()).await?;

    let userinfo = fetch_userinfo(ctx, access_token).await?;

    if idinfo.sub != userinfo.sub {
        tracing::error!(
            "Id mismatch in OidcIdInfo and Userinfo: \nOidcIdInfo: {:#?}\nUserInfo: {:#?}",
            idinfo,
            userinfo
        );
        return Err(OAuth2Error::IdMismatch);
    }
    Ok((idinfo, userinfo))
}

async fn get_pkce_verifier(auth_response: &AuthResponse) -> Result<String, OAuth2Error> {
    let oauth2_state = crate::OAuth2State::new(auth_response.state.clone())?;
    let state_in_response = decode_state(&oauth2_state)?;

    let pkce_cache_key = CacheKey::new(state_in_response.pkce_id.clone())
        .map_err(OAuth2Error::convert_storage_error)?;
    let pkce_session: StoredToken =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::pkce(), pkce_cache_key.clone())
            .await?
            .ok_or_else(|| {
                OAuth2Error::SecurityTokenNotFound("pkce-session not found".to_string())
            })?;

    remove_data::<OAuth2Error>(CachePrefix::pkce(), pkce_cache_key).await?;

    Ok(pkce_session.token)
}

async fn verify_nonce(auth_response: &AuthResponse, idinfo: OidcIdInfo) -> Result<(), OAuth2Error> {
    let oauth2_state = crate::OAuth2State::new(auth_response.state.clone())?;
    let state_in_response = decode_state(&oauth2_state)?;

    verify_and_consume_nonce(&state_in_response.nonce_id, idinfo.nonce.as_deref()).await
}

/// CSRF checks for the OAuth2 callback.
///
/// The cookie name `OAUTH2_CSRF_COOKIE_NAME` is intentionally a single global
/// (not per-provider).  This implements the "latest OAuth2 flow wins" policy:
/// starting a new flow overwrites the cookie, causing any abandoned in-flight
/// flow's callback to fail here.  See the policy comment in `config.rs` and
/// the Decision Log entry "2026-04-16: Preserve the 'latest flow wins' CSRF
/// cookie policy" in issue `20260226-2020` for the full rationale.
pub(crate) async fn csrf_checks(
    cookies: Cookie,
    query: &AuthResponse,
    headers: HeaderMap,
) -> Result<(), OAuth2Error> {
    let csrf_token = cookies
        .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
        .ok_or_else(|| {
            OAuth2Error::SecurityTokenNotFound("No CSRF session cookie found".to_string())
        })?;

    let oauth2_state = crate::OAuth2State::new(query.state.clone())?;
    let state_in_response = decode_state(&oauth2_state)?;
    tracing::debug!("State in response: {:#?}", state_in_response);

    // Get the csrf_id from the state parameter
    let csrf_id = &state_in_response.csrf_id;

    let csrf_cache_key =
        CacheKey::new(csrf_id.clone()).map_err(OAuth2Error::convert_storage_error)?;
    let csrf_session: StoredToken =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::csrf(), csrf_cache_key.clone())
            .await?
            .ok_or_else(|| {
                OAuth2Error::SecurityTokenNotFound("csrf-session not found".to_string())
            })?;
    tracing::debug!("CSRF Session: {:#?}", csrf_session);

    remove_data::<OAuth2Error>(CachePrefix::csrf(), csrf_cache_key).await?;

    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Compare the token from the cookie with the token stored in the session
    if csrf_token != csrf_session.token {
        tracing::error!("CSRF Token in cookie: {:#?}", csrf_token);
        tracing::error!("Stored CSRF Token: {:#?}", csrf_session.token);
        return Err(OAuth2Error::CsrfTokenMismatch);
    }

    if Utc::now() > csrf_session.expires_at {
        tracing::error!("Now: {}", Utc::now());
        tracing::error!("CSRF Expires At: {:#?}", csrf_session.expires_at);
        return Err(OAuth2Error::CsrfTokenExpired);
    }

    if user_agent != csrf_session.user_agent.clone().unwrap_or_default() {
        tracing::error!("User Agent: {:#?}", user_agent);
        tracing::error!(
            "Stored User Agent: {:#?}",
            csrf_session.user_agent.unwrap_or_default()
        );
        return Err(OAuth2Error::UserAgentMismatch);
    }

    Ok(())
}

/// Calculate at_hash according to OpenID Connect specification
///
/// The at_hash is calculated by:
/// 1. Hashing the access token using the same algorithm as the ID token's JOSE header
/// 2. Taking the left-most half of the hash
/// 3. Base64url encoding the result
fn calculate_at_hash(access_token: &str, algorithm: Algorithm) -> Result<String, OAuth2Error> {
    fn half_hash<D: Digest>(data: &[u8]) -> Vec<u8> {
        let hash = D::digest(data);
        hash[..hash.len() / 2].to_vec() // Take left-most half
    }

    let hash_bytes = match algorithm {
        Algorithm::RS256 | Algorithm::HS256 | Algorithm::ES256 => {
            half_hash::<Sha256>(access_token.as_bytes())
        }
        Algorithm::RS384 | Algorithm::HS384 | Algorithm::ES384 => {
            half_hash::<Sha384>(access_token.as_bytes())
        }
        Algorithm::RS512 | Algorithm::HS512 => half_hash::<Sha512>(access_token.as_bytes()),
        _ => {
            return Err(OAuth2Error::UnsupportedAlgorithm(format!(
                "Unsupported algorithm for at_hash calculation: {algorithm:?}"
            )));
        }
    };

    Ok(base64url_encode(hash_bytes)?)
}

/// Verify at_hash according to OpenID Connect specification
///
/// This function verifies that the at_hash in the ID token matches the calculated
/// hash of the access token using the algorithm specified in the ID token's JOSE header.
///
/// # Arguments
///
/// * `idinfo` - The ID token information containing the at_hash claim
/// * `access_token` - The access token to verify against
/// * `algorithm` - The algorithm from the ID token's JOSE header
///
/// # Returns
///
/// * `Ok(())` - If verification succeeds or at_hash is not present
/// * `Err(OAuth2Error)` - If verification fails or calculation error occurs
fn verify_at_hash(
    idinfo: &OidcIdInfo,
    access_token: &str,
    algorithm: Algorithm,
) -> Result<(), OAuth2Error> {
    if idinfo.at_hash.is_none() {
        tracing::warn!("at_hash is None in ID Token: {:#?}", idinfo);
        return Ok(());
    }

    // Calculate at_hash according to OpenID Connect specification:
    // 1. Hash the access token using the same algorithm as the ID token's JOSE header
    // 2. Take the left-most half of the hash (first 16 bytes for SHA256)
    // 3. Base64url encode the result
    let calculated_at_hash = calculate_at_hash(access_token, algorithm)?;

    tracing::debug!(
        "ID Token at_hash: {:?}, Access Token Hash: {:?}",
        idinfo.at_hash,
        calculated_at_hash
    );

    if idinfo.at_hash.as_ref().unwrap() != &calculated_at_hash {
        tracing::error!(
            "at_hash mismatch: ID Token at_hash: {:?}, Access Token Hash: {:?}",
            idinfo.at_hash,
            calculated_at_hash
        );
        return Err(OAuth2Error::AtHashMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
