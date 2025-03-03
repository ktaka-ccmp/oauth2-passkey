use headers::Cookie;
use http::header::HeaderMap;

use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use crate::common::header_set_cookie;
use crate::config::{
    OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_MAX_AGE, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_GOOGLE_CLIENT_ID,
    OAUTH2_QUERY_STRING, OAUTH2_REDIRECT_URI,
};
use crate::errors::OAuth2Error;
use crate::types::{AuthResponse, GoogleUserInfo, StateParams, StoredToken};

use super::google::{exchange_code_for_token, fetch_user_data_from_google};
use super::idtoken::{IdInfo as GoogleIdInfo, verify_idtoken};
use super::utils::{
    encode_state, generate_store_token, get_token_from_store, remove_token_from_store,
};

pub async fn prepare_oauth2_auth_request(
    headers: HeaderMap,
) -> Result<(String, HeaderMap), OAuth2Error> {
    let expires_at = Utc::now() + Duration::seconds((*OAUTH2_CSRF_COOKIE_MAX_AGE) as i64);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let (csrf_token, csrf_id) = generate_store_token("csrf", expires_at, Some(user_agent)).await?;
    let (nonce_token, nonce_id) = generate_store_token("nonce", expires_at, None).await?;
    let (pkce_token, pkce_id) = generate_store_token("pkce", expires_at, None).await?;

    tracing::debug!("PKCE ID: {:?}, PKCE verifier: {:?}", pkce_id, pkce_token);
    let pkce_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_token.as_bytes()));

    tracing::debug!("PKCE Challenge: {:#?}", pkce_challenge);
    let encoded_state = encode_state(csrf_token, nonce_id, pkce_id);

    let auth_url = format!(
        "{}?{}&client_id={}&redirect_uri={}&state={}&nonce={}\
        &code_challenge={}&code_challenge_method={}",
        OAUTH2_AUTH_URL.as_str(),
        OAUTH2_QUERY_STRING.as_str(),
        OAUTH2_GOOGLE_CLIENT_ID.as_str(),
        OAUTH2_REDIRECT_URI.as_str(),
        encoded_state,
        nonce_token,
        pkce_challenge,
        "S256"
    );

    tracing::debug!("Auth URL: {:#?}", auth_url);

    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        csrf_id,
        expires_at,
        *OAUTH2_CSRF_COOKIE_MAX_AGE as i64,
    )
    .map_err(|e| OAuth2Error::Cookie(e.to_string()))?;

    tracing::debug!("Headers: {:#?}", headers);

    Ok((auth_url, headers))
}

pub async fn get_idinfo_userinfo(
    auth_response: &AuthResponse,
) -> Result<(GoogleIdInfo, GoogleUserInfo), OAuth2Error> {
    let pkce_verifier = get_pkce_verifier(auth_response).await?;
    let (access_token, id_token) =
        exchange_code_for_token(auth_response.code.clone(), pkce_verifier).await?;

    let idinfo = verify_idtoken(id_token, OAUTH2_GOOGLE_CLIENT_ID.to_string())
        .await
        .map_err(|e| OAuth2Error::IdToken(e.to_string()))?;

    verify_nonce(auth_response, idinfo.clone()).await?;

    let userinfo = fetch_user_data_from_google(access_token).await?;

    if idinfo.sub != userinfo.id {
        tracing::error!(
            "Id mismatch in IdInfo and Userinfo: \nIdInfo: {:#?}\nUserInfo: {:#?}",
            idinfo,
            userinfo
        );
        return Err(OAuth2Error::IdMismatch);
    }
    Ok((idinfo, userinfo))
}

async fn get_pkce_verifier(auth_response: &AuthResponse) -> Result<String, OAuth2Error> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .map_err(|e| OAuth2Error::Serde(e.to_string()))?;

    let pkce_session: StoredToken =
        get_token_from_store("pkce", &state_in_response.pkce_id).await?;

    remove_token_from_store("pkce", &state_in_response.pkce_id).await?;

    Ok(pkce_session.token)
}

async fn verify_nonce(
    auth_response: &AuthResponse,
    idinfo: GoogleIdInfo,
) -> Result<(), OAuth2Error> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .map_err(|e| OAuth2Error::Serde(e.to_string()))?;

    let nonce_session: StoredToken =
        get_token_from_store("nonce", &state_in_response.nonce_id).await?;

    tracing::debug!("Nonce Data: {:#?}", nonce_session);

    if Utc::now() > nonce_session.expires_at {
        tracing::error!("Nonce Expired: {:#?}", nonce_session.expires_at);
        tracing::error!("Now: {:#?}", Utc::now());
        return Err(OAuth2Error::NonceExpired);
    }
    if idinfo.nonce != Some(nonce_session.token.clone()) {
        tracing::error!("Nonce in ID Token: {:#?}", idinfo.nonce);
        tracing::error!("Stored Nonce: {:#?}", nonce_session.token);
        return Err(OAuth2Error::NonceMismatch);
    }

    remove_token_from_store("nonce", &state_in_response.nonce_id).await?;

    Ok(())
}

pub async fn csrf_checks(
    cookies: Cookie,
    query: &AuthResponse,
    headers: HeaderMap,
) -> Result<(), OAuth2Error> {
    let csrf_id = cookies
        .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
        .ok_or_else(|| {
            OAuth2Error::SecurityTokenNotFound("No CSRF session cookie found".to_string())
        })?;

    let csrf_session: StoredToken = get_token_from_store("csrf", csrf_id).await?;
    tracing::debug!("CSRF Session: {:#?}", csrf_session);

    remove_token_from_store("csrf", csrf_id).await?;

    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let decoded_state_string = String::from_utf8(
        URL_SAFE
            .decode(&query.state)
            .map_err(|e| OAuth2Error::DecodeState(e.to_string()))?,
    )
    .map_err(|e| OAuth2Error::DecodeState(e.to_string()))?;

    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .map_err(|e| OAuth2Error::Serde(e.to_string()))?;

    if state_in_response.csrf_token != csrf_session.token {
        tracing::error!(
            "CSRF Token in state param: {:#?}",
            state_in_response.csrf_token
        );
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
