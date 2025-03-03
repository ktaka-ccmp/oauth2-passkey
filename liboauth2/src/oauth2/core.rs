use headers::Cookie;
use http::header::HeaderMap;

use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use url::Url;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use libstorage::GENERIC_CACHE_STORE;

use crate::common::{gen_random_string, header_set_cookie};
use crate::config::{
    OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_MAX_AGE, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_GOOGLE_CLIENT_ID,
    OAUTH2_GOOGLE_CLIENT_SECRET, OAUTH2_QUERY_STRING, OAUTH2_REDIRECT_URI, OAUTH2_TOKEN_URL,
    OAUTH2_USERINFO_URL,
};
use crate::errors::OAuth2Error;
use crate::types::{AuthResponse, GoogleUserInfo, OidcTokenResponse, StateParams, StoredToken};

use super::idtoken::{IdInfo as GoogleIdInfo, verify_idtoken};

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

    let pkce_session: StoredToken = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get("pkce", &state_in_response.pkce_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?
        .ok_or_else(|| OAuth2Error::SecurityTokenNotFound("PKCE Session not found".to_string()))?
        .try_into()?;

    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove("pkce", &state_in_response.pkce_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;
    let pkce_verifier = pkce_session.token.clone();
    tracing::debug!("PKCE Verifier: {:#?}", pkce_verifier);
    Ok(pkce_verifier)
}

async fn verify_nonce(
    auth_response: &AuthResponse,
    idinfo: GoogleIdInfo,
) -> Result<(), OAuth2Error> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .map_err(|e| OAuth2Error::Serde(e.to_string()))?;

    let nonce_session: StoredToken = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get("nonce", &state_in_response.nonce_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?
        .ok_or_else(|| OAuth2Error::SecurityTokenNotFound("Nonce Session not found".to_string()))?
        .try_into()?;

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

    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove("nonce", &state_in_response.nonce_id)
        .await
        .expect("Failed to remove nonce session");

    Ok(())
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

    let csrf_session: StoredToken = GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store()
        .get("csrf", csrf_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?
        .ok_or_else(|| OAuth2Error::SecurityTokenNotFound("CSRF Session not found".to_string()))?
        .try_into()?;

    tracing::debug!("CSRF Session: {:#?}", csrf_session);

    GENERIC_CACHE_STORE
        .lock()
        .await
        .get_store_mut()
        .remove("csrf", csrf_id)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
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

async fn fetch_user_data_from_google(access_token: String) -> Result<GoogleUserInfo, OAuth2Error> {
    let client = crate::client::get_client();
    let response = client
        .get(OAUTH2_USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| OAuth2Error::FetchUserInfo(e.to_string()))?;

    let response_body = response
        .text()
        .await
        .map_err(|e| OAuth2Error::FetchUserInfo(e.to_string()))?;

    tracing::debug!("Response Body: {:#?}", response_body);
    let user_data: GoogleUserInfo = serde_json::from_str(&response_body)
        .map_err(|e| OAuth2Error::Serde(format!("Failed to deserialize response body: {}", e)))?;

    tracing::debug!("User data: {:#?}", user_data);
    Ok(user_data)
}

async fn exchange_code_for_token(
    code: String,
    code_verifier: String,
) -> Result<(String, String), OAuth2Error> {
    let client = crate::client::get_client();
    let response = client
        .post(OAUTH2_TOKEN_URL.as_str())
        .form(&[
            ("code", code),
            ("client_id", OAUTH2_GOOGLE_CLIENT_ID.to_string()),
            ("client_secret", OAUTH2_GOOGLE_CLIENT_SECRET.to_string()),
            ("redirect_uri", OAUTH2_REDIRECT_URI.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;

    match response.status() {
        reqwest::StatusCode::OK => {
            tracing::debug!("Token Exchange Response: {:#?}", response);
        }
        status => {
            tracing::debug!("Token Exchange Response: {:#?}", response);
            return Err(OAuth2Error::TokenExchange(status.to_string()));
        }
    };

    let response_body = response
        .text()
        .await
        .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;
    let response_json: OidcTokenResponse = serde_json::from_str(&response_body)
        .map_err(|e| OAuth2Error::TokenExchange(e.to_string()))?;
    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.clone().unwrap();

    tracing::debug!("Response JSON: {:#?}", response_json);
    Ok((access_token, id_token))
}
