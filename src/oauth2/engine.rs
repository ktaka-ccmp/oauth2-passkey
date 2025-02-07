use anyhow::{Context, Result};
use headers::Cookie;
use http::header::HeaderMap;

use serde::{Deserialize, Serialize};

// use http::HeaderValue;
// use tower_http::cors::CorsLayer;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use url::Url;

use chrono::{DateTime, Utc};

use crate::oauth2::idtoken::{verify_idtoken, IdInfo};
use crate::common::{AppError, gen_random_string};
use crate::types::{AppState, StateParams, StoredToken, User, OAuth2Params};
use crate::oauth2::{CSRF_COOKIE_MAX_AGE, CSRF_COOKIE_NAME, OAUTH2_USERINFO_URL};

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
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
    state: &AppState,
) -> Result<(String, String), AppError> {
    let token = gen_random_string(32)?;
    let token_id = gen_random_string(32)?;

    let token_data = StoredToken {
        token: token.clone(),
        expires_at,
        user_agent,
        ttl: CSRF_COOKIE_MAX_AGE,
    };

    let mut token_store = state.token_store.lock().await;
    token_store.put(&token_id, token_data.clone()).await?;

    Ok((token, token_id))
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    code: String,
    pub state: String,
    _id_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OidcTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
    id_token: Option<String>,
}

pub async fn get_user_oidc_oauth2(
    auth_response: &AuthResponse,
    state: &AppState,
) -> Result<User, AppError> {
    let pkce_verifier = get_pkce_verifier(auth_response, state).await?;
    let (access_token, id_token) = exchange_code_for_token(
        state.oauth2_params.clone(),
        auth_response.code.clone(),
        pkce_verifier,
    )
    .await?;
    let user_data = user_from_verified_idtoken(id_token, state, auth_response).await?;
    let user_data_userinfo = fetch_user_data_from_google(access_token).await?;
    #[cfg(debug_assertions)]
    println!("User Data from Userinfo: {:#?}", user_data_userinfo);
    if user_data.id != user_data_userinfo.id {
        return Err(anyhow::anyhow!("ID mismatch").into());
    }
    Ok(user_data)
}

async fn get_pkce_verifier(
    auth_response: &AuthResponse,
    state: &AppState,
) -> Result<String, AppError> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)?;

    let token_store = state.token_store.lock().await;

    let pkce_session = token_store
        .get(&state_in_response.pkce_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("PKCE Session not found"))?;

    let pkce_verifier = pkce_session.token.clone();
    println!("PKCE Verifier: {:#?}", pkce_verifier);
    Ok(pkce_verifier)
}

async fn user_from_verified_idtoken(
    id_token: String,
    state: &AppState,
    auth_response: &AuthResponse,
) -> Result<User, AppError> {
    let idinfo = verify_idtoken(id_token, state.oauth2_params.client_id.clone()).await?;
    verify_nonce(auth_response, idinfo.clone(), state).await?;
    let user_data_idtoken = User {
        family_name: idinfo.family_name,
        name: idinfo.name,
        picture: idinfo.picture.unwrap_or_default(),
        email: idinfo.email,
        given_name: idinfo.given_name,
        id: idinfo.sub,
        hd: idinfo.hd,
        verified_email: idinfo.email_verified,
    };
    Ok(user_data_idtoken)
}

async fn verify_nonce(
    auth_response: &AuthResponse,
    idinfo: IdInfo,
    state: &AppState,
) -> Result<(), AppError> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)?;

    let mut token_store = state.token_store.lock().await;

    let nonce_session = token_store
        .get(&state_in_response.nonce_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Nonce Session not found"))?;

    println!("Nonce Data: {:#?}", nonce_session);

    if Utc::now() > nonce_session.expires_at {
        println!("Nonce Expired: {:#?}", nonce_session.expires_at);
        println!("Now: {:#?}", Utc::now());
        return Err(anyhow::anyhow!("Nonce expired").into());
    }
    if idinfo.nonce != Some(nonce_session.token.clone()) {
        println!("Nonce in ID Token: {:#?}", idinfo.nonce);
        println!("Stored Nonce: {:#?}", nonce_session.token);
        return Err(anyhow::anyhow!("Nonce mismatch").into());
    }

    token_store
        .remove(&state_in_response.nonce_id)
        .await
        .expect("Failed to remove nonce session");

    Ok(())
}

pub async fn validate_origin(headers: &HeaderMap, auth_url: &str) -> Result<(), AppError> {
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
            println!("Expected Origin: {:#?}", expected_origin);
            println!("Actual Origin: {:#?}", origin);
            Err(anyhow::anyhow!("Invalid origin").into())
        }
    }
}

pub async fn csrf_checks(
    cookies: Cookie,
    state: &AppState,
    query: &AuthResponse,
    headers: HeaderMap,
) -> Result<(), AppError> {
    let token_store = state.token_store.lock().await;

    let csrf_id = cookies
        .get(CSRF_COOKIE_NAME)
        .ok_or_else(|| anyhow::anyhow!("No CSRF session cookie found"))?;
    let csrf_session = token_store
        .get(csrf_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("CSRF Session not found in Session Store"))?;

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let decoded_state_string = String::from_utf8(
        URL_SAFE
            .decode(&query.state)
            .map_err(|e| anyhow::anyhow!("Failed to decode state: {e}"))?,
    )
    .context("Failed to convert decoded state to string")?;

    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .context("Failed to deserialize state from response")?;

    if state_in_response.csrf_token != csrf_session.token {
        println!(
            "CSRF Token in state param: {:#?}",
            state_in_response.csrf_token
        );
        println!("Stored CSRF Token: {:#?}", csrf_session.token);
        return Err(anyhow::anyhow!("CSRF token mismatch").into());
    }

    if Utc::now() > csrf_session.expires_at {
        println!("Now: {}", Utc::now());
        println!("CSRF Expires At: {:#?}", csrf_session.expires_at);
        return Err(anyhow::anyhow!("CSRF token expired").into());
    }

    if user_agent != csrf_session.user_agent.clone().unwrap_or_default() {
        println!("User Agent: {:#?}", user_agent);
        println!(
            "Stored User Agent: {:#?}",
            csrf_session.user_agent.unwrap_or_default()
        );
        return Err(anyhow::anyhow!("User agent mismatch").into());
    }

    Ok(())
}

async fn fetch_user_data_from_google(access_token: String) -> Result<User, AppError> {
    let response = reqwest::Client::new()
        .get(OAUTH2_USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .context("failed in sending request to target Url")?;
    let response_body = response
        .text()
        .await
        .context("failed to get response body")?;
    let user_data: User =
        serde_json::from_str(&response_body).context("failed to deserialize response body")?;
    println!("User data: {:#?}", user_data);
    Ok(user_data)
}

async fn exchange_code_for_token(
    params: OAuth2Params,
    code: String,
    code_verifier: String,
) -> Result<(String, String), AppError> {
    let response = reqwest::Client::new()
        .post(params.token_url)
        .form(&[
            ("code", code),
            ("client_id", params.client_id.clone()),
            ("client_secret", params.client_secret.clone()),
            ("redirect_uri", params.redirect_uri.clone()),
            ("grant_type", "authorization_code".to_string()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .context("failed in sending request request to authorization server")?;

    match response.status() {
        reqwest::StatusCode::OK => {
            println!("Debug Token Exchange Response: {:#?}", response);
        }
        status => {
            println!("Token Exchange Response: {:#?}", response);
            return Err(anyhow::anyhow!("Unexpected status code: {:#?}", status).into());
        }
    };

    let response_body = response
        .text()
        .await
        .context("failed to get response body")?;
    let response_json: OidcTokenResponse =
        serde_json::from_str(&response_body).context("failed to deserialize response body")?;
    let access_token = response_json.access_token.clone();
    let id_token = response_json.id_token.clone().unwrap();
    println!("Response JSON: {:#?}", response_json);
    Ok((access_token, id_token))
}

