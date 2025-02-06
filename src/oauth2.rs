use anyhow::{Context, Result};
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect, Response},
    RequestPartsExt,
};
use axum_extra::{headers, TypedHeader};
use http::{request::Parts, StatusCode};

use serde::{Deserialize, Serialize};

// use http::HeaderValue;
// use tower_http::cors::CorsLayer;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use url::Url;

use chrono::{DateTime, Duration, Utc};
use rand::{rng, Rng};

use std::{convert::Infallible, env};

use crate::idtoken::{verify_idtoken, IdInfo};

static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
static OAUTH2_USERINFO_URL: &str = "https://www.googleapis.com/userinfo/v2/me";

static OAUTH2_QUERY_STRING: &str = "response_type=code\
&scope=openid+email+profile\
&response_mode=form_post\
&access_type=online\
&prompt=consent";
// &response_mode=form_post\
// &response_mode=query\

// Supported parameters:
// response_type: code
// scope: openid+email+profile
// response_mode: form_post, query
// access_type: online, offline(for refresh token)
// prompt: none, consent, select_account

// "__Host-" prefix are added to make cookies "host-only".
static SESSION_COOKIE_NAME: &str = "__Host-SessionId";
static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
static SESSION_COOKIE_MAX_AGE: i64 = 600; // 10 minutes
static CSRF_COOKIE_MAX_AGE: i64 = 60; // 60 seconds

pub async fn app_state_init() -> AppState {
    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();

    let oauth2_params = OAuth2Params {
        client_id: env::var("CLIENT_ID").expect("Missing CLIENT_ID!"),
        client_secret: env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!"),
        redirect_uri: format!(
            "{}/auth/authorized",
            env::var("ORIGIN").expect("Missing ORIGIN!")
        ),
        auth_url: OAUTH2_AUTH_URL.to_string(),
        token_url: OAUTH2_TOKEN_URL.to_string(),
        query_string: OAUTH2_QUERY_STRING.to_string(),
    };

    let session_params = SessionParams {
        session_cookie_name: SESSION_COOKIE_NAME.to_string(),
        csrf_cookie_name: CSRF_COOKIE_NAME.to_string(),
        session_cookie_max_age: SESSION_COOKIE_MAX_AGE,
        csrf_cookie_max_age: CSRF_COOKIE_MAX_AGE,
    };

    AppState {
        store,
        oauth2_params,
        session_params,
    }
}

#[derive(Clone, Debug)]
pub struct SessionParams {
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub session_cookie_max_age: i64,
    pub csrf_cookie_max_age: i64,
}

#[derive(Clone, Debug)]
pub struct OAuth2Params {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub auth_url: String,
    token_url: String,
    pub query_string: String,
}

#[derive(Clone)]
pub struct AppState {
    pub store: MemoryStore,
    pub oauth2_params: OAuth2Params,
    pub session_params: SessionParams,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for OAuth2Params {
    fn from_ref(state: &AppState) -> Self {
        state.oauth2_params.clone()
    }
}

impl FromRef<AppState> for SessionParams {
    fn from_ref(state: &AppState) -> Self {
        state.session_params.clone()
    }
}

// The user data we'll get back from Google
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    family_name: String,
    pub name: String,
    picture: String,
    email: String,
    given_name: String,
    id: String,
    hd: Option<String>,
    verified_email: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct StateParams {
    csrf_token: String,
    nonce_id: String,
    pkce_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenData {
    token: String,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
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
    session_key: &str,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
    store: &MemoryStore,
) -> Result<(String, String), AppError> {
    let token: String = rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let token_data = TokenData {
        token: token.clone(),
        expires_at,
        user_agent,
    };

    let mut session = Session::new();
    session.insert(session_key, token_data)?;
    session.set_expiry(expires_at);

    let session_id = store
        .store_session(session)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to store session"))?;

    Ok((token, session_id))
}

pub async fn delete_session_from_store(
    cookies: headers::Cookie,
    cookie_name: String,
    store: &MemoryStore,
) -> Result<(), AppError> {
    if let Some(cookie) = cookies.get(&cookie_name) {
        if let Some(session) = store
            .load_session(cookie.to_string())
            .await
            .context("failed to load session")?
        {
            store
                .destroy_session(session)
                .await
                .context("failed to destroy session")?;
        }
    };
    Ok(())
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

pub async fn authorized(
    auth_response: &AuthResponse,
    state: AppState,
) -> Result<impl IntoResponse, AppError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;

    let pkce_verifier = get_pkce_verifier(auth_response, &state).await?;

    let (access_token, id_token) = exchange_code_for_token(
        state.oauth2_params.clone(),
        auth_response.code.clone(),
        pkce_verifier,
    )
    .await?;

    // println!("Access Token: {:#?}", access_token);
    // println!("ID Token: {:#?}", id_token);

    let user_data = user_from_verified_idtoken(id_token, &state, auth_response).await?;

    // Optional check for user data from userinfo endpoint
    let user_data_userinfo = fetch_user_data_from_google(access_token).await?;

    #[cfg(debug_assertions)]
    println!("User Data from Userinfo: {:#?}", user_data_userinfo);

    if user_data.id != user_data_userinfo.id {
        return Err(anyhow::anyhow!("ID mismatch").into());
    }

    let max_age = SESSION_COOKIE_MAX_AGE;
    let expires_at = Utc::now() + Duration::seconds(max_age);
    let session_id = create_and_store_session(user_data, &state.store, expires_at).await?;
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        session_id,
        expires_at,
        max_age,
    )?;
    println!("Headers: {:#?}", headers);

    Ok((headers, Redirect::to("/popup_close")))
}

async fn get_pkce_verifier(
    auth_response: &AuthResponse,
    state: &AppState,
) -> Result<String, AppError> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)?;
    let session = state
        .store
        .load_session(state_in_response.pkce_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("PKCE Session not found"))?;
    let pkce_session: TokenData = session
        .get("pkce_session")
        .ok_or_else(|| anyhow::anyhow!("No pkce data in session"))?;
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
    verify_nonce(auth_response, idinfo.clone(), &state.store).await?;
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
    store: &MemoryStore,
) -> Result<(), AppError> {
    let decoded_state_string =
        String::from_utf8(URL_SAFE.decode(&auth_response.state).unwrap()).unwrap();
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)?;

    let session = store
        .load_session(state_in_response.nonce_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Nonce Session not found"))?;
    let nonce_session: TokenData = session
        .get("nonce_session")
        .ok_or_else(|| anyhow::anyhow!("No nonce data in session"))?;

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

    store
        .destroy_session(session)
        .await
        .context("failed to destroy nonce session")?;

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
    cookies: headers::Cookie,
    store: &MemoryStore,
    query: &AuthResponse,
    headers: HeaderMap,
) -> Result<(), AppError> {
    let csrf_id = cookies
        .get(CSRF_COOKIE_NAME)
        .ok_or_else(|| anyhow::anyhow!("No CSRF session cookie found"))?;
    let session = store
        .load_session(csrf_id.to_string())
        .await?
        .ok_or_else(|| anyhow::anyhow!("CSRF Session not found in Session Store"))?;
    let csrf_session: TokenData = session
        .get("csrf_session")
        .ok_or_else(|| anyhow::anyhow!("No CSRF data in session"))?;

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

pub fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, AppError> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );
    Ok(headers)
}

async fn create_and_store_session(
    user_data: User,
    store: &MemoryStore,
    expires_at: DateTime<Utc>,
) -> Result<String, AppError> {
    let mut session = Session::new();
    session
        .insert("user", &user_data)
        .context("failed in inserting serialized value into session")?;
    session.set_expiry(expires_at);
    println!("Session: {:#?}", session);
    let session_id = store
        .store_session(session)
        .await
        .context("failed to store session")?
        .context("unexpected error retrieving cookie value")?;
    Ok(session_id)
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

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        println!("AuthRedirect called.");
        Redirect::temporary("/").into_response()
    }
}

impl<S> FromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|_| AuthRedirect)?;

        // Get session from cookie
        let session_cookie = cookies.get(SESSION_COOKIE_NAME).ok_or(AuthRedirect)?;
        let session = store
            .load_session(session_cookie.to_string())
            .await
            .map_err(|_| AuthRedirect)?;

        // Get user data from session
        let session = session.ok_or(AuthRedirect)?;
        let user = session.get::<User>("user").ok_or(AuthRedirect)?;
        Ok(user)
    }
}

impl<S> OptionalFromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <User as FromRequestParts<S>>::from_request_parts(parts, state).await {
            Ok(res) => Ok(Some(res)),
            Err(AuthRedirect) => Ok(None),
        }
    }
}

// Use anyhow, define error and enable '?'
// For a simplified example of using anyhow in axum check /examples/anyhow-error-response
#[derive(Debug)]
pub struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);

        let message = self.0.to_string();
        (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
