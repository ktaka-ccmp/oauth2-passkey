//! Shared OIDC mock implementation.
//!
//! Used by:
//! - the `mock-oidc` standalone binary (Playwright E2E in `tests-e2e/`)
//! - the in-process test fixture in
//!   `oauth2_passkey_axum/tests/common/axum_mock_server.rs`
//!
//! The handlers below implement enough of the OpenID Connect 1.0 + OAuth2
//! authorization-code flow to exercise `oauth2-passkey-axum` end-to-end:
//! discovery, `/oauth2/auth` (form_post and query response modes), `/oauth2/token`
//! (with PKCE), `/oauth2/userinfo`, JWKS.

use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub redirect_uri: String,
    /// OAuth2 state - echoed back to the client; not validated server-side.
    #[allow(dead_code)]
    pub state: String,
    pub scope: Option<String>,
    pub response_type: String,
    pub client_id: String,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct TestUser {
    pub email: String,
    pub sub: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
}

impl TestUser {
    pub fn default_first_user() -> Self {
        Self {
            email: "first-user@example.com".to_string(),
            sub: "google_first-user-test-google-id".to_string(),
            name: "First User".to_string(),
            given_name: "First".to_string(),
            family_name: "User".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub issuer: String,
    pub client_id: String,
    pub user: Arc<Mutex<TestUser>>,
    pub authorization_codes: Arc<Mutex<HashMap<String, AuthorizationRequest>>>,
}

impl AppState {
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>, user: TestUser) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            user: Arc::new(Mutex::new(user)),
            authorization_codes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Drop authorization codes older than 10 minutes.
    pub fn cleanup_expired_codes(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut codes = self.authorization_codes.lock().unwrap();
        codes.retain(|_, r| now - r.created_at <= 600);
    }
}

/// Build the OIDC router (discovery, /authorize, /token, /userinfo, JWKS).
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth2/auth", get(oauth2_auth))
        .route("/oauth2/token", post(oauth2_token))
        .route("/oauth2/userinfo", get(oauth2_userinfo))
        .route("/oauth2/v3/certs", get(oauth2_jwks))
        .with_state(state)
}

/// Build helper routes used by external test runners (Playwright):
/// - `GET /test/healthz` → readiness probe
/// - `POST /test/config` → override the active `TestUser` (JSON body)
pub fn test_routes(state: AppState) -> Router {
    Router::new()
        .route("/test/healthz", get(healthz))
        .route("/test/config", post(test_config))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn oidc_discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/oauth2/auth", state.issuer),
        "token_endpoint": format!("{}/oauth2/token", state.issuer),
        "userinfo_endpoint": format!("{}/oauth2/userinfo", state.issuer),
        "jwks_uri": format!("{}/oauth2/v3/certs", state.issuer),
        "scopes_supported": ["openid", "email", "profile"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"]
    }))
}

async fn oauth2_auth(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    let redirect_uri = params
        .get("redirect_uri")
        .cloned()
        .unwrap_or_else(|| state.issuer.clone());
    let state_param = params
        .get("state")
        .cloned()
        .unwrap_or_else(|| "mock_state".to_string());
    let nonce = params.get("nonce").cloned();
    let code_challenge = params.get("code_challenge").cloned();
    let code_challenge_method = params.get("code_challenge_method").cloned();
    let scope = params.get("scope").cloned();
    let response_type = params
        .get("response_type")
        .cloned()
        .unwrap_or_else(|| "code".to_string());
    let client_id = params
        .get("client_id")
        .cloned()
        .unwrap_or_else(|| state.client_id.clone());
    let response_mode = params
        .get("response_mode")
        .cloned()
        .unwrap_or_else(|| "form_post".to_string());

    let auth_code = Uuid::new_v4().to_string();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    state.authorization_codes.lock().unwrap().insert(
        auth_code.clone(),
        AuthorizationRequest {
            nonce,
            code_challenge,
            code_challenge_method,
            redirect_uri: redirect_uri.clone(),
            state: state_param.clone(),
            scope,
            response_type,
            client_id,
            created_at,
        },
    );

    match response_mode.as_str() {
        "form_post" => {
            let form = format!(
                "<html><body><form id='auth_form' action='{redirect_uri}' method='POST'>\
                 <input type='hidden' name='code' value='{auth_code}'>\
                 <input type='hidden' name='state' value='{state_param}'>\
                 </form><script>document.getElementById('auth_form').submit();</script></body></html>"
            );
            Ok(Html(form).into_response())
        }
        _ => {
            let redirect_url = format!("{redirect_uri}?code={auth_code}&state={state_param}");
            Ok(Redirect::to(&redirect_url).into_response())
        }
    }
}

async fn oauth2_token(
    State(state): State<AppState>,
    Form(params): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let code = params.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let grant_type = params
        .get("grant_type")
        .cloned()
        .unwrap_or_else(|| "authorization_code".to_string());
    let code_verifier = params.get("code_verifier").cloned();
    let redirect_uri = params.get("redirect_uri").cloned();
    let client_id = params.get("client_id").cloned();

    if grant_type != "authorization_code" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let auth_request = state
        .authorization_codes
        .lock()
        .unwrap()
        .remove(code)
        .ok_or(StatusCode::BAD_REQUEST)?;

    if let Some(provided) = redirect_uri
        && provided != auth_request.redirect_uri
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(provided) = client_id
        && provided != auth_request.client_id
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if auth_request.response_type != "code" {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(challenge) = &auth_request.code_challenge {
        let verifier = code_verifier.ok_or(StatusCode::BAD_REQUEST)?;
        let method = auth_request
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");
        let computed = match method {
            "S256" => {
                use base64::Engine as _;
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(verifier.as_bytes());
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
            }
            "plain" => verifier,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        if computed != *challenge {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now - auth_request.created_at > 600 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let user = state.user.lock().unwrap().clone();
    let id_token = create_mock_id_token(&state, &user, auth_request.nonce.as_deref());

    Ok(Json(json!({
        "access_token": "mock_access_token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": auth_request.scope.unwrap_or_else(|| "openid email profile".to_string())
    })))
}

async fn oauth2_userinfo(State(state): State<AppState>) -> Json<Value> {
    let user = state.user.lock().unwrap().clone();
    Json(json!({
        "sub": user.sub,
        "email": user.email,
        "name": user.name,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "picture": "https://example.com/photo.jpg",
        "email_verified": true
    }))
}

async fn oauth2_jwks() -> Json<Value> {
    use base64::Engine as _;
    Json(json!({
        "keys": [{
            "kty": "oct",
            "kid": "mock_key_id",
            "use": "sig",
            "alg": "HS256",
            "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("test_secret")
        }]
    }))
}

fn create_mock_id_token(state: &AppState, user: &TestUser, nonce: Option<&str>) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": state.issuer,
        "sub": user.sub,
        "aud": state.client_id,
        "azp": state.client_id,
        "exp": now + 3600,
        "iat": now,
        "email": user.email,
        "name": user.name,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "email_verified": true,
    });
    if let Some(nonce_value) = nonce {
        claims["nonce"] = json!(nonce_value);
    }
    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("mock_key_id".to_string());
    let key = EncodingKey::from_secret("test_secret".as_ref());
    encode(&header, &claims, &key).expect("failed to encode mock ID token")
}

#[derive(Deserialize)]
struct TestConfigBody {
    email: Option<String>,
    sub: Option<String>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

async fn test_config(
    State(state): State<AppState>,
    Json(body): Json<TestConfigBody>,
) -> StatusCode {
    let mut user = state.user.lock().unwrap();
    if let Some(v) = body.email {
        user.email = v;
    }
    if let Some(v) = body.sub {
        user.sub = v;
    }
    if let Some(v) = body.name {
        user.name = v;
    }
    if let Some(v) = body.given_name {
        user.given_name = v;
    }
    if let Some(v) = body.family_name {
        user.family_name = v;
    }
    StatusCode::NO_CONTENT
}
