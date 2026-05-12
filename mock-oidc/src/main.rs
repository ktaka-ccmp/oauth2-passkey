//! Standalone mock OIDC provider for E2E testing.
//!
//! Implements a minimal subset of the OpenID Connect 1.0 + OAuth2 authorization
//! code flow sufficient to exercise oauth2-passkey-axum end-to-end:
//! discovery, /authorize (form_post and query), /token (with PKCE), /userinfo, JWKS.
//!
//! The user identity returned by the server can be updated at runtime via
//! `POST /test/config` so a single long-running instance can serve multiple
//! Playwright tests.
//!
//! NOTE: This mirrors `oauth2_passkey_axum/tests/common/axum_mock_server.rs`.
//! Eventually both should share a library crate; for now duplication is
//! deliberate to keep the integration test infrastructure untouched.

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
    env,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct AuthorizationRequest {
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    redirect_uri: String,
    /// OAuth2 state parameter - echoed to the client in the redirect but not
    /// validated during token exchange (the RP is responsible for validating
    /// state against its own session).
    #[allow(dead_code)]
    state: String,
    scope: Option<String>,
    response_type: String,
    client_id: String,
    created_at: u64,
}

#[derive(Clone)]
struct TestUser {
    email: String,
    sub: String,
    name: String,
    given_name: String,
    family_name: String,
}

#[derive(Clone)]
struct AppState {
    issuer: String,
    client_id: String,
    user: Arc<Mutex<TestUser>>,
    authorization_codes: Arc<Mutex<HashMap<String, AuthorizationRequest>>>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = env::var("MOCK_OIDC_BIND").unwrap_or_else(|_| "127.0.0.1:9876".to_string());
    let issuer = env::var("MOCK_OIDC_ISSUER").unwrap_or_else(|_| format!("http://{bind}"));
    let client_id = env::var("MOCK_OIDC_CLIENT_ID")
        .unwrap_or_else(|_| "test-client-id.apps.googleusercontent.com".to_string());

    let user = TestUser {
        email: env::var("MOCK_OIDC_USER_EMAIL")
            .unwrap_or_else(|_| "first-user@example.com".to_string()),
        sub: env::var("MOCK_OIDC_USER_SUB")
            .unwrap_or_else(|_| "google_first-user-test-google-id".to_string()),
        name: env::var("MOCK_OIDC_USER_NAME").unwrap_or_else(|_| "First User".to_string()),
        given_name: env::var("MOCK_OIDC_USER_GIVEN_NAME").unwrap_or_else(|_| "First".to_string()),
        family_name: env::var("MOCK_OIDC_USER_FAMILY_NAME").unwrap_or_else(|_| "User".to_string()),
    };

    let state = AppState {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        user: Arc::new(Mutex::new(user)),
        authorization_codes: Arc::new(Mutex::new(HashMap::new())),
    };

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            cleanup_expired_codes(&cleanup_state);
        }
    });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth2/auth", get(oauth2_auth))
        .route("/oauth2/token", post(oauth2_token))
        .route("/oauth2/userinfo", get(oauth2_userinfo))
        .route("/oauth2/v3/certs", get(oauth2_jwks))
        .route("/test/config", post(test_config))
        .route("/test/healthz", get(healthz))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {bind}: {e}"));

    tracing::info!(
        issuer = %issuer,
        client_id = %client_id,
        bind = %bind,
        "mock-oidc listening"
    );

    axum::serve(listener, app).await.expect("server error");
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

    let auth_request = AuthorizationRequest {
        nonce,
        code_challenge: code_challenge.clone(),
        code_challenge_method,
        redirect_uri: redirect_uri.clone(),
        state: state_param.clone(),
        scope,
        response_type,
        client_id,
        created_at,
    };

    state
        .authorization_codes
        .lock()
        .unwrap()
        .insert(auth_code.clone(), auth_request);

    tracing::info!(
        code = %auth_code,
        pkce = code_challenge.is_some(),
        mode = %response_mode,
        "issued authorization code"
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
        tracing::warn!(
            expected = %auth_request.redirect_uri,
            got = %provided,
            "redirect_uri mismatch"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(provided) = client_id
        && provided != auth_request.client_id
    {
        tracing::warn!(
            expected = %auth_request.client_id,
            got = %provided,
            "client_id mismatch"
        );
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
            "plain" => verifier.clone(),
            _ => return Err(StatusCode::BAD_REQUEST),
        };

        if computed != *challenge {
            tracing::warn!("PKCE validation failed");
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

fn cleanup_expired_codes(state: &AppState) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut codes = state.authorization_codes.lock().unwrap();
    codes.retain(|_, request| now - request.created_at <= 600);
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
    tracing::info!(email = %user.email, sub = %user.sub, "test user updated");
    StatusCode::NO_CONTENT
}
