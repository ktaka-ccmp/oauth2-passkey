use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::post,
    Router,
};
use libpasskey::{
    passkey::{
        auth::{
            start_authentication, verify_authentication, AuthenticationOptions,
            AuthenticatorResponse,
        },
        register::{
            finish_registration, start_registration, RegisterCredential, RegistrationOptions,
        },
    },
    AppState,
};

pub fn router_register(state: AppState) -> Router {
    Router::new()
        .route("/start", post(handle_start_registration))
        .route("/finish", post(handle_finish_registration))
        .with_state(state)
}

pub fn router_auth(state: AppState) -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
        .with_state(state)
}

async fn handle_start_registration(
    State(state): State<AppState>,
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    Json(
        start_registration(&state, username)
            .await
            .expect("Failed to start registration"),
    )
}

async fn handle_finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<String, (StatusCode, String)> {
    finish_registration(&state, reg_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

async fn handle_start_authentication(
    State(state): State<AppState>,
    username: Result<Json<String>, axum::extract::rejection::JsonRejection>,
) -> Json<AuthenticationOptions> {
    let username = match username {
        Ok(Json(username)) => Some(username),
        Err(_) => None,
    };

    Json(
        start_authentication(&state, username)
            .await
            .expect("Failed to start authentication"),
    )
}

async fn handle_finish_authentication(
    State(state): State<AppState>,
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    verify_authentication(&state, auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
