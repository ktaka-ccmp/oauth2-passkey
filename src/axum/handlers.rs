use askama::Template;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::Html,
};
use axum_core::response::IntoResponse;

use crate::passkey::{
    finish_registration, start_authentication, start_registration, verify_authentication,
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

use crate::config::PASSKEY_ROUTE_PREFIX;
use crate::types::AppState;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    passkey_route_prefix: &'static str,
}

pub(crate) async fn index() -> impl IntoResponse {
    let template = IndexTemplate {
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

pub(crate) async fn handle_start_registration(
    State(state): State<AppState>,
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    Json(
        start_registration(&state, username)
            .await
            .expect("Failed to start registration"),
    )
}

pub(crate) async fn handle_finish_registration(
    State(state): State<AppState>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<String, (StatusCode, String)> {
    finish_registration(&state, reg_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

pub(crate) async fn handle_start_authentication(
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

pub(crate) async fn handle_finish_authentication(
    State(state): State<AppState>,
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    verify_authentication(&state, auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
