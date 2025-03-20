use askama::Template;
use axum::{
    extract::{Json, Path},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
};
use serde_json::Value;

use oauth2_passkey::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    RegistrationStartRequest, SessionUser, delete_passkey_credential_core,
    handle_finish_authentication_core, handle_finish_registration_core,
    handle_start_authentication_core, handle_start_registration_core, list_credentials_core,
};
use oauth2_passkey::{PASSKEY_ROUTE_PREFIX, StoredCredential, get_related_origin_json};

use crate::session::AuthUser;

pub(crate) async fn handle_start_registration(
    auth_user: Option<AuthUser>,
    request_headers: HeaderMap,
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    // Use the new wrapper function that handles headers directly
    let registration_options =
        handle_start_registration_core(session_user, &request_headers, request).await?;

    Ok(Json(registration_options))
}

pub(crate) async fn handle_finish_registration(
    auth_user: Option<AuthUser>,
    request_headers: HeaderMap,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);
    handle_finish_registration_core(session_user, &request_headers, reg_data).await
}

pub(crate) async fn handle_start_authentication(
    Json(body): Json<Value>,
) -> Result<Json<AuthenticationOptions>, (StatusCode, String)> {
    // Call the core function with the extracted data
    let auth_options = handle_start_authentication_core(&body).await?;

    // Return the authentication options as JSON
    Ok(Json(auth_options))
}

pub(crate) async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    // Call the core function with the extracted data
    let (_, name, headers) = handle_finish_authentication_core(auth_response).await?;

    // Return the headers and name
    Ok((headers, name))
}

pub(crate) async fn serve_passkey_js() -> Response {
    let js_content = include_str!("../../static/passkey.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

#[derive(Template)]
#[template(path = "conditional_ui.j2")]
struct ConditionalUiTemplate {
    passkey_route_prefix: &'static str,
}

pub(crate) async fn conditional_ui() -> impl IntoResponse {
    let template = ConditionalUiTemplate {
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap_or_default())).into_response()
}

pub(crate) async fn serve_conditional_ui_js() -> Response {
    let js_content = include_str!("../../static/conditional_ui.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

pub(crate) async fn list_passkey_credentials(
    auth_user: Option<AuthUser>,
) -> Result<Json<Vec<StoredCredential>>, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);
    let credentials = list_credentials_core(session_user).await?;
    Ok(Json(credentials))
}

pub(crate) async fn delete_passkey_credential(
    auth_user: Option<AuthUser>,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);
    delete_passkey_credential_core(session_user, &credential_id)
        .await
        .map_err(|e| (e.0, e.1))
        .map(|()| StatusCode::NO_CONTENT)
}

pub(crate) async fn serve_related_origin() -> Response {
    // Get the WebAuthn configuration JSON from libpasskey
    match get_related_origin_json() {
        Ok(json) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(json.into())
            .unwrap_or_default(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("Failed to generate WebAuthn config: {}", e).into())
            .unwrap_or_default(),
    }
}
