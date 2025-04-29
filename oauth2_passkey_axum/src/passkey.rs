use askama::Template;
use axum::{
    extract::{Json, Path},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
    routing::{Router, delete, get, post},
};
use serde::Deserialize;
use serde_json::Value;

use oauth2_passkey::{
    AuthenticationOptions, AuthenticatorResponse, O2P_ROUTE_PREFIX, PasskeyCredential,
    RegisterCredential, RegistrationOptions, RegistrationStartRequest,
    delete_passkey_credential_core, get_related_origin_json, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_core, list_credentials_core, update_passkey_credential_core,
};

use super::error::IntoResponseError;
use super::session::AuthUser;

pub(super) fn router() -> Router {
    Router::new()
        .route("/passkey.js", get(serve_passkey_js))
        .route("/conditional_ui", get(conditional_ui))
        .route("/conditional_ui.js", get(serve_conditional_ui_js))
        .nest("/auth", router_auth())
        .nest("/register", router_register())
        .route("/credentials", get(list_passkey_credentials))
        .route(
            "/credentials/{credential_id}",
            delete(delete_passkey_credential),
        )
        .route("/credential/update", post(update_passkey_credential))
}

fn router_register() -> Router {
    Router::new()
        .route("/start", post(handle_start_registration))
        .route("/finish", post(handle_finish_registration))
}

fn router_auth() -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
}

/// Creates a router for the WebAuthn well-known endpoint
/// This should be mounted at the root level of the application
pub fn passkey_well_known_router() -> Router {
    Router::new().route("/webauthn", get(serve_related_origin))
}

async fn handle_start_registration(
    auth_user: Option<AuthUser>,
    request_headers: HeaderMap,
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| &u.session_user);

    // Use the new wrapper function that handles headers directly
    let registration_options =
        handle_start_registration_core(session_user, &request_headers, request)
            .await
            .into_response_error()?;

    Ok(Json(registration_options))
}

async fn handle_finish_registration(
    auth_user: Option<AuthUser>,
    request_headers: HeaderMap,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| &u.session_user);
    handle_finish_registration_core(session_user, &request_headers, reg_data)
        .await
        .into_response_error()
}

async fn handle_start_authentication(
    Json(body): Json<Value>,
) -> Result<Json<AuthenticationOptions>, (StatusCode, String)> {
    // Call the core function with the extracted data
    let auth_options = handle_start_authentication_core(&body)
        .await
        .into_response_error()?;

    // Return the authentication options as JSON
    Ok(Json(auth_options))
}

async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    // Call the core function with the extracted data
    let (_, name, headers) = handle_finish_authentication_core(auth_response)
        .await
        .into_response_error()?;

    // Return the headers and name
    Ok((headers, name))
}

async fn serve_passkey_js() -> Response {
    let js_content = include_str!("../static/passkey.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

#[derive(Template)]
#[template(path = "conditional_ui.j2")]
struct ConditionalUiTemplate<'a> {
    o2p_route_prefix: &'a str,
}

async fn conditional_ui() -> impl IntoResponse {
    let template = ConditionalUiTemplate {
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap_or_default())).into_response()
}

async fn serve_conditional_ui_js() -> Response {
    let js_content = include_str!("../static/conditional_ui.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

async fn list_passkey_credentials(
    auth_user: AuthUser,
) -> Result<Json<Vec<PasskeyCredential>>, (StatusCode, String)> {
    // let session_user = auth_user.as_ref().map(|u| u as &SessionUser);
    // let credentials = list_credentials_core(session_user)
    let credentials = list_credentials_core(&auth_user.session_user.id)
        .await
        .into_response_error()?;
    Ok(Json(credentials))
}

async fn delete_passkey_credential(
    auth_user: AuthUser,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    delete_passkey_credential_core(&auth_user.session_user.id, &credential_id)
        .await
        .into_response_error()
        .map(|()| StatusCode::NO_CONTENT)
}

async fn serve_related_origin() -> Response {
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

#[derive(Deserialize)]
struct UpdateCredentialUserDetailsRequest {
    pub credential_id: String,
    pub name: String,
    pub display_name: String,
}

/// Update the name and display name of a passkey credential
///
/// This endpoint allows users to update the name and display name of their passkey credentials.
/// It also provides the necessary information for the client to call the WebAuthn
/// signalCurrentUserDetails API to update the credential in the authenticator.
async fn update_passkey_credential(
    auth_user: AuthUser,
    Json(payload): Json<UpdateCredentialUserDetailsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = auth_user.session_user;

    // Call the update function
    let response = update_passkey_credential_core(
        &payload.credential_id,
        &payload.name,
        &payload.display_name,
        Some(session_user),
    )
    .await
    .into_response_error()?;

    Ok(Json(response))
}
