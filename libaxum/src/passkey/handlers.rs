use askama::Template;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use libauth::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    handle_finish_authentication_core, handle_finish_registration_core,
    handle_start_authentication_core, handle_start_registration_get_core,
    handle_start_registration_post_core, list_credentials_core,
};

use libpasskey::{PASSKEY_ROUTE_PREFIX, StoredCredential};
use libsession::User as SessionUser;

use crate::session::AuthUser;

/// Axum handler that extracts AuthUser from the request and delegates to the core function
pub(crate) async fn handle_start_registration_get(
    user: Option<AuthUser>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = user.as_ref().map(|u| u as &SessionUser);

    // Call the core function with the extracted data
    let options = handle_start_registration_get_core(session_user)
        .await
        .expect("Failed to start registration");

    Ok(Json(options))
}

pub(crate) async fn handle_start_registration_post(
    auth_user: Option<AuthUser>,
    Json(body): Json<Value>,
) -> Json<RegistrationOptions> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    // Call the core function with the extracted data
    let registration_options = handle_start_registration_post_core(session_user, &body)
        .await
        .expect("Failed to start registration");

    Json(registration_options)
}

pub(crate) async fn handle_finish_registration(
    auth_user: Option<AuthUser>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    handle_finish_registration_core(session_user, reg_data).await
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
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

pub(crate) async fn serve_conditional_ui_js() -> Response {
    let js_content = include_str!("../../static/conditional_ui.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

/// Axum handler that extracts AuthUser from the request and delegates to the core function
///
/// This function serves as a wrapper that handles the web framework specific parts
/// (extracting the user from the request) and then calls the core function.
// Template-friendly version of StoredCredential with binary data converted to strings
#[derive(Debug, Clone)]
struct TemplateCredential {
    credential_id_base64: String,
    user_id: String,
    user_name: String,
    user_display_name: String,
    user_handle: String,
    counter: String,
    created_at: String,
    updated_at: String,
}

impl From<StoredCredential> for TemplateCredential {
    fn from(cred: StoredCredential) -> Self {
        Self {
            credential_id_base64: URL_SAFE_NO_PAD.encode(&cred.credential_id),
            user_id: cred.user_id,
            user_name: cred.user.name,
            user_display_name: cred.user.display_name,
            user_handle: cred.user.user_handle,
            counter: cred.counter.to_string(),
            created_at: cred.created_at.to_string(),
            updated_at: cred.updated_at.to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "passkey_credentials.j2")]
struct PasskeyCredentialsTemplate {
    credentials: Vec<TemplateCredential>,
}

pub(crate) async fn list_passkey_credentials(
    auth_user: Option<AuthUser>,
) -> Result<Json<Vec<StoredCredential>>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    // Call the core function with the extracted data
    let credentials = list_credentials_core(session_user).await?;
    Ok(Json(credentials))
}

/// Display passkey credentials in HTML format using a template
///
/// This handler retrieves the passkey credentials for the authenticated user
/// and renders them using the passkey_credentials.j2 template.
pub(crate) async fn list_passkey_credentials_html(
    auth_user: Option<AuthUser>,
) -> Result<Html<String>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    // Call the core function with the extracted data
    let stored_credentials = list_credentials_core(session_user).await?;

    // Convert StoredCredential to TemplateCredential
    let credentials = stored_credentials
        .into_iter()
        .map(TemplateCredential::from)
        .collect();

    // Create template with credentials data
    let template = PasskeyCredentialsTemplate { credentials };

    // Render the template
    let html = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
    })?;

    Ok(Html(html))
}
