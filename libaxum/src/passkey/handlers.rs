use askama::Template;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use libuserdb::{User, UserStore};

use libauth::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    finish_authentication, finish_registration, finish_registration_with_auth_user,
    start_authentication, start_registration,
};

use liboauth2::OAuth2Store;
use libpasskey::{CredentialSearchField, PASSKEY_ROUTE_PREFIX, PasskeyStore, StoredCredential};
use libsession::{User as SessionUser, create_session_with_uid};

use crate::session::AuthUser;

pub(crate) async fn handle_start_registration_get(
    user: Option<AuthUser>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    match user {
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
        Some(u) => {
            tracing::debug!("User: {:#?}", u);

            let session_user: SessionUser = (*u).clone();

            let oauth2_accounts = OAuth2Store::get_oauth2_accounts(&u.id)
                // OAuth2Store::get_oauth2_accounts(&session_user.id)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
                .first()
                .cloned()
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "No OAuth2 accounts found".to_string(),
                    )
                })?;

            let username = oauth2_accounts.email.clone();
            let displayname = oauth2_accounts.name.clone();

            let options = start_registration(Some(session_user), username, displayname)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
                .expect("Failed to start registration");
            Ok(Json(options))
        }
    }
}

pub(crate) async fn handle_start_registration(
    auth_user: Option<AuthUser>,
    Json(body): Json<Value>,
) -> Json<RegistrationOptions> {
    let session_user: Option<SessionUser> = match auth_user {
        Some(u) => {
            tracing::debug!("User: {:#?}", u);

            let session_user: SessionUser = (*u).clone();
            Some(session_user)
        }
        None => None,
    };

    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .map(String::from)
        .expect("Missing username");

    let displayname = body
        .get("displayname")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or(username.clone());

    Json(
        start_registration(session_user, username, displayname)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
            .expect("Failed to start registration"),
    )
}

pub(crate) async fn handle_finish_registration(
    auth_user: Option<AuthUser>,
    Json(reg_data): Json<RegisterCredential>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    match auth_user {
        Some(u) => {
            tracing::debug!("User: {:#?}", u);

            let session_user: SessionUser = (*u).clone();
            let message = finish_registration_with_auth_user(session_user, reg_data)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            Ok((HeaderMap::new(), message))
        }
        None => {
            let new_user = User {
                id: Uuid::new_v4().to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            // Store the user
            let stored_user = UserStore::upsert_user(new_user)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            // Finish registration
            let result = finish_registration(&stored_user.id, &reg_data)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()));

            match result {
                Ok(message) => {
                    // Create session with the user_id
                    let headers = create_session_with_uid(&stored_user.id)
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

                    Ok((headers, message))
                }
                Err(err) => Err(err),
            }
        }
    }
}

pub(crate) async fn handle_start_authentication(
    Json(body): Json<Value>,
) -> Result<Json<AuthenticationOptions>, (StatusCode, String)> {
    let username = if body.is_object() {
        body.get("username")
            .and_then(|v| v.as_str())
            .map(String::from)
    } else if body.is_string() {
        Some(body.as_str().unwrap().to_string()) // Directly use the string
    } else {
        None
    };

    match start_authentication(username).await {
        Ok(auth_options) => Ok(Json(auth_options)),
        Err(e) => {
            tracing::debug!("Error: {:#?}", e);
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

pub(crate) async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    let (uid, name) = finish_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    tracing::debug!("User ID: {:#?}", uid);

    let headers = create_session_with_uid(&uid)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

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

pub(crate) async fn list_credentials(
    auth_user: Option<AuthUser>,
) -> Result<Json<Vec<StoredCredential>>, (StatusCode, String)> {
    match auth_user {
        Some(u) => {
            tracing::debug!("User: {:#?}", u);
            let credentials =
                PasskeyStore::get_credentials_by(CredentialSearchField::UserId(u.id.to_owned()))
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(Json(credentials))
        }
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
    }
}
