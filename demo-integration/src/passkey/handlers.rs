use askama::Template;
use axum::{
    extract::Json,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{Html, IntoResponse, Response},
};

use libpasskey::{
    // start_registration_with_auth_user,
    create_registration_options,
    finish_registration,
    start_authentication,
    start_registration,
    verify_authentication,
    AuthenticationOptions,
    AuthenticatorResponse,
    PublicKeyCredentialUserEntity,
    RegisterCredential,
    RegistrationOptions,
};

use crate::session::AuthUser;
use libpasskey::PASSKEY_ROUTE_PREFIX;
use libsession::User as SessionUser;

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate {
    passkey_route_prefix: &'static str,
}

pub(crate) async fn index() -> impl IntoResponse {
    let template = IndexTemplate {
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

pub(crate) async fn handle_start_registration_get(
    user: Option<AuthUser>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    match user {
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
        Some(u) => {
            #[cfg(debug_assertions)]
            println!("User: {:#?}", u);

            let options = start_registration_with_auth_user(u)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(Json(options))
        }
    }
}

async fn start_registration_with_auth_user(user: AuthUser) -> Result<RegistrationOptions, String> {
    let user_info = PublicKeyCredentialUserEntity {
        id: user.id.clone(),
        name: user.email.clone(),
        display_name: user.name.clone(),
    };

    #[cfg(debug_assertions)]
    println!("User info: {:#?}", user_info);

    let options = create_registration_options(user_info)
        .await
        .map_err(|e| e.to_string())?;

    Ok(options)
}

pub(crate) async fn handle_start_registration(
    Json(username): Json<String>,
) -> Json<RegistrationOptions> {
    Json(
        start_registration(username)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
            .expect("Failed to start registration"),
    )
}

pub(crate) async fn handle_finish_registration(
    Json(reg_data): Json<RegisterCredential>,
) -> Result<String, (StatusCode, String)> {
    #[cfg(debug_assertions)]
    println!("Registration data: {:#?}", reg_data);
    finish_registration(reg_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

pub(crate) async fn handle_start_authentication(
    username: Result<Json<String>, axum::extract::rejection::JsonRejection>,
) -> Json<AuthenticationOptions> {
    let username = match username {
        Ok(Json(username)) => Some(username),
        Err(_) => None,
    };

    Json(
        start_authentication(username)
            .await
            .expect("Failed to start authentication"),
    )
}

pub(crate) async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<String, (StatusCode, String)> {
    verify_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

pub(crate) async fn serve_passkey_js() -> Response {
    let js_content = include_str!("../../static/passkey.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}
