use askama::Template;
use axum::{
    extract::{Json, Path},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;

use oauth2_passkey::{
    AuthenticationOptions, AuthenticatorResponse, O2P_ROUTE_PREFIX, PasskeyCredential,
    RegisterCredential, RegistrationOptions, RegistrationStartRequest, SessionUser,
    delete_passkey_credential_core, get_related_origin_json, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_core, list_credentials_core, update_passkey_credential_core,
};

use crate::{passkey::conditional_ui, IntoResponseError};
use crate::session::AuthUser;

use axum::routing::{Router, delete, get, post};

pub fn router() -> Router {
    Router::new()
        .route("/user_summary.js", get(serve_user_summary_js))
        .route("/user_summary.css", get(serve_user_summary_css))
}
