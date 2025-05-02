use askama::Template;
use axum::{
    Router,
    extract::{Json as ExtractJson, Path},
    http::StatusCode,
    response::Html,
    routing::{delete, get, put},
};

use oauth2_passkey::{
    DbUser, O2P_ROUTE_PREFIX, SessionUser, delete_oauth2_account_core,
    delete_passkey_credential_core, delete_user_account_admin, update_user_admin_status,
};

use super::super::error::IntoResponseError;
use crate::config::O2P_REDIRECT_ANON;
use crate::session::AuthUser;

pub(super) fn router() -> Router<()> {
    Router::new()
        .route("/list_users", get(list_users))
        .route("/delete_user", delete(delete_user_account_handler))
        .route(
            "/delete_passkey_credential/{credential_id}",
            delete(delete_passkey_credential),
        )
        .route(
            "/delete_oauth2_account/{provider}/{provider_user_id}",
            delete(delete_oauth2_account),
        )
        .route("/update_admin_status", put(update_admin_status_handler))
}

#[derive(Template)]
#[template(path = "admin_user_list.j2")]
struct UserListTemplate {
    users: Vec<DbUser>,
    o2p_route_prefix: String,
    o2p_redirect_anon: String,
    csrf_token: String,
}

async fn list_users(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser for the core functions
    if !auth_user.is_admin {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    };

    // Fetch users from storage
    let users = oauth2_passkey::get_all_users()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let csrf_token = auth_user.csrf_token.clone();

    // Render the template
    let template = UserListTemplate {
        users,
        o2p_route_prefix: O2P_ROUTE_PREFIX.to_string(),
        o2p_redirect_anon: O2P_REDIRECT_ANON.to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?))
}

#[derive(serde::Deserialize)]
pub(super) struct DeleteUserRequest {
    user_id: String,
}

pub(super) async fn delete_user_account_handler(
    auth_user: AuthUser,
    ExtractJson(payload): ExtractJson<DeleteUserRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify that the user has admin privileges
    if !auth_user.is_admin {
        tracing::warn!(
            "User {} is not authorized to delete another user's account",
            auth_user.id
        );
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    // Call the core function to delete the user account and all associated data
    // Using the imported function from libauth
    delete_user_account_admin(&payload.user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::debug!(
        "User account deleted: {} by {}",
        payload.user_id,
        auth_user.id
    );

    // Return the credential IDs in the response for client-side notification
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
pub(super) struct PageUserContext {
    user_id: String,
}

async fn delete_passkey_credential(
    auth_user: AuthUser,
    Path(credential_id): Path<String>,
    ExtractJson(payload): ExtractJson<PageUserContext>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Check admin status
    if !auth_user.is_admin {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    delete_passkey_credential_core(&payload.user_id, &credential_id)
        .await
        .map(|()| StatusCode::NO_CONTENT)
        .into_response_error()
}

async fn delete_oauth2_account(
    auth_user: AuthUser,
    Path((provider, provider_user_id)): Path<(String, String)>,
    ExtractJson(payload): ExtractJson<PageUserContext>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Check admin status
    if !auth_user.is_admin {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    delete_oauth2_account_core(&payload.user_id, &provider, &provider_user_id)
        .await
        .map(|()| StatusCode::NO_CONTENT)
        .into_response_error()
}

#[derive(serde::Deserialize)]
pub(super) struct UpdateAdminStatusRequest {
    user_id: String,
    is_admin: bool,
}

pub(super) async fn update_admin_status_handler(
    auth_user: AuthUser,
    ExtractJson(payload): ExtractJson<UpdateAdminStatusRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Convert AuthUser to SessionUser for the core function
    let session_user = SessionUser::from(&auth_user);

    // Verify that the user has admin privileges
    if !session_user.is_admin {
        tracing::warn!(
            "User {} is not authorized to update admin status",
            session_user.id
        );
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    // Call the core function to update the user's admin status
    update_user_admin_status(&session_user, &payload.user_id, payload.is_admin)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::debug!(
        "User admin status updated: {} is_admin={} by {}",
        payload.user_id,
        payload.is_admin,
        session_user.id
    );

    Ok(StatusCode::OK)
}
