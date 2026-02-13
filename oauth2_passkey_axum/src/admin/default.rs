use axum::{
    Json, Router,
    extract::{Json as ExtractJson, Path},
    http::StatusCode,
    routing::{delete, get, put},
};

use oauth2_passkey::{
    CredentialId, DbUser, Provider, ProviderUserId, SessionId, UserId, delete_oauth2_account_core,
    delete_passkey_credential_core, delete_user_account_admin, get_all_users,
    update_user_admin_status,
};

use super::super::error::IntoResponseError;
use crate::session::AuthUser;

pub(super) fn router() -> Router<()> {
    Router::new()
        .route("/users", get(get_all_users_handler))
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

/// Handler for getting all users (JSON API for admin audit dropdown)
async fn get_all_users_handler(
    auth_user: AuthUser,
) -> Result<Json<Vec<DbUser>>, (StatusCode, String)> {
    if !auth_user.has_admin_privileges() {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let session_id = SessionId::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session ID: {e}"),
        )
    })?;

    let users = get_all_users(session_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(users))
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
    if !auth_user.has_admin_privileges() {
        tracing::warn!(
            "User {} is not authorized to delete another user's account",
            auth_user.id
        );
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    // Call the core function to delete the user account and all associated data
    // Using the imported function from libauth
    let session_id = SessionId::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session ID: {e}"),
        )
    })?;
    let user_id = UserId::new(payload.user_id.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user ID: {e}")))?;
    delete_user_account_admin(session_id, user_id)
        .await
        .map(|()| {
            tracing::debug!(
                "User account deleted: {} by {}",
                payload.user_id,
                auth_user.id
            );
            StatusCode::NO_CONTENT
        })
        .into_response_error()
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
    if !auth_user.has_admin_privileges() {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let user_id = UserId::new(payload.user_id.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user ID: {e}")))?;
    let credential_id_enum = CredentialId::new(credential_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid credential ID: {e}"),
        )
    })?;

    delete_passkey_credential_core(user_id, credential_id_enum)
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .into_response_error()
}

async fn delete_oauth2_account(
    auth_user: AuthUser,
    Path((provider, provider_user_id)): Path<(String, String)>,
    ExtractJson(payload): ExtractJson<PageUserContext>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Check admin status
    if !auth_user.has_admin_privileges() {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let user_id = UserId::new(payload.user_id.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user ID: {e}")))?;
    let provider_enum = Provider::new(provider)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid provider: {e}")))?;
    let provider_user_id_enum = ProviderUserId::new(provider_user_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid provider user ID: {e}"),
        )
    })?;

    delete_oauth2_account_core(user_id, provider_enum, provider_user_id_enum)
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
    // Verify that the user has admin privileges
    if !auth_user.has_admin_privileges() {
        tracing::warn!(
            "User {} is not authorized to update admin status",
            auth_user.id
        );
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    // Call the core function to update the user's admin status
    let session_id = SessionId::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session ID: {e}"),
        )
    })?;
    let user_id = UserId::new(payload.user_id.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user ID: {e}")))?;
    update_user_admin_status(session_id, user_id, payload.is_admin)
        .await
        .map(|_| {
            tracing::debug!(
                "User admin status updated: {} is_admin={} by {}",
                payload.user_id,
                payload.is_admin,
                auth_user.id
            );
            StatusCode::OK
        })
        .into_response_error()
}

#[cfg(test)]
mod tests;
