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
    delete_passkey_credential_core, update_user_admin_status,
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

    // Convert AuthUser to SessionUser for the core functions
    let session_user = oauth2_passkey::SessionUser::from(&auth_user);

    // Fetch users from storage with proper authorization
    let users = oauth2_passkey::get_all_users(&session_user)
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

#[derive(serde::Deserialize)]
pub(super) struct PageUserContext {
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

    // Convert AuthUser to SessionUser for the core function
    let session_user = oauth2_passkey::SessionUser::from(&auth_user);

    // Call the core function to delete the user account and all associated data with proper authorization
    oauth2_passkey::delete_user_account_admin(&session_user, &payload.user_id)
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

async fn delete_passkey_credential(
    auth_user: AuthUser,
    Path(credential_id): Path<String>,
    ExtractJson(payload): ExtractJson<PageUserContext>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Check admin status
    if !auth_user.is_admin {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    // Convert AuthUser to SessionUser for the core function
    let session_user = oauth2_passkey::SessionUser::from(&auth_user);

    // Use the authorized version with proper user_id parameter
    delete_passkey_credential_core(&session_user, &payload.user_id, &credential_id)
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

    // Convert AuthUser to SessionUser for the core function
    let session_user = oauth2_passkey::SessionUser::from(&auth_user);

    // Use the authorized version with proper user_id parameter
    delete_oauth2_account_core(
        &session_user,
        &payload.user_id,
        &provider,
        &provider_user_id,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the delete_user_account_handler returns an error
    /// when a non-admin user tries to delete another user's account.
    /// This test checks:
    /// 1. The handler returns an error status code (UNAUTHORIZED).
    /// 2. The error message is "Not authorized".
    #[tokio::test]
    async fn test_delete_user_account_handler_unauthorized() {
        // Create a non-admin user
        let auth_user = AuthUser {
            id: "user123".to_string(),
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            csrf_token: "token123".to_string(),
            csrf_via_header_verified: true,
        };

        // Create a delete request
        let payload = DeleteUserRequest {
            user_id: "user456".to_string(),
        };

        // Call the handler
        let result = delete_user_account_handler(auth_user, ExtractJson(payload)).await;

        // Verify that it returns an unauthorized error
        assert!(result.is_err());
        if let Err((status, message)) = result {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(message, "Not authorized".to_string());
        } else {
            panic!("Expected an error but got Ok");
        }
    }

    /// Test that the update_admin_status_handler returns an error
    /// when a non-admin user tries to update another user's admin status.
    /// This test checks:
    /// 1. The handler returns an error status code (UNAUTHORIZED).
    /// 2. The error message is "Not authorized".
    /// 3. The handler does not panic or return Ok when it should return an error.
    #[tokio::test]
    async fn test_update_admin_status_handler_unauthorized() {
        // Create a non-admin user
        let auth_user = AuthUser {
            id: "user123".to_string(),
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            csrf_token: "token123".to_string(),
            csrf_via_header_verified: true,
        };

        // Create an update request
        let payload = UpdateAdminStatusRequest {
            user_id: "user456".to_string(),
            is_admin: true,
        };

        // Call the handler
        let result = update_admin_status_handler(auth_user, ExtractJson(payload)).await;

        // Verify that it returns an unauthorized error
        assert!(result.is_err());
        if let Err((status, message)) = result {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(message, "Not authorized".to_string());
        } else {
            panic!("Expected an error but got Ok");
        }
    }

    // Note: Removed meaningless tests that only validated basic struct creation
    // These provided no validation value beyond testing basic Rust language features
}
