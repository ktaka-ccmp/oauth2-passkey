use askama::Template;
use axum::{
    Router,
    extract::{Json as ExtractJson, Path},
    http::StatusCode,
    response::Html,
    routing::{delete, get},
};

use oauth2_passkey::{
    DbUser, O2P_ROUTE_PREFIX, delete_oauth2_account_admin, delete_passkey_credential_admin,
    delete_user_account_admin, obfuscate_user_id,
};

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
            "/delete_oauth2_account/{provider_user_id}",
            delete(delete_oauth2_account),
        )
}

#[derive(Template)]
#[template(path = "admin_user_list.j2")]
struct UserListTemplate {
    users: Vec<DbUser>,
    o2p_route_prefix: String,
    o2p_redirect_anon: String,
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

    // Render the template
    let template = UserListTemplate {
        users,
        o2p_route_prefix: O2P_ROUTE_PREFIX.to_string(),
        o2p_redirect_anon: O2P_REDIRECT_ANON.to_string(),
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
    page_user_context: String,
}

async fn delete_passkey_credential(
    auth_user: AuthUser,
    Path(credential_id): Path<String>,
    ExtractJson(payload): ExtractJson<PageUserContext>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_admin_and_page_context(&auth_user, &payload.user_id, &payload.page_user_context)?;

    delete_passkey_credential_admin(&auth_user, &credential_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(|()| StatusCode::NO_CONTENT)
}

async fn delete_oauth2_account(
    auth_user: AuthUser,
    Path(provider_user_id): Path<String>,
    ExtractJson(payload): ExtractJson<PageUserContext>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_admin_and_page_context(&auth_user, &payload.user_id, &payload.page_user_context)?;

    delete_oauth2_account_admin(&auth_user, &provider_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .map(|()| StatusCode::NO_CONTENT)
}

fn validate_admin_and_page_context(
    auth_user: &AuthUser,
    user_id: &str,
    page_user_context: &str,
) -> Result<(), (StatusCode, String)> {
    if !auth_user.is_admin {
        tracing::warn!(
            "User {} is not authorized to delete another user's passkey credential",
            auth_user.id
        );
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    if obfuscate_user_id(user_id) != page_user_context {
        tracing::debug!(
            "Page user context mismatch for user {}: {} != {}",
            user_id,
            obfuscate_user_id(user_id),
            page_user_context
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "Page user context mismatch".to_string(),
        ));
    }

    Ok(())
}
