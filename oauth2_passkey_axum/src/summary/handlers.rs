use askama::Template;
use axum::{
    Router,
    extract::Json as ExtractJson,
    http::StatusCode,
    response::{Html, Json},
    routing::{delete, get, put},
};

use oauth2_passkey::SessionUser;
use oauth2_passkey::{
    O2P_ROUTE_PREFIX, delete_user_account, list_accounts_core, list_credentials_core,
    update_user_account,
};

use super::templates::{TemplateAccount, TemplateCredential, UserSummaryTemplate};
use crate::session::AuthUser;
use serde_json::{Value, json};

/// Create a router for the user summary endpoints
pub fn router() -> Router<()> {
    Router::new()
        .route("/", get(user_summary))
        .route("/user-info", get(user_info))
        .route("/user/delete", delete(delete_user_account_handler))
        .route("/user/update", put(update_user_account_handler))
}

/// Return basic user information as JSON for the client-side JavaScript
///
/// This endpoint provides the authenticated user's basic information (id, name, display_name)
/// to be used by client-side JavaScript for pre-filling forms or displaying user information.
pub async fn user_info(auth_user: Option<AuthUser>) -> Result<Json<Value>, (StatusCode, String)> {
    match auth_user {
        Some(user) => {
            // Get passkey credentials count for the user
            let stored_credentials = list_credentials_core(Some(&user)).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to fetch credentials: {:?}", e),
                )
            })?;

            // Return user information as JSON
            let user_data = json!({
                "id": user.id,
                "account": user.account,
                "label": user.label,
                "passkey_count": stored_credentials.len()
            });

            Ok(Json(user_data))
        }
        None => {
            // Return a 401 Unauthorized if no user is authenticated
            Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))
        }
    }
}

/// Delete the authenticated user's account and all associated data
///
/// This endpoint requires authentication and will delete:
/// 1. All OAuth2 accounts linked to the user
/// 2. All Passkey credentials registered by the user
/// 3. The user account itself
///
/// After successful deletion, the client should redirect to the logout endpoint
/// to clear the session.
#[derive(serde::Deserialize)]
pub struct DeleteUserRequest {
    user_id: String,
}

/// Request payload for updating user account information
#[derive(serde::Deserialize)]
pub struct UpdateUserRequest {
    user_id: String,
    account: Option<String>,
    label: Option<String>,
}

/// Update the authenticated user's account information
///
/// This endpoint allows users to update their account and label fields.
/// It requires authentication and verifies that the user is only updating their own account.
pub async fn update_user_account_handler(
    auth_user: AuthUser,
    ExtractJson(payload): ExtractJson<UpdateUserRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Get the user ID from the authenticated user
    let session_user_id = auth_user.id.clone();
    let request_user_id = payload.user_id.clone();

    // Verify that the user ID in the request matches the session user ID
    if session_user_id != request_user_id {
        tracing::warn!(
            "User ID mismatch in update request: session={}, request={}",
            session_user_id,
            request_user_id
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot update another user's account".to_string(),
        ));
    }

    tracing::debug!("Updating user account: {}", session_user_id);
    tracing::debug!(
        "New account: {:?}, new label: {:?}",
        payload.account,
        payload.label
    );

    // Call the core function to update the user account
    let updated_user = update_user_account(&session_user_id, payload.account, payload.label)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return the updated user information
    let user_data = json!({
        "id": updated_user.id,
        "account": updated_user.account,
        "label": updated_user.label,
        "success": true,
        "message": "User account updated successfully"
    });

    Ok(Json(user_data))
}

pub async fn delete_user_account_handler(
    auth_user: AuthUser,
    ExtractJson(payload): ExtractJson<DeleteUserRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Get the user ID from the authenticated user
    let session_user_id = auth_user.id.clone();
    let request_user_id = payload.user_id;

    // Verify that the user ID in the request matches the session user ID
    if session_user_id != request_user_id {
        tracing::warn!(
            "User ID mismatch in delete request: session={}, request={}",
            session_user_id,
            request_user_id
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot delete another user's account".to_string(),
        ));
    }

    tracing::debug!("Deleting user account: {}", session_user_id);

    // Call the core function to delete the user account and all associated data
    // Using the imported function from libauth
    delete_user_account(&session_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return a success status code
    Ok(StatusCode::OK)
}

/// Display a comprehensive summary page with user info, passkey credentials, and OAuth2 accounts
pub async fn user_summary(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser for the core functions
    let session_user: &SessionUser = &auth_user;

    // Fetch passkey credentials using the public function from libauth
    let stored_credentials = list_credentials_core(Some(session_user))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch credentials: {:?}", e),
            )
        })?;

    // Convert StoredCredential to TemplateCredential
    let passkey_credentials = stored_credentials
        .into_iter()
        .map(|cred| TemplateCredential {
            credential_id: cred.credential_id,
            user_id: cred.user_id.clone(),
            user_name: cred.user.name.clone(),
            user_display_name: cred.user.display_name.clone(),
            user_handle: cred.user.user_handle.clone(),
            counter: cred.counter.to_string(),
            created_at: cred.created_at.to_string(),
            updated_at: cred.updated_at.to_string(),
        })
        .collect();

    // Fetch OAuth2 accounts using the public function from libauth
    let oauth2_accounts = list_accounts_core(Some(session_user)).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch accounts: {:?}", e),
        )
    })?;

    // Convert OAuth2Account to TemplateAccount
    let oauth2_accounts = oauth2_accounts
        .into_iter()
        .map(|account| {
            TemplateAccount {
                id: account.id,
                user_id: account.user_id,
                provider: account.provider,
                provider_user_id: account.provider_user_id,
                name: account.name,
                email: account.email,
                picture: account.picture.unwrap_or_default(),
                metadata_str: account.metadata.to_string(), // Convert metadata Value to string
                created_at: account.created_at.to_string(),
                updated_at: account.updated_at.to_string(),
            }
        })
        .collect();

    // Create template with all data
    // Create the route strings first

    let template = UserSummaryTemplate::new(
        auth_user,
        passkey_credentials,
        oauth2_accounts,
        // Pass owned String values to the template
        O2P_ROUTE_PREFIX.to_string(),
    );

    // Render the template
    let html = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template rendering error: {:?}", e),
        )
    })?;

    Ok(Html(html))
}
