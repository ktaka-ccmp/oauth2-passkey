use axum::{
    Router,
    extract::Json as ExtractJson,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    routing::{delete, get, put},
};
use axum_extra::{TypedHeader, headers};
use serde::Deserialize;
use serde_json::{Value, json};

use oauth2_passkey::{delete_user_account, prepare_logout_response, update_user_account};

use crate::session::AuthUser;

/// Create a router for the user summary endpoints
pub(super) fn router() -> Router<()> {
    Router::new()
        .route("/logout", get(logout))
        .route("/delete", delete(delete_user_account_handler))
        .route("/update", put(update_user_account_handler))
}

#[derive(Deserialize)]
struct RedirectQuery {
    redirect: Option<String>,
}

/// Handles logout requests with optional redirection
///
/// If no redirect parameter is provided in the query string, this function
/// will just return the logout headers. If a redirect parameter is provided,
/// it will redirect to that URL after clearing the session.
async fn logout(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Query(params): Query<RedirectQuery>,
) -> impl IntoResponse {
    // Clear the session and handle errors
    match prepare_logout_response(cookies).await {
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Ok(headers) => match params.redirect {
            Some(redirect_to) => {
                // Redirect to the specified URL
                tracing::debug!("Redirecting to {}", redirect_to);
                (headers, Redirect::to(&redirect_to)).into_response()
            }
            None => {
                // Just return the headers (for API/AJAX calls)
                tracing::debug!("No redirect specified, returning headers");
                (headers, StatusCode::OK).into_response()
            }
        },
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
pub(super) struct DeleteUserRequest {
    user_id: String,
}

/// Request payload for updating user account information
#[derive(serde::Deserialize)]
pub(super) struct UpdateUserRequest {
    user_id: String,
    account: Option<String>,
    label: Option<String>,
}

/// Update the authenticated user's account information
///
/// This endpoint allows users to update their account and label fields.
/// It requires authentication and verifies that the user is only updating their own account.
pub(super) async fn update_user_account_handler(
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

pub(super) async fn delete_user_account_handler(
    auth_user: AuthUser,
    ExtractJson(payload): ExtractJson<DeleteUserRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
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
    let credential_ids = delete_user_account(&session_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return the credential IDs in the response for client-side notification
    Ok(Json(json!({
        "status": "success",
        "message": "User account deleted successfully",
        "credential_ids": credential_ids
    })))
}
