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

use oauth2_passkey::{
    SessionId, UserId, delete_user_account, prepare_logout_response, update_user_account,
};

use crate::session::AuthUser;

/// Create a router for the user summary endpoints
pub(crate) fn router() -> Router<()> {
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
    let updated_user = update_user_account(
        SessionId::new(auth_user.session_id.clone()),
        UserId::new(session_user_id.clone()),
        payload.account,
        payload.label,
    )
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

/// Delete the authenticated user's account and all associated data
///
/// This endpoint requires authentication and will delete:
/// 1. All OAuth2 accounts linked to the user
/// 2. All Passkey credentials registered by the user
/// 3. The user account itself
///
/// After successful deletion, the client should redirect to the logout endpoint
/// to clear the session.
/// Returns a list of credential IDs that were deleted.
#[derive(serde::Deserialize)]
pub(super) struct DeleteUserRequest {
    user_id: String,
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
    // Using the imported function from oauth2_passkey
    let credential_ids = delete_user_account(
        SessionId::new(auth_user.session_id.clone()),
        UserId::new(session_user_id.clone()),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return the credential IDs in the response for client-side notification
    Ok(Json(json!({
        "status": "success",
        "message": "User account deleted successfully",
        "credential_ids": credential_ids
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Test that the update_user_account_handler returns an error
    /// when a non-admin user tries to update another user's account.
    /// /// This test simulates a scenario where the authenticated user
    /// tries to update a different user's account, which should be forbidden.
    #[tokio::test]
    async fn test_update_user_account_handler_id_mismatch() {
        // Create a mock AuthUser
        let now = Utc::now();
        let auth_user = AuthUser {
            id: "user456".to_string(), // Different from request
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: Some(1),
            created_at: now,
            updated_at: now,
            csrf_token: "token".to_string(),
            csrf_via_header_verified: true,
            session_id: "session456".to_string(),
        };

        // Create a request payload with a different user ID
        let payload = UpdateUserRequest {
            user_id: "user123".to_string(), // Different from auth_user.id
            account: Some("new@example.com".to_string()),
            label: Some("New Label".to_string()),
        };

        // Call the handler
        let result = update_user_account_handler(auth_user, ExtractJson(payload)).await;

        // Verify the result is an error with FORBIDDEN status
        assert!(result.is_err());
        if let Err((status, message)) = result {
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(message, "Cannot update another user's account");
        }
    }

    /// Test that the delete_user_account_handler returns an error
    /// when a non-admin user tries to delete another user's account.
    /// This test simulates a scenario where the authenticated user
    /// tries to delete a different user's account, which should be forbidden.
    #[tokio::test]
    async fn test_delete_user_account_handler_id_mismatch() {
        // Create a mock AuthUser with a different ID
        let now = Utc::now();
        let auth_user = AuthUser {
            id: "user456".to_string(), // Different from request
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: Some(1),
            created_at: now,
            updated_at: now,
            csrf_token: "token".to_string(),
            csrf_via_header_verified: true,
            session_id: "session456".to_string(),
        };

        // Create a request payload with a different user ID
        let payload = DeleteUserRequest {
            user_id: "user123".to_string(), // Different from auth_user.id
        };

        // Call the handler
        let result = delete_user_account_handler(auth_user, ExtractJson(payload)).await;

        // Verify the result is an error with FORBIDDEN status
        assert!(result.is_err());
        if let Err((status, message)) = result {
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(message, "Cannot delete another user's account");
        }
    }

    // Note: Removed meaningless tests that only validated basic struct creation
    // and no-op router creation. These provided no validation value.
}
