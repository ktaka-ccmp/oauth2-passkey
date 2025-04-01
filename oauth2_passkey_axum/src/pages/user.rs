use askama::Template;
use axum::{
    extract::Json as ExtractJson,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{Html, Json, Response},
};

use oauth2_passkey::{
    O2P_ROUTE_PREFIX, SessionUser, delete_user_account, list_accounts_core, list_credentials_core,
    obfuscate_user_id, update_user_account,
};

use crate::session::AuthUser;
use serde_json::{Value, json};

// Template-friendly version of StoredCredential for display
#[derive(Debug)]
pub struct TemplateCredential {
    pub credential_id: String,
    pub user_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_handle: String,
    pub counter: String,
    pub created_at: String,
    pub updated_at: String,
}

// Template-friendly version of OAuth2Account for display
#[derive(Debug)]
pub struct TemplateAccount {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub name: String,
    pub email: String,
    pub picture: String,
    pub metadata_str: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Template)]
#[template(path = "summary.j2")]
pub struct UserSummaryTemplate {
    pub user: AuthUser,
    pub passkey_credentials: Vec<TemplateCredential>,
    pub oauth2_accounts: Vec<TemplateAccount>,
    pub o2p_route_prefix: String,
    pub obfuscated_user_id: String,
}

impl UserSummaryTemplate {
    pub fn new(
        user: AuthUser,
        passkey_credentials: Vec<TemplateCredential>,
        oauth2_accounts: Vec<TemplateAccount>,
        o2p_route_prefix: String,
    ) -> Self {
        let obfuscated_user_id = obfuscate_user_id(&user.id);

        Self {
            user,
            passkey_credentials,
            oauth2_accounts,
            o2p_route_prefix,
            obfuscated_user_id,
        }
    }
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

/// Display a comprehensive summary page with user info, passkey credentials, and OAuth2 accounts
pub async fn summary(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
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

pub(super) async fn serve_summary_js() -> Response {
    let js_content = include_str!("../../static/summary.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap()
}

pub(super) async fn serve_summary_css() -> Response {
    let css_content = include_str!("../../static/summary.css");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css")
        .body(css_content.to_string().into())
        .unwrap()
}
