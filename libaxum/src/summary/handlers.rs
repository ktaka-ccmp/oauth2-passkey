use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, Json},
    routing::get,
};

use libauth::{list_accounts_core, list_credentials_core};
use liboauth2::OAUTH2_ROUTE_PREFIX;
use libpasskey::PASSKEY_ROUTE_PREFIX;
use libsession::User as SessionUser;

use super::templates::{TemplateAccount, TemplateCredential, UserSummaryTemplate};
use crate::AuthUser;
use serde_json::{Value, json};

/// Create a router for the user summary endpoints
pub fn router() -> Router<()> {
    Router::new()
        .route("/", get(user_summary))
        .route("/user-info", get(user_info))
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
        .map(|cred| {
            // Convert Vec<u8> to hex string representation for consistency
            let credential_id_hex = cred.credential_id.iter().fold(
                String::with_capacity(cred.credential_id.len() * 2),
                |mut acc, b| {
                    use std::fmt::Write;
                    let _ = write!(acc, "{:02x}", b);
                    acc
                },
            );

            TemplateCredential {
                credential_id: credential_id_hex,
                user_id: cred.user_id.clone(),
                user_name: cred.user.name.clone(),
                user_display_name: cred.user.display_name.clone(),
                user_handle: cred.user.user_handle.clone(),
                counter: cred.counter.to_string(),
                created_at: cred.created_at.to_string(),
                updated_at: cred.updated_at.to_string(),
            }
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
    let template = UserSummaryTemplate {
        user: auth_user,
        passkey_credentials,
        oauth2_accounts,
        auth_route_prefix: OAUTH2_ROUTE_PREFIX.as_str(),
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };

    // Render the template
    let html = template.render().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template rendering error: {:?}", e),
        )
    })?;

    Ok(Html(html))
}
