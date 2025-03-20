use chrono::Utc;
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;

use crate::passkey::{
    AuthenticationOptions, AuthenticatorResponse, CredentialSearchField, PasskeyStore,
    RegisterCredential, RegistrationOptions, StoredCredential, finish_authentication,
    finish_registration, start_authentication, start_registration,
    verify_session_then_finish_registration,
};
use crate::session::{User as SessionUser, create_session_with_uid};
use crate::userdb::{User, UserStore};

use super::context_token::{add_context_token_to_header, verify_context_token_and_page};
use super::errors::AuthError;
use super::user_flow::gen_new_user_id;

/// Get the configured Passkey field mappings or defaults
fn get_passkey_field_mappings() -> (String, String) {
    (
        env::var("PASSKEY_USER_ACCOUNT_FIELD").unwrap_or_else(|_| "name".to_string()),
        env::var("PASSKEY_USER_LABEL_FIELD").unwrap_or_else(|_| "display_name".to_string()),
    )
}

/// Mode of registration operation to explicitly indicate user intent
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// Adding a passkey to an existing user (requires authentication)
    AddToExistingUser,
    /// Creating a new user with a passkey (no authentication required)
    NewUser,
}

/// Request for starting passkey registration with explicit mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub displayname: String,
    pub mode: RegistrationMode,
    /// Optional page context for session boundary verification
    #[serde(default)]
    pub page_context: Option<String>,
}

/// Core function that handles the business logic of starting registration with provided user info
///
/// This function takes an optional reference to a SessionUser, extracts username and displayname
/// from the request body, and returns registration options.
pub async fn handle_start_registration_core(
    auth_user: Option<&SessionUser>,
    request_headers: &HeaderMap,
    body: RegistrationStartRequest,
) -> Result<RegistrationOptions, (StatusCode, String)> {
    match body.mode {
        RegistrationMode::AddToExistingUser => {
            // let auth_user_id = auth_user.map(|u| u.id).unwrap();
            let Some(auth_user) = auth_user else {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Missing authentication user".to_string(),
                ));
            };

            verify_context_token_and_page(
                request_headers,
                body.page_context.as_ref(),
                &auth_user.id,
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            start_registration(Some(auth_user.clone()), body.username, body.displayname)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
        RegistrationMode::NewUser => start_registration(None, body.username, body.displayname)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Core function that handles the business logic of finishing registration
///
/// This function takes an optional reference to a SessionUser and registration data,
/// and either registers a new credential for an existing user or creates a new user
/// with the credential.
pub async fn handle_finish_registration_core(
    auth_user: Option<&SessionUser>,
    request_headers: &HeaderMap,
    reg_data: RegisterCredential,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    match auth_user {
        Some(session_user) => {
            tracing::debug!("handle_finish_registration_core: User: {:#?}", session_user);

            verify_context_token_and_page(
                request_headers,
                reg_data.page_context.as_ref(),
                &session_user.id,
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            // Handle authenticated user registration
            let message = verify_session_then_finish_registration(session_user.clone(), reg_data)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            Ok((HeaderMap::new(), message))
        }
        None => {
            let result = create_user_then_finish_registration(reg_data).await;

            match result {
                Ok((message, stored_user_id)) => {
                    // Create session with the user_id
                    let mut headers = create_session_with_uid(&stored_user_id)
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

                    // Add context token cookie for session boundary protection
                    add_context_token_to_header(&stored_user_id, &mut headers);

                    Ok((headers, message))
                }
                Err(err) => Err((StatusCode::BAD_REQUEST, err.to_string())),
            }
        }
    }
}

async fn create_user_then_finish_registration(
    reg_data: RegisterCredential,
) -> Result<(String, String), AuthError> {
    let (account, label) = get_account_and_label_from_passkey(&reg_data).await;

    let new_user = User {
        id: gen_new_user_id().await?,
        account,
        label,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let stored_user = UserStore::upsert_user(new_user.clone())
        .await
        .map_err(AuthError::User)?;

    let message = finish_registration(&stored_user.id, &reg_data)
        .await
        .map_err(AuthError::Passkey)?;

    Ok((message, stored_user.id))
}

async fn get_account_and_label_from_passkey(reg_data: &RegisterCredential) -> (String, String) {
    // Get user name from registration data with fallback mechanism
    let (name, display_name) = reg_data.get_registration_user_fields().await;

    // Get field mappings from configuration
    let (account_field, label_field) = get_passkey_field_mappings();

    // Map fields based on configuration
    let account = match account_field.as_str() {
        "name" => name.clone(),
        "display_name" => display_name.clone(),
        _ => name.clone(), // Default to name if invalid mapping
    };

    let label = match label_field.as_str() {
        "name" => name.clone(),
        "display_name" => display_name.clone(),
        _ => display_name.clone(), // Default to display_name if invalid mapping
    };
    (account, label)
}

/// Core function that handles the business logic of starting authentication
///
/// This function extracts the username from the request body and starts the
/// authentication process.
pub async fn handle_start_authentication_core(
    body: &Value,
) -> Result<AuthenticationOptions, (StatusCode, String)> {
    // Extract username from the request body
    let username = if body.is_object() {
        body.get("username")
            .and_then(|v| v.as_str())
            .map(String::from)
    } else if body.is_string() {
        Some(body.as_str().unwrap().to_string()) // Directly use the string
    } else {
        None
    };

    // Start the authentication process
    start_authentication(username).await.map_err(|e| {
        tracing::debug!("Error: {:#?}", e);
        (StatusCode::BAD_REQUEST, e.to_string())
    })
}

/// Core function that handles the business logic of finishing authentication
///
/// This function verifies the authentication response, creates a session for the
/// authenticated user, and returns the user ID, name, and session headers.
pub async fn handle_finish_authentication_core(
    auth_response: AuthenticatorResponse,
) -> Result<(String, String, HeaderMap), (StatusCode, String)> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    // Verify the authentication and get the user ID and name
    let (uid, name) = finish_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    tracing::debug!("User ID: {:#?}", uid);

    // Create a session for the authenticated user
    let mut headers = create_session_with_uid(&uid)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Add context token headers for session boundary protection
    add_context_token_to_header(&uid, &mut headers);

    Ok((uid, name, headers))
}

/// Core function that handles the business logic of listing passkey credentials
///
/// This function takes an optional reference to a SessionUser and returns the list of stored credentials
/// associated with that user, or an error if the user is not logged in.
pub async fn list_credentials_core(
    user: Option<&SessionUser>,
) -> Result<Vec<StoredCredential>, (StatusCode, String)> {
    match user {
        Some(user) => {
            tracing::debug!("list_credentials_core: User: {:#?}", user);
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user.id.to_owned()))
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
        }
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
    }
}

/// Delete a passkey credential for a user
///
/// This function checks that the credential belongs to the authenticated user
/// before deleting it to prevent unauthorized deletions.
pub async fn delete_passkey_credential_core(
    user: Option<&SessionUser>,
    credential_id: &str,
) -> Result<(), (StatusCode, String)> {
    // Ensure user is authenticated
    let user = match user {
        Some(user) => user,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "User not authenticated".to_string(),
            ));
        }
    };

    tracing::debug!("Attempting to delete credential with ID: {}", credential_id);

    let credential = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
        credential_id.to_owned(),
    ))
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .next()
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("Credential not found with ID: {}", credential_id),
    ))?;

    // Verify the credential belongs to the authenticated user
    if credential.user_id != user.id {
        return Err((
            StatusCode::FORBIDDEN,
            "Not authorized to delete this credential".to_string(),
        ));
    }

    // Delete the credential using the raw credential ID format from the database
    PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
        credential.credential_id.clone(),
    ))
    .await
    .map_err(|e| {
        tracing::error!("Failed to delete credential: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::debug!("Successfully deleted credential");

    Ok(())
}
