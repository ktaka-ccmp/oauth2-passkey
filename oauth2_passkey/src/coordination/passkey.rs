use chrono::Utc;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;

use crate::passkey::{
    AuthenticationOptions, AuthenticatorResponse, CredentialSearchField, PasskeyCredential,
    PasskeyStore, RegisterCredential, RegistrationOptions, finish_authentication,
    finish_registration, start_authentication, start_registration,
    verify_session_then_finish_registration,
};
use crate::session::User as SessionUser;
use crate::session::{renew_session_header, verify_context_token_and_page};
use crate::userdb::{User, UserStore};

use super::errors::CoordinationError;
use super::user::gen_new_user_id;

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
) -> Result<RegistrationOptions, CoordinationError> {
    match body.mode {
        RegistrationMode::AddToExistingUser => {
            let auth_user = auth_user.ok_or(CoordinationError::Unauthorized.log())?;

            verify_context_token_and_page(
                request_headers,
                body.page_context.as_ref(),
                &auth_user.id,
            )?;

            let result =
                start_registration(Some(auth_user.clone()), body.username, body.displayname)
                    .await?;
            Ok(result)
        }
        RegistrationMode::NewUser => {
            let result = start_registration(None, body.username, body.displayname).await?;
            Ok(result)
        }
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
) -> Result<(HeaderMap, String), CoordinationError> {
    match auth_user {
        Some(session_user) => {
            tracing::debug!("handle_finish_registration_core: User: {:#?}", session_user);

            verify_context_token_and_page(
                request_headers,
                reg_data.page_context.as_ref(),
                &session_user.id,
            )?;

            // Handle authenticated user registration
            let message =
                verify_session_then_finish_registration(session_user.clone(), reg_data).await?;

            Ok((HeaderMap::new(), message))
        }
        None => {
            let result = create_user_then_finish_registration(reg_data).await;

            match result {
                Ok((message, stored_user_id)) => {
                    // Create session with the user_id
                    let headers = renew_session_header(stored_user_id).await?;

                    Ok((headers, message))
                }
                Err(err) => Err(err),
            }
        }
    }
}

async fn create_user_then_finish_registration(
    reg_data: RegisterCredential,
) -> Result<(String, String), CoordinationError> {
    let (account, label) = get_account_and_label_from_passkey(&reg_data).await;

    let new_user = User {
        id: gen_new_user_id().await?,
        account,
        label,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let stored_user = UserStore::upsert_user(new_user.clone()).await?;

    let message = finish_registration(&stored_user.id, &reg_data).await?;

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
) -> Result<AuthenticationOptions, CoordinationError> {
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
    Ok(start_authentication(username).await?)
}

/// Core function that handles the business logic of finishing authentication
///
/// This function verifies the authentication response, creates a session for the
/// authenticated user, and returns the user ID, name, and session headers.
pub async fn handle_finish_authentication_core(
    auth_response: AuthenticatorResponse,
) -> Result<(String, String, HeaderMap), CoordinationError> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    // Verify the authentication and get the user ID and name
    let (uid, name) = finish_authentication(auth_response).await?;

    tracing::debug!("User ID: {:#?}", uid);

    // Create a session for the authenticated user
    let headers = renew_session_header(uid.clone()).await?;

    Ok((uid, name, headers))
}

/// Core function that handles the business logic of listing passkey credentials
///
/// This function takes an optional reference to a SessionUser and returns the list of stored credentials
/// associated with that user, or an error if the user is not logged in.
pub async fn list_credentials_core(
    user: Option<&SessionUser>,
) -> Result<Vec<PasskeyCredential>, CoordinationError> {
    // Ensure user is authenticated
    let user = user.ok_or_else(|| CoordinationError::Unauthorized.log())?;

    tracing::trace!("list_credentials_core: User: {:#?}", user);
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user.id.to_owned())).await?;
    Ok(credentials)
}

/// Delete a passkey credential for a user
///
/// This function checks that the credential belongs to the authenticated user
/// before deleting it to prevent unauthorized deletions.
pub async fn delete_passkey_credential_core(
    user: Option<&SessionUser>,
    credential_id: &str,
) -> Result<(), CoordinationError> {
    // Ensure user is authenticated
    let user = user.ok_or_else(|| CoordinationError::Unauthorized.log())?;

    tracing::debug!("delete_passkey_credential_core: User: {:#?}", user);
    tracing::debug!("Attempting to delete credential with ID: {}", credential_id);

    let credential = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
        credential_id.to_owned(),
    ))
    .await?
    .into_iter()
    .next()
    .ok_or(
        CoordinationError::ResourceNotFound {
            resource_type: "Passkey".to_string(),
            resource_id: credential_id.to_string(),
        }
        .log(),
    )?;

    // Verify the credential belongs to the authenticated user
    if credential.user_id != user.id {
        return Err(CoordinationError::Unauthorized.log());
    }

    // Delete the credential using the raw credential ID format from the database
    PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
        credential.credential_id.clone(),
    ))
    .await?;

    tracing::debug!("Successfully deleted credential");

    Ok(())
}
