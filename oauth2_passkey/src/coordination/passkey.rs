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
use crate::session::{new_session_header, verify_context_token_and_page};
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
    AddToUser,
    /// Creating a new user with a passkey (no authentication required)
    CreateUser,
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
        RegistrationMode::AddToUser => {
            let auth_user = match auth_user {
                Some(user) => user,
                None => return Err(CoordinationError::Unauthorized.log()),
            };

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
        RegistrationMode::CreateUser => {
            match auth_user {
                Some(_) => return Err(CoordinationError::UnexpectedlyAuthorized.log()),
                None => {
                    tracing::trace!("handle_start_registration_core: Create User");
                }
            };

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
                    let headers =
                        new_session_header(stored_user_id, request_headers.clone()).await?;

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
        is_admin: false,
        sequence_number: None,
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
    headers: HeaderMap,
) -> Result<(String, String, HeaderMap), CoordinationError> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    // Verify the authentication and get the user ID and name
    let (uid, name) = finish_authentication(auth_response).await?;

    tracing::debug!("User ID: {:#?}", uid);

    // Create a session for the authenticated user
    let headers = new_session_header(uid.clone(), headers).await?;

    Ok((uid, name, headers))
}

/// Core function that handles the business logic of listing passkey credentials
///
/// This function takes a user ID and returns the list of stored credentials
/// associated with that user, or an error if the user is not logged in.
pub async fn list_credentials_core(
    user_id: &str,
) -> Result<Vec<PasskeyCredential>, CoordinationError> {
    tracing::trace!("list_credentials_core: User ID: {:#?}", user_id);
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_owned())).await?;
    Ok(credentials)
}

/// Delete a passkey credential for a user
///
/// This function checks that the credential belongs to the authenticated user
/// before deleting it to prevent unauthorized deletions.
pub async fn delete_passkey_credential_core(
    user_id: &str,
    credential_id: &str,
) -> Result<(), CoordinationError> {
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
    if credential.user_id != user_id {
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

/// Update the name and display name of a passkey credential
///
/// This function updates the name and display name fields of a passkey credential
/// and returns the updated credential information.
///
/// # Arguments
/// * `credential_id` - The ID of the credential to update
/// * `name` - The new name for the credential
/// * `display_name` - The new display name for the credential
/// * `session_user` - The authenticated user session
///
/// # Returns
/// * The updated credential information in a Result
pub async fn update_passkey_credential_core(
    credential_id: &str,
    name: &str,
    display_name: &str,
    session_user: Option<SessionUser>,
) -> Result<serde_json::Value, CoordinationError> {
    // Ensure the user is authenticated
    let user_id = match session_user {
        Some(user) => user.id,
        None => {
            return Err(CoordinationError::Unauthorized.log());
        }
    };

    // Get the credential to verify ownership
    let credential = match PasskeyStore::get_credential(credential_id).await? {
        Some(cred) => cred,
        None => {
            return Err(CoordinationError::ResourceNotFound {
                resource_type: "Passkey".to_string(),
                resource_id: credential_id.to_string(),
            });
        }
    };

    // Verify that the credential belongs to the authenticated user
    if credential.user_id != user_id {
        return Err(CoordinationError::Unauthorized.log());
    }

    // Update the credential in the database
    PasskeyStore::update_credential(credential_id, name, display_name).await?;

    // Get the updated credential
    let updated_credential = match PasskeyStore::get_credential(credential_id).await? {
        Some(cred) => cred,
        None => {
            return Err(CoordinationError::ResourceNotFound {
                resource_type: "Passkey".to_string(),
                resource_id: credential_id.to_string(),
            });
        }
    };

    tracing::debug!("Successfully updated credential");

    // Return the credential information in JSON format
    Ok(serde_json::json!({
        "credentialId": credential_id,
        "name": updated_credential.user.name,
        "displayName": updated_credential.user.display_name,
        "userHandle": updated_credential.user.user_handle,
    }))
}
