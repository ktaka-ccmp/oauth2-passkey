use chrono::Utc;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, sync::LazyLock};

use crate::passkey::{
    AuthenticationOptions, AuthenticatorResponse, CredentialId, CredentialSearchField,
    PasskeyCredential, PasskeyStore, RegisterCredential, RegistrationOptions, commit_registration,
    finish_authentication, prepare_registration_storage, start_authentication, start_registration,
    validate_registration_challenge, verify_session_then_finish_registration,
};
use crate::session::{User as SessionUser, UserId, new_session_header};
use crate::userdb::{User, UserStore};

use super::errors::CoordinationError;
use super::user::gen_new_user_id;

/// Passkey user account field mapping configuration
static PASSKEY_USER_ACCOUNT_FIELD: LazyLock<String> =
    LazyLock::new(|| env::var("PASSKEY_USER_ACCOUNT_FIELD").unwrap_or_else(|_| "name".to_string()));

/// Passkey user label field mapping configuration
static PASSKEY_USER_LABEL_FIELD: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_USER_LABEL_FIELD").unwrap_or_else(|_| "display_name".to_string())
});

/// Get the configured Passkey field mappings or defaults
fn get_passkey_field_mappings() -> (String, String) {
    (
        PASSKEY_USER_ACCOUNT_FIELD.clone(),
        PASSKEY_USER_LABEL_FIELD.clone(),
    )
}

/// Mode of registration operation to explicitly indicate user intent.
///
/// This enum defines the available modes for passkey registration, determining
/// whether a new user account should be created or a passkey should be added to
/// an existing authenticated user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// Adding a passkey to an existing user (requires authentication).
    ///
    /// This mode is used when an authenticated user wants to add another
    /// passkey to their account, such as registering a new device or
    /// security key as a backup.
    AddToUser,

    /// Creating a new user with a passkey (no authentication required).
    ///
    /// This mode is used for new user registration, where the user doesn't
    /// have an existing account and wants to create one using a passkey
    /// as their authentication method.
    CreateUser,
}

/// Request for starting passkey registration with explicit mode.
///
/// This struct represents the data needed to begin a passkey registration process.
/// It specifies the user information and the registration mode (whether adding a
/// new passkey to an existing user or creating a new user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    /// Username for the passkey registration (login identifier)
    pub username: String,
    /// Display name for the passkey registration (user-friendly name)
    pub displayname: String,
    /// Mode of registration (add to existing user or create new user)
    pub mode: RegistrationMode,
}

/// Core function that handles the business logic of starting registration with provided user info
///
/// This function takes an optional reference to a SessionUser, extracts username and displayname
/// from the request body, and returns registration options.
#[tracing::instrument(skip(auth_user), fields(user_id = auth_user.as_ref().map(|u| u.id.as_str()), username = %body.username, display_name = %body.displayname, mode = ?body.mode))]
pub async fn handle_start_registration_core(
    auth_user: Option<&SessionUser>,
    body: RegistrationStartRequest,
) -> Result<RegistrationOptions, CoordinationError> {
    tracing::info!("Starting passkey registration flow");
    match body.mode {
        RegistrationMode::AddToUser => {
            let auth_user = match auth_user {
                Some(user) => user,
                None => return Err(CoordinationError::Unauthorized.log()),
            };

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
#[tracing::instrument(skip(auth_user, reg_data), fields(user_id = auth_user.as_ref().map(|u| u.id.as_str())))]
pub async fn handle_finish_registration_core(
    auth_user: Option<&SessionUser>,
    reg_data: RegisterCredential,
) -> Result<(HeaderMap, String), CoordinationError> {
    tracing::info!("Finishing passkey registration flow");
    match auth_user {
        Some(session_user) => {
            tracing::debug!("handle_finish_registration_core: User: {:#?}", session_user);

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
                    let headers = new_session_header(UserId::new(stored_user_id)).await?;

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
    // We avoid calling finish_registration() directly since it expects an existing user,
    // forcing us to create users before validation (which leaves orphaned records on failure).
    // Instead, we use finish_registration()'s 3 constituent functions: validate_registration_challenge(),
    // prepare_registration_storage(), and commit_registration() with user creation in between.

    // Step 1: Pure validation (no user_id needed, no side effects)
    // This prevents orphaned user records if validation fails
    let validated_data = validate_registration_challenge(&reg_data).await?;
    let user_handle = validated_data.user_handle.clone();

    // Step 2: Create user after successful challenge validation
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

    let stored_user = UserStore::upsert_user(new_user).await?;

    // Step 3: Prepare credential storage (cleanup existing credentials)
    let credential =
        prepare_registration_storage(UserId::new(stored_user.id.clone()), validated_data).await?;

    // Step 4: Atomic commit (store credential + cleanup challenge)
    let message = commit_registration(credential, &user_handle).await?;

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
#[tracing::instrument(skip(body), fields(username))]
pub async fn handle_start_authentication_core(
    body: &Value,
) -> Result<AuthenticationOptions, CoordinationError> {
    tracing::info!("Starting passkey authentication flow");
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

    // Record username in the tracing span
    if let Some(ref username) = username {
        tracing::Span::current().record("username", username);
    }

    // Start the authentication process
    Ok(start_authentication(username).await?)
}

/// Core function that handles the business logic of finishing authentication
///
/// This function verifies the authentication response, creates a session for the
/// authenticated user, and returns the user ID, name, and session headers.
#[tracing::instrument(skip(auth_response), fields(user_id))]
pub async fn handle_finish_authentication_core(
    auth_response: AuthenticatorResponse,
) -> Result<(String, String, HeaderMap), CoordinationError> {
    tracing::info!("Finishing passkey authentication flow");
    tracing::debug!("Auth response: {:#?}", auth_response);

    // Verify the authentication and get the user ID and name
    let (uid, name) = finish_authentication(auth_response).await?;

    // Record user_id in the tracing span
    tracing::Span::current().record("user_id", &uid);
    tracing::info!(user_id = %uid, user_name = %name, "Passkey authentication successful");
    tracing::debug!("User ID: {:#?}", uid);

    // Create a session for the authenticated user
    let headers = new_session_header(UserId::new(uid.clone())).await?;

    Ok((uid, name, headers))
}

/// Core function that handles the business logic of listing passkey credentials
///
/// This function takes a user ID and returns the list of stored credentials
/// associated with that user, or an error if the user is not logged in.
#[tracing::instrument(fields(user_id))]
pub async fn list_credentials_core(
    user_id: UserId,
) -> Result<Vec<PasskeyCredential>, CoordinationError> {
    tracing::debug!("Listing passkey credentials for user");
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id)).await?;
    tracing::info!(
        credential_count = credentials.len(),
        "Retrieved passkey credentials"
    );
    Ok(credentials)
}

/// Delete a passkey credential for a user
///
/// This function checks that the credential belongs to the authenticated user
/// before deleting it to prevent unauthorized deletions.
#[tracing::instrument(fields(user_id, credential_id))]
pub async fn delete_passkey_credential_core(
    user_id: UserId,
    credential_id: CredentialId,
) -> Result<(), CoordinationError> {
    tracing::info!("Attempting to delete passkey credential");

    let credential = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
        credential_id.clone(),
    ))
    .await?
    .into_iter()
    .next()
    .ok_or(
        CoordinationError::ResourceNotFound {
            resource_type: "Passkey".to_string(),
            resource_id: credential_id.as_str().to_string(),
        }
        .log(),
    )?;

    // Verify the credential belongs to the authenticated user
    if credential.user_id != user_id.as_str() {
        return Err(CoordinationError::Unauthorized.log());
    }

    // Delete the credential using the raw credential ID format from the database
    PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(credential_id)).await?;

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
#[tracing::instrument(skip(session_user), fields(user_id = session_user.as_ref().map(|u| u.id.as_str()), credential_id, name, display_name))]
pub async fn update_passkey_credential_core(
    credential_id: CredentialId,
    name: &str,
    display_name: &str,
    session_user: Option<SessionUser>,
) -> Result<serde_json::Value, CoordinationError> {
    tracing::info!("Updating passkey credential details");
    // Ensure the user is authenticated
    let user_id = match session_user {
        Some(user) => user.id,
        None => {
            return Err(CoordinationError::Unauthorized.log());
        }
    };

    // Get the credential to verify ownership
    let credential = match PasskeyStore::get_credential(credential_id.clone()).await? {
        Some(cred) => cred,
        None => {
            return Err(CoordinationError::ResourceNotFound {
                resource_type: "Passkey".to_string(),
                resource_id: credential_id.as_str().to_string(),
            });
        }
    };

    // Verify that the credential belongs to the authenticated user
    if credential.user_id != user_id {
        return Err(CoordinationError::Unauthorized.log());
    }

    // Update the credential in the database
    PasskeyStore::update_credential(credential_id.clone(), name, display_name).await?;

    // Get the updated credential
    let updated_credential = match PasskeyStore::get_credential(credential_id.clone()).await? {
        Some(cred) => cred,
        None => {
            return Err(CoordinationError::ResourceNotFound {
                resource_type: "Passkey".to_string(),
                resource_id: credential_id.as_str().to_string(),
            });
        }
    };

    tracing::debug!("Successfully updated credential");

    // Return the credential information in JSON format
    Ok(serde_json::json!({
        "credentialId": credential_id.as_str(),
        "name": updated_credential.user.name,
        "displayName": updated_credential.user.display_name,
        "userHandle": updated_credential.user.user_handle,
    }))
}

#[cfg(test)]
mod tests;
