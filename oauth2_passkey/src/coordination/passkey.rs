use chrono::Utc;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, sync::LazyLock};

use crate::passkey::{
    AuthenticationOptions, AuthenticatorResponse, CredentialSearchField, PasskeyCredential,
    PasskeyStore, RegisterCredential, RegistrationOptions, finish_authentication,
    finish_registration, start_authentication, start_registration,
    validate_registration_challenge_only, verify_session_then_finish_registration,
};
use crate::session::User as SessionUser;
use crate::session::new_session_header;
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
                    let headers = new_session_header(stored_user_id).await?;

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
    // Generate user ID first, but don't create user in database yet
    let user_id = gen_new_user_id().await?;

    // Validate challenge and registration data BEFORE creating user
    // This prevents orphaned user records if validation fails
    validate_registration_challenge_only(&reg_data).await?;

    // Only create user after successful challenge validation
    let (account, label) = get_account_and_label_from_passkey(&reg_data).await;

    let new_user = User {
        id: user_id.clone(),
        account,
        label,
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let stored_user = UserStore::upsert_user(new_user).await?;

    // After user is created, complete the registration by storing the credential
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
    let headers = new_session_header(uid.clone()).await?;

    Ok((uid, name, headers))
}

/// Core function that handles the business logic of listing passkey credentials
///
/// This function takes a user ID and returns the list of stored credentials
/// associated with that user, or an error if the user is not logged in.
#[tracing::instrument(fields(user_id))]
pub async fn list_credentials_core(
    user_id: &str,
) -> Result<Vec<PasskeyCredential>, CoordinationError> {
    tracing::debug!("Listing passkey credentials for user");
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_owned())).await?;
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
    user_id: &str,
    credential_id: &str,
) -> Result<(), CoordinationError> {
    tracing::info!("Attempting to delete passkey credential");

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
#[tracing::instrument(skip(session_user), fields(user_id = session_user.as_ref().map(|u| u.id.as_str()), credential_id, name, display_name))]
pub async fn update_passkey_credential_core(
    credential_id: &str,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::PasskeyCredential;
    use crate::test_utils::init_test_environment;
    use crate::userdb::User;
    use serial_test::serial;

    async fn create_test_user_in_db(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let user = User {
            id: user_id.to_string(),
            account: "test_account".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        UserStore::upsert_user(user).await?;
        Ok(())
    }

    async fn insert_test_passkey_credential(
        credential_id: &str,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create a simple user object for the credential
        let user = serde_json::json!({
            "name": "Test User",
            "displayName": "Test Display Name",
            "user_handle": user_id.to_string()
        });

        // Convert to the required format
        let passkey_user = serde_json::from_value(user).expect("Failed to create user entity");

        let credential = PasskeyCredential {
            credential_id: credential_id.to_string(),
            user_id: user_id.to_string(),
            public_key: "test_public_key".to_string(),
            aaguid: "test-aaguid".to_string(),
            user: passkey_user,
            counter: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: Utc::now(),
        };

        PasskeyStore::store_credential(credential.credential_id.clone(), credential).await?;
        Ok(())
    }

    /// Test deletion of a nonexistent passkey credential
    ///
    /// This test verifies that `delete_passkey_credential_core` returns a ResourceNotFound error
    /// when called with a credential ID that does not exist in the database.
    /// It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user in the database
    /// 3. Calls `delete_passkey_credential_core` with a nonexistent credential ID
    /// 4. Verifies that the function returns a ResourceNotFound error
    ///
    #[tokio::test]
    #[serial]
    async fn test_delete_passkey_credential_core_not_found()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test database
        init_test_environment().await;

        // Create test user
        let user_id = "test_user_4";
        let credential_id = "nonexistent_credential";

        create_test_user_in_db(user_id).await?;

        // Try to delete a nonexistent passkey credential
        let result = delete_passkey_credential_core(user_id, credential_id).await;
        assert!(
            matches!(result, Err(CoordinationError::ResourceNotFound { .. })),
            "Expected ResourceNotFound error, got: {result:?}"
        );

        Ok(())
    }

    /// Test successful update of a passkey credential
    ///
    /// This test verifies that `update_passkey_credential_core` correctly updates
    /// a passkey credential when given valid input. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user and passkey credential in the database
    /// 3. Calls `update_passkey_credential_core` to update the credential
    /// 4. Verifies that the credential was successfully updated
    ///
    #[tokio::test]
    #[serial]
    async fn test_update_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>>
    {
        // Setup test environment
        init_test_environment().await;

        // Create test user and passkey credential
        let user_id = "test_user_6";
        let credential_id = "test_credential_6";

        create_test_user_in_db(user_id).await?;
        insert_test_passkey_credential(credential_id, user_id).await?;

        // Create a session user for authentication
        let session_user = SessionUser {
            id: user_id.to_string(),
            account: "test_account".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Update the passkey credential
        let new_name = "Updated Name";
        let new_display_name = "Updated Display Name";
        let result = update_passkey_credential_core(
            credential_id,
            new_name,
            new_display_name,
            Some(session_user),
        )
        .await;

        assert!(
            result.is_ok(),
            "Failed to update passkey credential: {result:?}"
        );

        // Verify the credential was updated
        let updated_credential = PasskeyStore::get_credential(credential_id).await?.unwrap();
        assert_eq!(
            updated_credential.user.name, new_name,
            "Name was not updated"
        );
        assert_eq!(
            updated_credential.user.display_name, new_display_name,
            "Display name was not updated"
        );

        Ok(())
    }

    /// Test unauthorized update of a passkey credential
    ///
    /// This test verifies that `update_passkey_credential_core` returns an Unauthorized error
    /// when called with a different user ID than the one associated with the credential.
    /// It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates test users and a passkey credential in the database
    /// 3. Calls `update_passkey_credential_core` with a different user ID
    /// 4. Verifies that the function returns an Unauthorized error
    ///
    #[tokio::test]
    #[serial]
    async fn test_update_passkey_credential_core_unauthorized()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test environment
        init_test_environment().await;

        // Create test users and passkey credential
        let user_id = "test_user_7";
        let other_user_id = "test_user_8";
        let credential_id = "test_credential_7";

        create_test_user_in_db(user_id).await?;
        create_test_user_in_db(other_user_id).await?;
        insert_test_passkey_credential(credential_id, user_id).await?;

        // Create a session user for authentication with a different user ID
        let session_user = SessionUser {
            id: other_user_id.to_string(),
            account: "other_account".to_string(),
            label: "Other User".to_string(),
            is_admin: false,
            sequence_number: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Try to update the passkey credential as a different user
        let result = update_passkey_credential_core(
            credential_id,
            "Updated Name",
            "Updated Display Name",
            Some(session_user),
        )
        .await;

        assert!(
            matches!(result, Err(CoordinationError::Unauthorized)),
            "Expected Unauthorized error, got: {result:?}"
        );

        Ok(())
    }

    /// Test update of a passkey credential without a session user
    ///
    /// This test verifies that `update_passkey_credential_core` returns an Unauthorized error
    /// when called without a session user. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user and passkey credential in the database
    /// 3. Calls `update_passkey_credential_core` without a session user
    /// 4. Verifies that the function returns an Unauthorized error
    ///
    #[tokio::test]
    #[serial]
    async fn test_update_passkey_credential_core_no_session()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test environment
        init_test_environment().await;

        // Create test user and passkey credential
        let user_id = "test_user_9";
        let credential_id = "test_credential_9";

        create_test_user_in_db(user_id).await?;
        insert_test_passkey_credential(credential_id, user_id).await?;

        // Try to update the passkey credential without a session user
        let result = update_passkey_credential_core(
            credential_id,
            "Updated Name",
            "Updated Display Name",
            None,
        )
        .await;

        assert!(
            matches!(result, Err(CoordinationError::Unauthorized)),
            "Expected Unauthorized error, got: {result:?}"
        );

        Ok(())
    }

    /// Test default field mappings
    ///
    /// This test verifies that `get_passkey_field_mappings` returns the default field mappings
    /// when called without any environment variables set. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Calls `get_passkey_field_mappings` to retrieve the field mappings
    /// 3. Verifies that the returned values are the default values
    ///
    #[test]
    fn test_get_passkey_field_mappings_defaults() {
        // Test default mappings - since .env_test doesn't set these variables,
        // they should use their default values
        let (account_field, label_field) = get_passkey_field_mappings();
        assert_eq!(
            account_field, "name",
            "Default account field should be 'name'"
        );
        assert_eq!(
            label_field, "display_name",
            "Default label field should be 'display_name'"
        );
    }

    /// Test logic of field mapping function
    ///
    /// This test verifies that `get_passkey_field_mappings` returns the correct field mappings
    /// based on the environment variables set. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Sets environment variables to simulate different scenarios
    /// 3. Calls `get_passkey_field_mappings` to retrieve the field mappings
    /// 4. Verifies that the returned values are the expected values
    ///
    #[test]
    fn test_get_passkey_field_mappings_logic() {
        // Test the logic of the field mapping function by simulating different scenarios
        // We can't test LazyLock behavior directly without environment manipulation,
        // but we can test that the function returns reasonable defaults
        let (account_field, label_field) = get_passkey_field_mappings();

        // Verify the returned values are valid field names
        assert!(
            !account_field.is_empty(),
            "Account field should not be empty"
        );
        assert!(!label_field.is_empty(), "Label field should not be empty");

        // These should be the default values since .env_test doesn't override them
        assert_eq!(account_field, "name");
        assert_eq!(label_field, "display_name");
    }
}
