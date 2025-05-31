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
use crate::session::new_session_header;
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
}

/// Core function that handles the business logic of starting registration with provided user info
///
/// This function takes an optional reference to a SessionUser, extracts username and displayname
/// from the request body, and returns registration options.
pub async fn handle_start_registration_core(
    auth_user: Option<&SessionUser>,
    body: RegistrationStartRequest,
) -> Result<RegistrationOptions, CoordinationError> {
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
pub async fn handle_finish_registration_core(
    auth_user: Option<&SessionUser>,
    reg_data: RegisterCredential,
) -> Result<(HeaderMap, String), CoordinationError> {
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
) -> Result<(String, String, HeaderMap), CoordinationError> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    // Verify the authentication and get the user ID and name
    let (uid, name) = finish_authentication(auth_response).await?;

    tracing::debug!("User ID: {:#?}", uid);

    // Create a session for the authenticated user
    let headers = new_session_header(uid.clone()).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::PasskeyCredential;
    use crate::userdb::User;

    async fn setup_test_db() -> Result<(), Box<dyn std::error::Error>> {
        // Use a consistent prefix for all tests to ensure tables are properly created and accessed
        let _db_path = "/tmp/test_passkey_fixed.db";
        let db_url = "sqlite:/tmp/test_passkey_fixed.db";
        let table_prefix = "test_o2p_fixed_";

        // Set environment variables for testing
        // Using unsafe block as env::set_var is not thread-safe
        unsafe {
            std::env::set_var("GENERIC_DATA_STORE_TYPE", "sqlite");
            std::env::set_var("GENERIC_DATA_STORE_URL", db_url);
            std::env::set_var("DB_TABLE_PREFIX", table_prefix);
            std::env::set_var("GENERIC_CACHE_STORE_TYPE", "memory");
            std::env::set_var("GENERIC_CACHE_STORE_URL", "memory://test");
        }

        // Initialize the database
        crate::userdb::init().await?;
        crate::passkey::init().await?;

        Ok(())
    }

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

    #[tokio::test]
    async fn test_delete_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>>
    {
        // Setup test database
        setup_test_db().await?;

        // Create test user and passkey credential
        let user_id = "test_user_1";
        let credential_id = "test_credential_1";

        create_test_user_in_db(user_id).await?;
        insert_test_passkey_credential(credential_id, user_id).await?;

        // Delete the passkey credential
        let result = delete_passkey_credential_core(user_id, credential_id).await;
        assert!(
            result.is_ok(),
            "Failed to delete passkey credential: {:?}",
            result
        );

        // Verify the credential was deleted
        let credentials = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
            credential_id.to_string(),
        ))
        .await?;
        assert!(credentials.is_empty(), "Passkey credential was not deleted");

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_passkey_credential_core_unauthorized()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test database
        setup_test_db().await?;

        // Create test users and passkey credential
        let user_id = "test_user_2";
        let other_user_id = "test_user_3";
        let credential_id = "test_credential_2";

        create_test_user_in_db(user_id).await?;
        create_test_user_in_db(other_user_id).await?;
        insert_test_passkey_credential(credential_id, user_id).await?;

        // Try to delete the passkey credential as a different user
        let result = delete_passkey_credential_core(other_user_id, credential_id).await;
        assert!(
            matches!(result, Err(CoordinationError::Unauthorized)),
            "Expected Unauthorized error, got: {:?}",
            result
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_passkey_credential_core_not_found()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test database
        setup_test_db().await?;

        // Create test user
        let user_id = "test_user_4";
        let credential_id = "nonexistent_credential";

        create_test_user_in_db(user_id).await?;

        // Try to delete a nonexistent passkey credential
        let result = delete_passkey_credential_core(user_id, credential_id).await;
        assert!(
            matches!(result, Err(CoordinationError::ResourceNotFound { .. })),
            "Expected ResourceNotFound error, got: {:?}",
            result
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_list_credentials_core() -> Result<(), Box<dyn std::error::Error>> {
        // Setup test database
        setup_test_db().await?;

        // Create test user and passkey credentials
        let user_id = "test_user_5";
        let credential_id1 = "test_credential_5_1";
        let credential_id2 = "test_credential_5_2";

        create_test_user_in_db(user_id).await?;
        insert_test_passkey_credential(credential_id1, user_id).await?;
        insert_test_passkey_credential(credential_id2, user_id).await?;

        // List the passkey credentials
        let credentials = list_credentials_core(user_id).await?;
        assert_eq!(
            credentials.len(),
            2,
            "Expected 2 passkey credentials, got: {}",
            credentials.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>>
    {
        // Setup test database
        setup_test_db().await?;

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
            "Failed to update passkey credential: {:?}",
            result
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

    #[tokio::test]
    async fn test_update_passkey_credential_core_unauthorized()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test database
        setup_test_db().await?;

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
            "Expected Unauthorized error, got: {:?}",
            result
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_passkey_credential_core_no_session()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test database
        setup_test_db().await?;

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
            "Expected Unauthorized error, got: {:?}",
            result
        );

        Ok(())
    }
}
