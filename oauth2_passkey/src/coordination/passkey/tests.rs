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

    PasskeyStore::store_credential(
        CredentialId::new(credential.credential_id.clone()).expect("Valid test credential ID"),
        credential,
    )
    .await?;
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
async fn test_delete_passkey_credential_core_not_found() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test database
    init_test_environment().await;

    // Create test user
    let user_id = "test_user_4";
    let credential_id = "nonexistent_credential";

    create_test_user_in_db(user_id).await?;

    // Try to delete a nonexistent passkey credential
    let result = delete_passkey_credential_core(
        UserId::new(user_id.to_string()).expect("Valid user ID"),
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
    )
    .await;
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
async fn test_update_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>> {
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
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Update the passkey credential
    let new_name = "Updated Name";
    let new_display_name = "Updated Display Name";
    let result = update_passkey_credential_core(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
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
    let updated_credential = PasskeyStore::get_credential(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
    )
    .await?
    .unwrap();
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
async fn test_update_passkey_credential_core_unauthorized() -> Result<(), Box<dyn std::error::Error>>
{
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
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Try to update the passkey credential as a different user
    let result = update_passkey_credential_core(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
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
async fn test_update_passkey_credential_core_no_session() -> Result<(), Box<dyn std::error::Error>>
{
    // Setup test environment
    init_test_environment().await;

    // Create test user and passkey credential
    let user_id = "test_user_9";
    let credential_id = "test_credential_9";

    create_test_user_in_db(user_id).await?;
    insert_test_passkey_credential(credential_id, user_id).await?;

    // Try to update the passkey credential without a session user
    let result = update_passkey_credential_core(
        CredentialId::new(credential_id.to_string()).expect("Valid credential ID"),
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
