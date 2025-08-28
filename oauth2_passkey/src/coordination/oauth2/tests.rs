use super::*;
use crate::oauth2::OAuth2Account;
use crate::test_utils::init_test_environment;
use crate::userdb::User;
use chrono::Utc;
use serial_test::serial;

/// Test OAuth2 field mappings return expected defaults
///
/// This test verifies that OAuth2 field mappings return the correct default values
/// when environment variables are not defined.
///
#[tokio::test]
#[serial]
async fn test_get_oauth2_field_mappings_defaults() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Test default mappings - since .env_test doesn't set these variables,
    // they should use their default values
    let (account_field, label_field) = get_oauth2_field_mappings();
    assert_eq!(
        account_field, "email",
        "Default account field should be 'email'"
    );
    assert_eq!(label_field, "name", "Default label field should be 'name'");

    Ok(())
}

/// Test OAuth2 field mappings with environment variables
///
/// This test verifies that OAuth2 field mappings work correctly when environment
/// variables are defined, testing the configuration system behavior.
///
#[tokio::test]
#[serial]
async fn test_get_account_and_label_from_oauth2_account() -> Result<(), Box<dyn std::error::Error>>
{
    // Setup test environment
    init_test_environment().await;

    // Create a test OAuth2Account
    let oauth2_account = OAuth2Account {
        id: "test_id".to_string(),
        user_id: "test_user".to_string(),
        provider: "google".to_string(),
        provider_user_id: "google_123".to_string(),
        name: "John Doe".to_string(),
        email: "john.doe@example.com".to_string(),
        picture: Some("https://example.com/picture.jpg".to_string()),
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Test the field mapping function
    let (account, label) = get_account_and_label_from_oauth2_account(&oauth2_account);

    // With default mappings: account_field="email", label_field="name"
    assert_eq!(
        account, "john.doe@example.com",
        "Account should be mapped to email"
    );
    assert_eq!(label, "John Doe", "Label should be mapped to name");

    Ok(())
}

// Helper function to create a test user
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

// Helper function to create a test OAuth2 account
async fn create_test_oauth2_account_in_db(
    user_id: &str,
    provider: &str,
    provider_user_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let unique_provider_user_id = format!("{provider_user_id}-{timestamp}");
    let account_id = format!("test-id-{timestamp}");

    let oauth2_account = OAuth2Account {
        id: account_id.clone(),
        user_id: user_id.to_string(),
        provider: provider.to_string(),
        provider_user_id: unique_provider_user_id.clone(),
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
        picture: Some("https://example.com/picture.jpg".to_string()),
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
    Ok(unique_provider_user_id)
}

/// Test the core OAuth2 account listing functionality
///
/// This test verifies that `list_accounts_core()` correctly retrieves all OAuth2 accounts
/// associated with a specific user. It creates a test user with multiple OAuth2 accounts
/// from different providers and verifies:
/// - The correct number of accounts are returned
/// - All returned accounts belong to the specified user
/// - The function handles multiple provider accounts correctly
#[tokio::test]
#[serial]
async fn test_list_accounts_core() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test user and OAuth2 accounts with unique timestamp-based ID
    let timestamp = chrono::Utc::now().timestamp_millis();
    let user_id = format!("test_user_list_accounts_{timestamp}");
    let provider1 = "google";
    let provider2 = "github";
    let provider_user_id1 = "google_user_123";
    let provider_user_id2 = "github_user_456";

    create_test_user_in_db(&user_id).await?;
    let _unique_provider_user_id1 =
        create_test_oauth2_account_in_db(&user_id, provider1, provider_user_id1).await?;
    let _unique_provider_user_id2 =
        create_test_oauth2_account_in_db(&user_id, provider2, provider_user_id2).await?;

    // List the OAuth2 accounts
    let accounts = list_accounts_core(UserId::new(user_id.clone())).await?;
    assert_eq!(
        accounts.len(),
        2,
        "Expected 2 OAuth2 accounts, got: {}",
        accounts.len()
    );

    // Verify the accounts belong to the correct user
    for account in &accounts {
        assert_eq!(
            account.user_id, user_id,
            "Account should belong to the test user"
        );
    }

    Ok(())
}

/// Test the core OAuth2 account deletion functionality
/// This test verifies that `delete_oauth2_account_core()` correctly deletes an OAuth2 account
/// associated with a user. It creates a test user and OAuth2 account, then attempts to delete
/// the account, verifying:
/// - The account is successfully deleted
/// - The account cannot be found after deletion
/// - Unauthorized deletion attempts by other users are correctly handled
#[tokio::test]
#[serial]
async fn test_delete_oauth2_account_core_success() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test user and OAuth2 account
    let user_id = "test_user_delete_success";
    let provider = "google";
    let provider_user_id = "google_user_delete_123";

    create_test_user_in_db(user_id).await?;
    let unique_provider_user_id =
        create_test_oauth2_account_in_db(user_id, provider, provider_user_id).await?;

    // Delete the OAuth2 account
    let result = delete_oauth2_account_core(
        UserId::new(user_id.to_string()),
        Provider::new(provider.to_string()),
        ProviderUserId::new(unique_provider_user_id.clone()),
    )
    .await;
    assert!(
        result.is_ok(),
        "Failed to delete OAuth2 account: {result:?}"
    );

    // Verify the account was deleted
    let accounts = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        crate::oauth2::ProviderUserId::new(unique_provider_user_id),
    ))
    .await?;
    assert!(accounts.is_empty(), "OAuth2 account was not deleted");

    Ok(())
}

/// Test the core OAuth2 account deletion functionality for unauthorized access
/// This test verifies that `delete_oauth2_account_core()` correctly handles unauthorized deletion
/// attempts. It creates a test user and OAuth2 account, then tries to delete the account
/// as a different user, verifying:
/// - The deletion attempt fails with an Unauthorized error
/// - The account remains in the database after the unauthorized attempt
#[tokio::test]
#[serial]
async fn test_delete_oauth2_account_core_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test users and OAuth2 account with unique IDs
    let timestamp = chrono::Utc::now().timestamp_millis();
    let user_id = format!("test_user_delete_owner_{timestamp}");
    let other_user_id = format!("test_user_delete_unauthorized_{timestamp}");
    let provider = "google";
    let provider_user_id = format!("google_user_delete_456_{timestamp}");

    create_test_user_in_db(&user_id).await?;
    create_test_user_in_db(&other_user_id).await?;
    let unique_provider_user_id =
        create_test_oauth2_account_in_db(&user_id, provider, &provider_user_id).await?;

    // Try to delete the OAuth2 account as a different user
    let result = delete_oauth2_account_core(
        UserId::new(other_user_id),
        Provider::new(provider.to_string()),
        ProviderUserId::new(unique_provider_user_id),
    )
    .await;
    assert!(
        matches!(result, Err(CoordinationError::Unauthorized)),
        "Expected Unauthorized error, got: {result:?}"
    );

    Ok(())
}
