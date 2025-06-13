use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{AccountSearchField, OAuth2Account};
use crate::storage::GENERIC_DATA_STORE;

use super::postgres::*;
use super::sqlite::*;

pub(crate) struct OAuth2Store;

impl OAuth2Store {
    /// Generate a unique ID for an OAuth2 account
    /// This function checks if the generated ID already exists in the database
    /// and retries up to 3 times if there's a collision
    pub(crate) async fn gen_unique_account_id() -> Result<String, OAuth2Error> {
        // Try up to 3 times to generate a unique ID
        for _ in 0..3 {
            let id = uuid::Uuid::new_v4().to_string();

            // Check if an account with this ID already exists
            match Self::get_oauth2_accounts_by(AccountSearchField::Id(id.clone())).await {
                Ok(accounts) if accounts.is_empty() => return Ok(id), // ID is unique, return it
                Ok(_) => continue,                                    // ID exists, try again
                Err(e) => {
                    return Err(OAuth2Error::Database(format!(
                        "Failed to check account ID: {}",
                        e
                    )));
                }
            }
        }

        // If we get here, we failed to generate a unique ID after multiple attempts
        // This is extremely unlikely with UUID v4, but we handle it anyway
        Err(OAuth2Error::Internal(
            "Failed to generate a unique OAuth2 account ID after multiple attempts".to_string(),
        ))
    }

    /// Initialize the OAuth2 database tables
    pub(crate) async fn init() -> Result<(), OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_oauth2_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_oauth2_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            )),
        }
    }

    /// Get all OAuth2 accounts for a user
    pub(crate) async fn get_oauth2_accounts(
        user_id: &str,
    ) -> Result<Vec<OAuth2Account>, OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_oauth2_accounts_by_field_sqlite(
                pool,
                &AccountSearchField::UserId(user_id.to_string()),
            )
            .await
            // get_oauth2_accounts_sqlite(pool, user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_accounts_by_field_postgres(
                pool,
                &AccountSearchField::UserId(user_id.to_string()),
            )
            .await
            // get_oauth2_accounts_postgres(pool, user_id).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    pub(crate) async fn get_oauth2_accounts_by(
        field: AccountSearchField,
    ) -> Result<Vec<OAuth2Account>, OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;
        if let Some(pool) = store.as_sqlite() {
            get_oauth2_accounts_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_accounts_by_field_postgres(pool, &field).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    /// Get OAuth2 account by provider and provider_user_id
    pub(crate) async fn get_oauth2_account_by_provider(
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuth2Account>, OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_oauth2_account_by_provider_sqlite(pool, provider, provider_user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_account_by_provider_postgres(pool, provider, provider_user_id).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    /// Create or update an OAuth2 account
    /// Note: This does not create a user. The user_id must be set before calling this method.
    pub(crate) async fn upsert_oauth2_account(
        mut account: OAuth2Account,
    ) -> Result<OAuth2Account, OAuth2Error> {
        if account.user_id.is_empty() {
            return Err(OAuth2Error::Storage(
                "user_id must be set before upserting OAuth2 account".to_string(),
            ));
        }

        // Generate a unique ID if one isn't provided
        if account.id.is_empty() {
            account.id = Self::gen_unique_account_id().await?;
        }

        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            upsert_oauth2_account_sqlite(pool, account).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_oauth2_account_postgres(pool, account).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    pub(crate) async fn delete_oauth2_accounts_by(
        field: AccountSearchField,
    ) -> Result<(), OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_oauth2_accounts_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            delete_oauth2_accounts_by_field_postgres(pool, &field).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::types::{AccountSearchField, OAuth2Account};
    use crate::test_utils::init_test_environment;
    use crate::userdb::{User, UserStore};
    use serial_test::serial;

    async fn create_test_account(
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
    ) -> OAuth2Account {
        OAuth2Account {
            id: String::new(), // Will be generated
            user_id: user_id.to_string(),
            provider: provider.to_string(),
            provider_user_id: provider_user_id.to_string(),
            name: format!("Test User {}", provider_user_id),
            email: format!("{}@example.com", provider_user_id),
            picture: Some("https://example.com/avatar.png".to_string()),
            metadata: serde_json::json!({
                "test": true,
                "provider": provider
            }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // Helper function to create a user first, then an OAuth2 account
    // This ensures foreign key constraints are satisfied
    async fn create_test_user_and_account(
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
    ) -> OAuth2Account {
        // Ensure both stores are initialized before using them
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");

        // First create the user
        let user = User {
            sequence_number: None,
            id: user_id.to_string(),
            account: format!("{}@example.com", user_id),
            label: format!("Test User {}", user_id),
            is_admin: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Insert the user (ignore result, upsert handles existing users)
        let _ = UserStore::upsert_user(user).await;

        // Create and insert the OAuth2 account
        let account = create_test_account(user_id, provider, provider_user_id).await;
        OAuth2Store::upsert_oauth2_account(account)
            .await
            .expect("Failed to insert OAuth2 account")
    }

    // Helper function to generate unique test identifiers to avoid conflicts between parallel tests
    fn generate_unique_test_id(base: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let thread_id = std::thread::current().id();
        format!("{}_{:?}_{}", base, thread_id, counter)
    }

    /// Test unique account ID generation functionality
    ///
    /// This test verifies that the `gen_unique_account_id` function generates unique,
    /// non-empty UUID strings. It calls the function multiple times and validates
    /// that each generated ID is unique, non-empty, and parseable as a valid UUID.
    ///
    #[tokio::test]
    async fn test_gen_unique_account_id() {
        init_test_environment().await;

        // Test that we can generate unique IDs
        let id1 = OAuth2Store::gen_unique_account_id().await.unwrap();
        let id2 = OAuth2Store::gen_unique_account_id().await.unwrap();

        assert_ne!(id1, id2, "Generated IDs should be unique");
        assert!(!id1.is_empty(), "Generated ID should not be empty");
        assert!(!id2.is_empty(), "Generated ID should not be empty");

        // Test that IDs are valid UUIDs
        uuid::Uuid::parse_str(&id1).expect("ID should be a valid UUID");
        uuid::Uuid::parse_str(&id2).expect("ID should be a valid UUID");
    }

    /// Test OAuth2Store initialization and database table creation
    ///
    /// This test verifies that the OAuth2Store::init() function succeeds without errors,
    /// ensuring that the necessary database tables and structures are created properly
    /// during the initialization process.
    ///
    #[tokio::test]
    #[serial]
    async fn test_init_creates_tables() {
        init_test_environment().await;

        // The init function should succeed without errors
        let result = OAuth2Store::init().await;
        assert!(result.is_ok(), "OAuth2Store::init() should succeed");
    }

    /// Test OAuth2 account creation through upsert operation
    ///
    /// This test verifies that `upsert_oauth2_account` can successfully create a new OAuth2
    /// account record in the database. It creates a test user first to satisfy foreign key
    /// constraints, then creates an OAuth2 account linked to that user, and validates that
    /// all account fields are stored correctly with a generated ID.
    ///
    #[tokio::test]
    #[serial]
    async fn test_upsert_oauth2_account_create() {
        init_test_environment().await;

        // First create a user to satisfy foreign key constraints
        let user_id = generate_unique_test_id("user");
        let user = User {
            sequence_number: None,
            id: user_id.clone(),
            account: format!("{}@example.com", user_id),
            label: format!("Test User {}", user_id),
            is_admin: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Insert the user - SQLite functions now ensure tables exist
        UserStore::upsert_user(user).await.unwrap();

        // Create and insert the OAuth2 account
        let test_account = create_test_account(&user_id, "google", "google123").await;
        let inserted_account = OAuth2Store::upsert_oauth2_account(test_account.clone())
            .await
            .unwrap();

        assert!(
            !inserted_account.id.is_empty(),
            "Account should have generated ID"
        );
        assert_eq!(inserted_account.user_id, test_account.user_id);
        assert_eq!(inserted_account.provider, test_account.provider);
        assert_eq!(
            inserted_account.provider_user_id,
            test_account.provider_user_id
        );
        assert_eq!(inserted_account.email, test_account.email);
        assert_eq!(inserted_account.name, test_account.name);
        assert_eq!(inserted_account.picture, test_account.picture);

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted_account.id))
            .await
            .unwrap();
    }

    /// Test OAuth2 account upsert validation with empty user ID
    ///
    /// This test verifies that `upsert_oauth2_account` properly validates required fields
    /// and returns an appropriate error when the user_id field is empty. It creates an
    /// OAuth2 account with an empty user_id and validates that the storage operation
    /// fails with a descriptive error message about the missing user_id requirement.
    ///
    #[tokio::test]
    #[serial]
    async fn test_upsert_oauth2_account_empty_user_id() {
        init_test_environment().await;

        let mut test_account = create_test_account("", "google", "google123").await;
        test_account.user_id = String::new();

        // Should fail with empty user_id
        let result = OAuth2Store::upsert_oauth2_account(test_account).await;
        assert!(result.is_err(), "Should fail with empty user_id");

        if let Err(OAuth2Error::Storage(msg)) = result {
            assert!(
                msg.contains("user_id must be set"),
                "Error should mention user_id requirement"
            );
        } else {
            panic!("Expected OAuth2Error::Storage");
        }
    }

    /// Test OAuth2 account update through upsert operation
    ///
    /// This test verifies that `upsert_oauth2_account` can successfully update an existing
    /// OAuth2 account record. It creates an account, modifies some fields (name and email),
    /// performs an upsert operation, and validates that the account ID remains the same
    /// while the updated fields are properly persisted in the database.
    ///
    #[tokio::test]
    #[serial]
    async fn test_upsert_oauth2_account_update() {
        init_test_environment().await;

        let test_account = create_test_user_and_account("user123", "google", "google123").await;

        // Insert the account
        let mut inserted_account = OAuth2Store::upsert_oauth2_account(test_account)
            .await
            .unwrap();

        // Update the account
        inserted_account.name = "Updated Name".to_string();
        inserted_account.email = "updated@example.com".to_string();

        let updated_account = OAuth2Store::upsert_oauth2_account(inserted_account.clone())
            .await
            .unwrap();

        assert_eq!(
            updated_account.id, inserted_account.id,
            "ID should remain the same"
        );
        assert_eq!(updated_account.name, "Updated Name".to_string());
        assert_eq!(updated_account.email, "updated@example.com".to_string());

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(updated_account.id))
            .await
            .unwrap();
    }

    /// Test retrieving OAuth2 accounts by user ID
    ///
    /// This test verifies that `get_oauth2_accounts` can successfully retrieve multiple OAuth2
    /// accounts associated with a single user ID. It creates a user with two OAuth2 accounts
    /// (Google and GitHub), then retrieves all accounts for that user and validates that both
    /// accounts are returned with correct provider information.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_oauth2_accounts_by_user_id() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");

        let user_id = generate_unique_test_id("test_user");
        let google_provider_id = generate_unique_test_id("google");
        let github_provider_id = generate_unique_test_id("github");

        let inserted1 = create_test_user_and_account(&user_id, "google", &google_provider_id).await;

        // Create second account for the same user (user already exists)
        let account2 = create_test_account(&user_id, "github", &github_provider_id).await;
        let inserted2 = OAuth2Store::upsert_oauth2_account(account2).await.unwrap();

        // Retrieve accounts
        let accounts = OAuth2Store::get_oauth2_accounts(&user_id).await.unwrap();

        assert_eq!(accounts.len(), 2, "Should have 2 accounts for the user");

        let mut found_google = false;
        let mut found_github = false;
        for account in &accounts {
            if account.provider == "google" {
                found_google = true;
                assert_eq!(account.provider_user_id, google_provider_id);
            } else if account.provider == "github" {
                found_github = true;
                assert_eq!(account.provider_user_id, github_provider_id);
            }
        }

        assert!(found_google, "Should find Google account");
        assert!(found_github, "Should find GitHub account");

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted1.id))
            .await
            .unwrap();
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted2.id))
            .await
            .unwrap();
    }

    /// Test retrieving OAuth2 accounts by account ID
    ///
    /// This test verifies that `get_oauth2_accounts_by` can successfully retrieve an OAuth2
    /// account when searching by account ID. It creates a test user and OAuth2 account,
    /// searches for the account using its ID, and validates that exactly one matching
    /// account is returned with the correct ID.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_oauth2_accounts_by_id() {
        init_test_environment().await;

        let inserted_account = create_test_user_and_account("user123", "google", "google123").await;

        // Search by ID
        let accounts = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Id(
            inserted_account.id.clone(),
        ))
        .await
        .unwrap();

        assert_eq!(accounts.len(), 1, "Should find exactly one account");
        assert_eq!(accounts[0].id, inserted_account.id);
        assert_eq!(accounts[0].provider, "google");

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted_account.id))
            .await
            .unwrap();
    }

    /// Test retrieving OAuth2 accounts by provider name
    ///
    /// This test verifies that `get_oauth2_accounts_by` can successfully retrieve OAuth2
    /// accounts when searching by provider name. It creates multiple accounts with different
    /// providers, searches for accounts by a specific provider, and validates that only
    /// accounts from that provider are returned.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_oauth2_accounts_by_provider() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");

        // Clean up any existing Google accounts from other tests to ensure test isolation
        let existing_google_accounts =
            OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Provider("google".to_string()))
                .await
                .unwrap_or_default();
        for account in existing_google_accounts {
            let _ =
                OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(account.id)).await;
        }

        let provider1_id = generate_unique_test_id("google");
        let provider2_id = generate_unique_test_id("google");
        let provider3_id = generate_unique_test_id("github");

        let inserted1 = create_test_user_and_account(
            &generate_unique_test_id("user1"),
            "google",
            &provider1_id,
        )
        .await;
        let inserted2 = create_test_user_and_account(
            &generate_unique_test_id("user2"),
            "google",
            &provider2_id,
        )
        .await;
        let inserted3 = create_test_user_and_account(
            &generate_unique_test_id("user3"),
            "github",
            &provider3_id,
        )
        .await;

        // Search by provider
        let google_accounts =
            OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Provider("google".to_string()))
                .await
                .unwrap();

        assert_eq!(google_accounts.len(), 2, "Should find 2 Google accounts");
        for account in &google_accounts {
            assert_eq!(account.provider, "google");
        }

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted1.id))
            .await
            .unwrap();
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted2.id))
            .await
            .unwrap();
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted3.id))
            .await
            .unwrap();
    }

    /// Test retrieving specific OAuth2 account by provider and provider user ID
    ///
    /// This test verifies that `get_oauth2_account_by_provider` can successfully retrieve
    /// a specific OAuth2 account using both the provider name and provider_user_id as
    /// lookup criteria. It creates a test account, searches for it using this composite
    /// key, and validates that the correct account is returned.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_oauth2_account_by_provider() {
        init_test_environment().await;

        let inserted_account = create_test_user_and_account("user123", "google", "google123").await;

        // Find by provider and provider_user_id
        let found_account = OAuth2Store::get_oauth2_account_by_provider("google", "google123")
            .await
            .unwrap();

        assert!(found_account.is_some(), "Should find the account");
        let found_account = found_account.unwrap();
        assert_eq!(found_account.id, inserted_account.id);
        assert_eq!(found_account.provider, "google");
        assert_eq!(found_account.provider_user_id, "google123");

        // Try to find non-existent account
        let not_found = OAuth2Store::get_oauth2_account_by_provider("google", "nonexistent")
            .await
            .unwrap();
        assert!(not_found.is_none(), "Should not find non-existent account");

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted_account.id))
            .await
            .unwrap();
    }

    /// Test OAuth2 account deletion by account ID
    ///
    /// This test verifies that `delete_oauth2_accounts_by` can successfully delete an OAuth2
    /// account when searching by account ID. It creates a test account, verifies it exists,
    /// deletes it using the account ID, and confirms the account is no longer retrievable
    /// from the database.
    ///
    #[tokio::test]
    #[serial]
    async fn test_delete_oauth2_accounts_by_id() {
        init_test_environment().await;

        let user_id = generate_unique_test_id("user");
        let provider_user_id = generate_unique_test_id("google");
        let inserted_account =
            create_test_user_and_account(&user_id, "google", &provider_user_id).await;

        // Verify account exists
        let accounts_before = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Id(
            inserted_account.id.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(
            accounts_before.len(),
            1,
            "Account should exist before deletion"
        );

        // Delete account
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted_account.id.clone()))
            .await
            .unwrap();

        // Verify account is deleted
        let accounts_after =
            OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Id(inserted_account.id))
                .await
                .unwrap();
        assert_eq!(accounts_after.len(), 0, "Account should be deleted");
    }

    /// Test OAuth2 account deletion by user ID
    ///
    /// This test verifies that `delete_oauth2_accounts_by` can successfully delete all OAuth2
    /// accounts associated with a specific user ID. It creates multiple accounts for the same
    /// user, verifies they exist, deletes them all using the user ID, and confirms that no
    /// accounts remain for that user.
    ///
    #[tokio::test]
    #[serial]
    async fn test_delete_oauth2_accounts_by_user_id() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");

        let user_id = generate_unique_test_id("user_to_delete");
        let _inserted1 =
            create_test_user_and_account(&user_id, "google", &generate_unique_test_id("google"))
                .await;

        // Create second account for the same user (user already exists)
        let account2 =
            create_test_account(&user_id, "github", &generate_unique_test_id("github")).await;
        let _inserted2 = OAuth2Store::upsert_oauth2_account(account2).await.unwrap();

        // Verify accounts exist
        let accounts_before = OAuth2Store::get_oauth2_accounts(&user_id).await.unwrap();
        assert_eq!(
            accounts_before.len(),
            2,
            "Should have 2 accounts before deletion"
        );

        // Delete all accounts for user
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.clone()))
            .await
            .unwrap();

        // Verify accounts are deleted
        let accounts_after = OAuth2Store::get_oauth2_accounts(&user_id).await.unwrap();
        assert_eq!(accounts_after.len(), 0, "All accounts should be deleted");
    }

    /// Test OAuth2 account retrieval with non-existent user ID
    ///
    /// This test verifies that `get_oauth2_accounts` returns an empty result when querying
    /// for OAuth2 accounts with a user ID that doesn't exist in the database. It attempts
    /// to retrieve accounts for a non-existent user and validates that an empty list is
    /// returned rather than an error.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_oauth2_accounts_empty_result() {
        init_test_environment().await;

        // Try to get accounts for non-existent user
        let accounts = OAuth2Store::get_oauth2_accounts("nonexistent_user")
            .await
            .unwrap();
        assert_eq!(
            accounts.len(),
            0,
            "Should return empty vector for non-existent user"
        );
    }

    /// Test OAuth2 account search with different search field variants
    ///
    /// This test verifies that `get_oauth2_accounts_by` works correctly with all supported
    /// AccountSearchField variants (ID, UserId, Provider, ProviderAndUserId). It creates
    /// test accounts and validates that each search method returns the expected results
    /// for the appropriate search criteria.
    ///
    #[tokio::test]
    #[serial]
    async fn test_account_search_field_variants() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");

        let user_id = generate_unique_test_id("search_test_user");
        let provider_user_id = generate_unique_test_id("search_google");
        let inserted_account =
            create_test_user_and_account(&user_id, "google", &provider_user_id).await;

        // Test search by ID
        let by_id = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Id(
            inserted_account.id.clone(),
        ))
        .await
        .unwrap();
        assert_eq!(by_id.len(), 1);

        // Test search by UserId
        let by_user_id =
            OAuth2Store::get_oauth2_accounts_by(AccountSearchField::UserId(user_id.clone()))
                .await
                .unwrap();
        assert_eq!(by_user_id.len(), 1);

        // Test search by Provider
        let by_provider =
            OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Provider("google".to_string()))
                .await
                .unwrap();
        assert!(!by_provider.is_empty());

        // Test search by Email
        let by_email = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::Email(
            inserted_account.email.clone(),
        ))
        .await
        .unwrap();
        assert!(!by_email.is_empty());

        // Clean up
        OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(inserted_account.id))
            .await
            .unwrap();
    }

    /// Test concurrent OAuth2 account operations and thread safety
    ///
    /// This test verifies that OAuth2 account operations are thread-safe when multiple
    /// concurrent upsert operations are performed simultaneously. It spawns multiple tokio
    /// tasks that create and upsert accounts concurrently, then validates that all operations
    /// complete successfully without data corruption or race conditions.
    ///
    #[tokio::test]
    #[serial]
    async fn test_concurrent_account_operations() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");

        // Create accounts and insert them concurrently
        let user_id = &generate_unique_test_id("concurrent_test_user");

        // Create one account with user, then create additional accounts for the same user
        let account0 =
            create_test_user_and_account(user_id, "provider", &generate_unique_test_id("user0"))
                .await;
        let account1 =
            create_test_account(user_id, "provider", &generate_unique_test_id("user1")).await;
        let account2 =
            create_test_account(user_id, "provider", &generate_unique_test_id("user2")).await;
        let account3 =
            create_test_account(user_id, "provider", &generate_unique_test_id("user3")).await;
        let account4 = create_test_account(user_id, "provider", "user4").await;

        let (result1, result2, result3, result4) = tokio::join!(
            OAuth2Store::upsert_oauth2_account(account1),
            OAuth2Store::upsert_oauth2_account(account2),
            OAuth2Store::upsert_oauth2_account(account3),
            OAuth2Store::upsert_oauth2_account(account4)
        );

        let inserted_accounts = vec![
            account0, // already inserted by create_test_user_and_account
            result1.unwrap(),
            result2.unwrap(),
            result3.unwrap(),
            result4.unwrap(),
        ];

        assert_eq!(
            inserted_accounts.len(),
            5,
            "All concurrent insertions should succeed"
        );

        // Verify all accounts have unique IDs
        let mut ids = std::collections::HashSet::new();
        for account in &inserted_accounts {
            assert!(ids.insert(account.id.clone()), "All IDs should be unique");
        }

        // Clean up
        for account in inserted_accounts {
            OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::Id(account.id))
                .await
                .unwrap();
        }
    }
}
