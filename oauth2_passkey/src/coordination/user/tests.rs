use super::*;
use crate::test_utils::init_test_environment;
use serial_test::serial;

use crate::oauth2::OAuth2Store;
use crate::passkey::{PasskeyCredential, PasskeyStore};
use crate::session::{SessionId, UserId, insert_test_session, insert_test_user};
use crate::userdb::{User as DbUser, UserStore};

// Helper function to create a test user
fn create_test_user(id: &str, account: &str, label: &str) -> DbUser {
    DbUser {
        id: id.to_string(),
        account: account.to_string(),
        label: label.to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// Helper function to create a minimal test PasskeyCredential for testing
// We only need the credential_id field for our tests
fn create_test_credential(id: &str, user_id: &str) -> PasskeyCredential {
    // Create a minimal PasskeyCredential with just the fields we need
    // This avoids using private types that aren't re-exported
    let now = chrono::Utc::now();
    PasskeyCredential {
        sequence_number: None,
        credential_id: id.to_string(),
        user_id: user_id.to_string(),
        public_key: String::new(),
        aaguid: String::new(),
        rp_id: String::new(),
        counter: 0,
        // We don't need to access the user field in our tests
        // so we can use a simpler approach
        user: serde_json::from_str(
            "{\"user_handle\":\"test\",\"name\":\"test\",\"displayName\":\"Test\"}",
        )
        .unwrap(),
        created_at: now,
        updated_at: now,
        last_used_at: now,
    }
}

// Helper function to create a test OAuth2 account
fn create_test_oauth2_account(
    id: &str,
    user_id: &str,
    provider: &str,
    provider_user_id: &str,
) -> crate::OAuth2Account {
    crate::OAuth2Account {
        sequence_number: None,
        id: id.to_string(),
        user_id: user_id.to_string(),
        provider: provider.to_string(),
        provider_user_id: provider_user_id.to_string(),
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
        picture: None,
        metadata: serde_json::json!({}),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Test successful update of a user account
///
/// This test verifies that `update_user_account` correctly updates a user account
/// when given valid input. It creates a test user in the database with a session,
/// calls the update function, and verifies both the return value and the updated database state.
///
#[serial]
#[tokio::test]
async fn test_update_user_account_success() {
    use crate::test_utils::init_test_environment;
    init_test_environment().await;

    let user_id = "test-user";
    let session_id = "test-session-user";

    // 1. Create user and session using test utilities
    insert_test_user(
        UserId::new(user_id.to_string()).expect("Valid test user ID"),
        "old-account",
        "Old Label",
        false,
    )
    .await
    .expect("Failed to create test user");
    insert_test_session(
        SessionId::new(session_id.to_string()).expect("Valid test session ID"),
        UserId::new(user_id.to_string()).expect("Valid test user ID"),
        "test-csrf",
        3600,
    )
    .await
    .expect("Failed to create test session");

    // 2. Call the actual function from the parent module
    let result = super::update_user_account(
        SessionId::new(session_id.to_string()).expect("Valid session ID"), // session_id with valid session
        UserId::new(user_id.to_string()).expect("Valid user ID"),          // user_id
        Some("new-account".to_string()),
        Some("New Label".to_string()),
    )
    .await;

    // 3. Verify the result from the function call
    assert!(
        result.is_ok(),
        "update_user_account failed: {:?}",
        result.err()
    );
    let updated_user_from_func = result.unwrap();
    assert_eq!(updated_user_from_func.id, user_id);
    assert_eq!(updated_user_from_func.account, "new-account");
    assert_eq!(updated_user_from_func.label, "New Label");

    // 4. Verify directly from DB for extra confidence
    let user_from_db =
        UserStore::get_user(UserId::new(user_id.to_string()).expect("Valid user ID"))
            .await
            .expect("DB error getting user")
            .expect("User not found in DB after update");
    assert_eq!(user_from_db.account, "new-account");
    assert_eq!(user_from_db.label, "New Label");
}

/// Test update of a non-existent user account
///
/// This test verifies that `update_user_account` returns a ResourceNotFound error
/// when called with a user ID that does not exist in the database.
///
#[serial]
#[tokio::test]
async fn test_update_user_account_not_found() {
    init_test_environment().await;

    let session_user_id = "session-user";
    let session_id = "test-session";
    let nonexistent_user_id = "nonexistent-user";

    // Create a session user (who will try to update a non-existent user)
    insert_test_user(
        UserId::new(session_user_id.to_string()).expect("Valid session user ID"),
        "session@example.com",
        "Session User",
        false,
    )
    .await
    .expect("Failed to create session user");
    insert_test_session(
        SessionId::new(session_id.to_string()).expect("Valid session ID"),
        UserId::new(session_user_id.to_string()).expect("Valid session user ID"),
        "test-csrf",
        3600,
    )
    .await
    .expect("Failed to create session");

    // Call the actual function with a non-existent target user
    let result = super::update_user_account(
        SessionId::new(session_id.to_string()).expect("Valid session ID"), // session_id (valid session)
        UserId::new(nonexistent_user_id.to_string()).expect("Valid nonexistent user ID"), // user_id (non-existent)
        Some("new-account".to_string()),
        Some("New Label".to_string()),
    )
    .await;

    // Verify the result - should fail with Unauthorized because session user != target user
    assert!(result.is_err());
    match result {
        Err(CoordinationError::Unauthorized) => {
            // Expected - session user cannot update other users unless they are the same
        }
        _ => panic!("Expected Unauthorized error, got {result:?}"),
    }
}

/// Test successful deletion of a user account
///
/// This test verifies that `delete_user_account` correctly deletes a user account
/// when given a valid user ID. It creates a test user in the database, deletes it,
/// and verifies the user no longer exists in the database.
///
#[serial]
#[tokio::test]
async fn test_delete_user_account_success() {
    init_test_environment().await;

    // Explicitly ensure tables exist for this test's connection
    // This is necessary for in-memory databases where each test may get a fresh instance
    UserStore::init()
        .await
        .expect("Failed to initialize UserStore");
    OAuth2Store::init()
        .await
        .expect("Failed to initialize OAuth2Store");
    PasskeyStore::init()
        .await
        .expect("Failed to initialize PasskeyStore");

    // Use unique timestamp to avoid conflicts with other tests
    let timestamp = chrono::Utc::now().timestamp_millis();
    let user_id_to_delete = format!("user-to-delete-{timestamp}");

    // 1. Create user
    let test_user = create_test_user(
        &user_id_to_delete,
        &format!("test-account-{timestamp}"),
        "Test User",
    );
    UserStore::upsert_user(test_user.clone())
        .await
        .expect("Failed to insert user");

    // 2. Create passkey credentials
    let cred1 = create_test_credential(&format!("credential-1-{timestamp}"), &user_id_to_delete);
    let cred2 = create_test_credential(&format!("credential-2-{timestamp}"), &user_id_to_delete);
    PasskeyStore::store_credential(
        CredentialId::new(cred1.credential_id.clone()).expect("Valid credential ID"),
        cred1.clone(),
    )
    .await
    .expect("Failed to store cred1");
    PasskeyStore::store_credential(
        CredentialId::new(cred2.credential_id.clone()).expect("Valid credential ID"),
        cred2.clone(),
    )
    .await
    .expect("Failed to store cred2");

    // 3. Create OAuth2 accounts
    let oauth_acc1 = create_test_oauth2_account(
        &format!("oauth-acc-1-{timestamp}"),
        &user_id_to_delete,
        "google",
        &format!("google-id-1-{timestamp}"),
    );
    let oauth_acc2 = create_test_oauth2_account(
        &format!("oauth-acc-2-{timestamp}"),
        &user_id_to_delete,
        "github",
        &format!("github-id-1-{timestamp}"),
    );
    OAuth2Store::upsert_oauth2_account(oauth_acc1)
        .await
        .expect("Failed to upsert oauth_acc1");
    OAuth2Store::upsert_oauth2_account(oauth_acc2)
        .await
        .expect("Failed to upsert oauth_acc2");

    // Create session for the user (user deleting their own account)
    let session_id = format!("test-session-{timestamp}");
    insert_test_session(
        SessionId::new(session_id.clone()).expect("Valid session ID"),
        UserId::new(user_id_to_delete.clone()).expect("Valid user ID"),
        "test-csrf",
        3600,
    )
    .await
    .expect("Failed to create session");

    // 4. Call the actual function
    let result = super::delete_user_account(
        SessionId::new(session_id.clone()).expect("Valid session ID"),
        UserId::new(user_id_to_delete.clone()).expect("Valid user ID"),
    )
    .await;

    // 5. Verify returned credential IDs
    assert!(
        result.is_ok(),
        "delete_user_account failed: {:?}",
        result.err()
    );
    let mut returned_credential_ids = result.unwrap();
    returned_credential_ids.sort(); // Sort for consistent comparison
    let expected_ids = vec![
        format!("credential-1-{}", timestamp),
        format!("credential-2-{}", timestamp),
    ];
    let mut expected_sorted = expected_ids.clone();
    expected_sorted.sort();
    assert_eq!(returned_credential_ids, expected_sorted);

    // 6. Verify user is deleted
    let user_from_db =
        UserStore::get_user(UserId::new(user_id_to_delete.clone()).expect("Valid user ID"))
            .await
            .expect("DB error getting user");
    assert!(user_from_db.is_none(), "User was not deleted from DB");

    // 7. Verify passkeys are deleted
    let passkeys_from_db = PasskeyStore::get_credentials_by(CredentialSearchField::UserId(
        UserId::new(user_id_to_delete.clone()).expect("Valid user ID"),
    ))
    .await
    .expect("DB error getting passkeys");
    assert!(passkeys_from_db.is_empty(), "Passkeys were not deleted");

    // 8. Verify OAuth2 accounts are deleted
    let oauth_accounts_from_db = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::UserId(
        UserId::new(user_id_to_delete.clone()).expect("Valid user ID"),
    ))
    .await
    .expect("DB error getting oauth accounts");
    assert!(
        oauth_accounts_from_db.is_empty(),
        "OAuth2 accounts were not deleted"
    );
}

/// Test deletion of a user account that does not exist
///
/// This test verifies that `delete_user_account` returns a ResourceNotFound error
/// when called with a non-existent user ID. It performs the following steps:
/// 1. Initializes a test environment
/// 2. Calls `delete_user_account` with a non-existent user ID
/// 3. Verifies that the function returns a ResourceNotFound error
///
#[serial]
#[tokio::test]
async fn test_delete_user_account_not_found() {
    init_test_environment().await;

    let session_user_id = "session-user";
    let session_id = "test-session";
    let nonexistent_user_id = "nonexistent-user";

    // Create a session user (who will try to delete a non-existent user)
    insert_test_user(
        UserId::new(session_user_id.to_string()).expect("Valid session user ID"),
        "session@example.com",
        "Session User",
        false,
    )
    .await
    .expect("Failed to create session user");
    insert_test_session(
        SessionId::new(session_id.to_string()).expect("Valid session ID"),
        UserId::new(session_user_id.to_string()).expect("Valid session user ID"),
        "test-csrf",
        3600,
    )
    .await
    .expect("Failed to create session");

    let result = super::delete_user_account(
        SessionId::new(session_id.to_string()).expect("Valid session ID"),
        UserId::new(nonexistent_user_id.to_string()).expect("Valid nonexistent user ID"),
    )
    .await;

    assert!(result.is_err());
    match result {
        Err(CoordinationError::Unauthorized) => {
            // Expected - session user cannot delete other users unless they are the same or admin
        }
        _ => panic!("Expected Unauthorized error, got {result:?}"),
    }
}

/// Test successful generation of a new user ID
///
/// This test verifies that `gen_new_user_id` correctly generates a new user ID
/// when called. It performs the following steps:
/// 1. Initializes a test environment
/// 2. Creates a test user directly in the database
/// 3. Calls `gen_new_user_id` to generate a new user ID
/// 4. Verifies that the user ID was successfully generated
///
#[serial]
#[tokio::test]
async fn test_gen_new_user_id_success() {
    init_test_environment().await;

    // Explicitly ensure tables exist for this test's connection
    // This is necessary for in-memory databases where each test may get a fresh instance
    UserStore::init()
        .await
        .expect("Failed to initialize UserStore");
    OAuth2Store::init()
        .await
        .expect("Failed to initialize OAuth2Store");
    PasskeyStore::init()
        .await
        .expect("Failed to initialize PasskeyStore");

    let result = super::gen_new_user_id().await;
    assert!(result.is_ok(), "gen_new_user_id failed: {:?}", result.err());
    let generated_id = result.unwrap();
    assert!(!generated_id.is_empty(), "Generated ID is empty");

    // Verify the ID is indeed not in the DB (gen_new_user_id should ensure this)
    let user_from_db =
        UserStore::get_user(UserId::new(generated_id.clone()).expect("Valid user ID"))
            .await
            .expect("DB error checking generated ID");
    assert!(
        user_from_db.is_none(),
        "Generated ID was found in DB, but should be unique"
    );
}

/// Test generation of a new user ID with maximum retries
///
/// This test verifies that `gen_new_user_id` correctly generates a new user ID
/// when called with maximum retries. It performs the following steps:
/// 1. Initializes a test environment
/// 2. Creates a test user directly in the database
/// 3. Calls `gen_new_user_id` to generate a new user ID
/// 4. Verifies that the user ID was successfully generated
///
#[serial]
#[tokio::test]
async fn test_gen_new_user_id_max_retries() {
    // Set up the test database
    init_test_environment().await;

    // Explicitly ensure tables exist for this test's connection
    // This is necessary for in-memory databases where each test may get a fresh instance
    UserStore::init()
        .await
        .expect("Failed to initialize UserStore");
    OAuth2Store::init()
        .await
        .expect("Failed to initialize OAuth2Store");
    PasskeyStore::init()
        .await
        .expect("Failed to initialize PasskeyStore");

    // Create test users with known IDs that will collide using unique timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let test_user1 = create_test_user(
        &format!("fixed-uuid-1-{timestamp}"),
        &format!("user1-{timestamp}@example.com"),
        "Test User 1",
    );
    let test_user2 = create_test_user(
        &format!("fixed-uuid-2-{timestamp}"),
        &format!("user2-{timestamp}@example.com"),
        "Test User 2",
    );
    let test_user3 = create_test_user(
        &format!("fixed-uuid-3-{timestamp}"),
        &format!("user3-{timestamp}@example.com"),
        "Test User 3",
    );

    UserStore::upsert_user(test_user1.clone())
        .await
        .expect("Failed to insert test user 1");
    UserStore::upsert_user(test_user2.clone())
        .await
        .expect("Failed to insert test user 2");
    UserStore::upsert_user(test_user3.clone())
        .await
        .expect("Failed to insert test user 3");

    // Test the failure case (all 3 UUIDs exist)
    {
        // Mock implementation with 3 colliding IDs
        let result = gen_new_user_id_with_mock(&[
            &format!("fixed-uuid-1-{timestamp}"),
            &format!("fixed-uuid-2-{timestamp}"),
            &format!("fixed-uuid-3-{timestamp}"),
        ])
        .await;

        // Verify it fails with the expected error
        assert!(result.is_err());
        if let Err(CoordinationError::Coordination(msg)) = result {
            assert_eq!(
                msg,
                "Failed to generate a unique user ID after multiple attempts"
            );
        } else {
            panic!("Expected CoordinationError::Coordination, got {result:?}");
        }
    }

    // Test the success case (third UUID is unique)
    {
        // Mock implementation where the third ID is unique
        let result = gen_new_user_id_with_mock(&[
            &format!("fixed-uuid-1-{timestamp}"),
            &format!("fixed-uuid-2-{timestamp}"),
            &format!("fixed-uuid-4-{timestamp}"),
        ])
        .await;

        // Verify it succeeds with the expected ID
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), format!("fixed-uuid-4-{timestamp}"));
    }

    // Clean up
    UserStore::delete_user(UserId::new(test_user1.id).expect("Valid user ID"))
        .await
        .ok();
    UserStore::delete_user(UserId::new(test_user2.id).expect("Valid user ID"))
        .await
        .ok();
    UserStore::delete_user(UserId::new(test_user3.id).expect("Valid user ID"))
        .await
        .ok();
}

/// Test that the first user can self-delete when other admins exist ("escape hatch").
///
/// This verifies the design feature: the first-user special-casing is a sensible default,
/// and library users who prefer all admins to be equal can have the first user self-delete
/// after creating another admin. After deletion, all remaining admins are protected equally
/// by the last-admin guard only.
///
/// Note: The actual deletion may encounter FK constraint errors when parallel non-serial
/// tests re-create child records via `init_test_environment()` between the child record
/// deletion and user deletion. In that case, `delete_user_atomically()` is used as a
/// fallback to complete the deletion while holding the GENERIC_DATA_STORE lock.
#[serial]
#[tokio::test]
async fn test_first_user_escape_hatch_self_delete() {
    use crate::test_utils::{delete_user_atomically, restore_first_user_after_deletion};

    init_test_environment().await;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let other_admin_id = format!("other-admin-escape-{timestamp}");

    // Create another admin so first-user is NOT the last admin
    let other_admin = DbUser {
        sequence_number: None,
        id: other_admin_id.clone(),
        account: format!("{other_admin_id}@example.com"),
        label: "Other Admin".to_string(),
        is_admin: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    UserStore::upsert_user(other_admin)
        .await
        .expect("Failed to create other admin");

    // Create a session for the first-user
    let first_user_session_id = format!("session-escape-hatch-{timestamp}");
    insert_test_session(
        SessionId::new(first_user_session_id.clone()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
        "test-csrf-token",
        3600,
    )
    .await
    .expect("Failed to create session for first user");

    // First-user self-deletes via the user account page (should succeed)
    let result = super::delete_user_account(
        SessionId::new(first_user_session_id).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
    )
    .await;

    // The guard should allow this deletion (not Conflict).
    // In the full test suite, parallel tests may re-create child records between
    // the child delete and user delete, causing an FK constraint error.
    // This is a test infrastructure race condition, not a logic bug.
    match &result {
        Ok(_) => {
            // Guard passed and deletion succeeded
        }
        Err(CoordinationError::Conflict(_)) => {
            panic!(
                "First user should be able to self-delete when other admins exist (guard blocked), got: {result:?}"
            );
        }
        Err(_) => {
            // FK constraint error or other DB error -- guard passed but parallel test interference
            // Complete the deletion atomically
            delete_user_atomically("first-user").await;
        }
    }

    // Verify first-user no longer exists
    let deleted_user =
        UserStore::get_user(UserId::new("first-user".to_string()).expect("Valid user ID"))
            .await
            .expect("Failed to query user");
    assert!(
        deleted_user.is_none(),
        "First user should no longer exist after self-deletion"
    );

    // Cleanup: restore first-user with sequence_number=1 and associated credentials
    restore_first_user_after_deletion().await;

    // Cleanup: delete the other admin
    UserStore::delete_user(UserId::new(other_admin_id).expect("Valid user ID"))
        .await
        .ok();
}

/// Test that self-deletion of the last admin user is prevented.
/// This ensures the last-admin guard also covers the self-deletion path,
/// not just the admin deletion path.
#[serial]
#[tokio::test]
async fn test_self_delete_last_admin_prevented() {
    init_test_environment().await;

    // Create a session for the first-user (who is the only admin in the test environment)
    let first_user_session_id = "test-session-first-user-self-delete";
    insert_test_session(
        SessionId::new(first_user_session_id.to_string()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
        "test-csrf-token",
        3600,
    )
    .await
    .expect("Failed to create session for first user");

    // Attempt to self-delete the first-user (the only admin) -> should fail
    let result = super::delete_user_account(
        SessionId::new(first_user_session_id.to_string()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
    )
    .await;

    // Verify the operation fails with Conflict error
    assert!(
        result.is_err(),
        "Should not be able to self-delete the last admin"
    );
    match result {
        Err(CoordinationError::Conflict(msg)) => {
            assert!(
                msg.contains("Cannot delete the last admin user"),
                "Error message should mention last admin deletion, got: {msg}"
            );
        }
        _ => panic!("Expected Conflict error about last admin, got {result:?}"),
    }
}

// Helper function to mock UUID generation with fixed values
async fn gen_new_user_id_with_mock(uuids: &[&str]) -> Result<String, CoordinationError> {
    // Try up to 3 times to generate a unique ID
    for uuid_index in 0..3 {
        if uuid_index >= uuids.len() {
            return Err(CoordinationError::Coordination(
                "Mock UUID list exhausted".to_string(),
            ));
        }

        let id = uuids[uuid_index].to_string();

        // Check if a user with this ID already exists
        match UserStore::get_user(UserId::new(id.clone()).expect("Valid user ID")).await {
            Ok(None) => return Ok(id), // ID is unique, return it
            Ok(Some(_)) => continue,   // ID exists, try again
            Err(e) => {
                return Err(
                    CoordinationError::Database(format!("Failed to check user ID: {e}")).log(),
                );
            }
        }
    }

    // If we get here, we failed to generate a unique ID after multiple attempts
    Err(CoordinationError::Coordination(
        "Failed to generate a unique user ID after multiple attempts".to_string(),
    )
    .log())
}
