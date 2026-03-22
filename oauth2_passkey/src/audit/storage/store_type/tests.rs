use super::*;
use crate::audit::LoginHistoryEntry;
use crate::test_utils::init_test_environment;
use chrono::{Duration, Utc};
use serial_test::serial;

/// Helper to create a test login history entry with a given timestamp
fn create_test_entry(user_id: &str, timestamp: chrono::DateTime<Utc>) -> LoginHistoryEntry {
    LoginHistoryEntry {
        id: None,
        user_id: user_id.to_string(),
        timestamp,
        auth_method: "passkey".to_string(),
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
        success: true,
        credential_id: None,
        provider: None,
        provider_user_id: None,
        failure_reason: None,
        aaguid: None,
        email: None,
    }
}

/// Test that delete_old_entries removes old entries and keeps recent ones
#[tokio::test]
#[serial]
async fn test_delete_old_entries_removes_old_keeps_recent() {
    init_test_environment().await;
    let _ = LoginHistoryStore::init().await;

    let user_id = "user_retention_test";

    // Insert an entry from 100 days ago
    let old_entry = create_test_entry(user_id, Utc::now() - Duration::days(100));
    let _old_entry = LoginHistoryStore::insert(old_entry)
        .await
        .expect("Failed to insert old entry");

    // Insert a recent entry (now)
    let recent_entry = create_test_entry(user_id, Utc::now());
    let recent_entry = LoginHistoryStore::insert(recent_entry)
        .await
        .expect("Failed to insert recent entry");

    // Delete entries older than 90 days
    let deleted = LoginHistoryStore::delete_old_entries(90)
        .await
        .expect("Failed to delete old entries");
    assert_eq!(deleted, 1, "Should delete exactly 1 old entry");

    // Verify: recent entry still exists, old entry is gone
    let remaining = LoginHistoryStore::get_by_user(user_id, 100, 0)
        .await
        .expect("Failed to get entries");
    assert_eq!(remaining.len(), 1, "Should have 1 remaining entry");
    assert_eq!(
        remaining[0].id, recent_entry.id,
        "Remaining entry should be the recent one"
    );

    // Cleanup: delete the remaining entry
    let _ = LoginHistoryStore::delete_old_entries(1).await;
    // Force cleanup by inserting nothing - just verify we can query
    let _ = LoginHistoryStore::get_by_user(user_id, 100, 0).await;
}

/// Test that delete_old_entries with days_to_keep=0 returns an error
#[tokio::test]
#[serial]
async fn test_delete_old_entries_zero_days_returns_error() {
    init_test_environment().await;
    let _ = LoginHistoryStore::init().await;

    let result = LoginHistoryStore::delete_old_entries(0).await;
    assert!(result.is_err(), "days_to_keep=0 should return error");

    if let Err(e) = result {
        assert!(
            e.to_string()
                .contains("days_to_keep must be greater than 0"),
            "Error message should mention validation: {e}"
        );
    }
}

/// Test that delete_old_entries returns 0 when no old entries exist
#[tokio::test]
#[serial]
async fn test_delete_old_entries_no_old_entries() {
    init_test_environment().await;
    let _ = LoginHistoryStore::init().await;

    let user_id = "user_retention_no_old";

    // Insert only a recent entry
    let entry = create_test_entry(user_id, Utc::now());
    let _ = LoginHistoryStore::insert(entry)
        .await
        .expect("Failed to insert entry");

    // Delete entries older than 1 day - should delete nothing
    let deleted = LoginHistoryStore::delete_old_entries(1)
        .await
        .expect("Failed to delete old entries");
    assert_eq!(deleted, 0, "Should delete 0 entries when all are recent");

    // Cleanup
    let _ = LoginHistoryStore::delete_old_entries(1).await;
}

/// Test that delete_old_entries correctly deletes multiple old entries at once
#[tokio::test]
#[serial]
async fn test_delete_old_entries_multiple_old_entries() {
    init_test_environment().await;
    let _ = LoginHistoryStore::init().await;

    let user_id = "user_retention_multi";

    // Insert 3 old entries (200, 150, 100 days ago)
    for days_ago in [200, 150, 100] {
        let entry = create_test_entry(user_id, Utc::now() - Duration::days(days_ago));
        LoginHistoryStore::insert(entry)
            .await
            .expect("Failed to insert old entry");
    }

    // Insert 2 recent entries (10 days ago, now)
    for days_ago in [10, 0] {
        let entry = create_test_entry(user_id, Utc::now() - Duration::days(days_ago));
        LoginHistoryStore::insert(entry)
            .await
            .expect("Failed to insert recent entry");
    }

    // Delete entries older than 30 days
    let deleted = LoginHistoryStore::delete_old_entries(30)
        .await
        .expect("Failed to delete old entries");
    assert_eq!(deleted, 3, "Should delete all 3 old entries");

    // Verify 2 recent entries remain
    let remaining = LoginHistoryStore::get_by_user(user_id, 100, 0)
        .await
        .expect("Failed to get entries");
    assert_eq!(remaining.len(), 2, "Should have 2 remaining entries");

    // Cleanup
    let _ = LoginHistoryStore::delete_old_entries(1).await;
}
