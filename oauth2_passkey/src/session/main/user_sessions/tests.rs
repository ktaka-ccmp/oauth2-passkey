use crate::session::main::user_sessions::{
    add_session_to_user_mapping, cleanup_stale_sessions, get_user_session_ids,
    remove_session_from_user_mapping,
};
use crate::session::types::{SessionId, UserId};
use crate::session::{insert_test_session, insert_test_user};
use crate::test_utils;

#[tokio::test]
async fn test_get_user_session_ids_empty() {
    test_utils::init_test_environment().await;

    let user_id = "test-user-sessions-empty";
    let result = get_user_session_ids(user_id).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_add_and_get_session_ids() {
    test_utils::init_test_environment().await;

    let user_id = "test-user-add-sessions";
    let session_id_1 = "test-session-add-1-abcdefghij";
    let session_id_2 = "test-session-add-2-abcdefghij";

    // Add first session
    add_session_to_user_mapping(user_id, session_id_1)
        .await
        .unwrap();
    let result = get_user_session_ids(user_id).await.unwrap();
    assert_eq!(result, vec![session_id_1]);

    // Add second session
    add_session_to_user_mapping(user_id, session_id_2)
        .await
        .unwrap();
    let result = get_user_session_ids(user_id).await.unwrap();
    assert_eq!(result, vec![session_id_1, session_id_2]);

    // Adding duplicate should not create duplicates
    add_session_to_user_mapping(user_id, session_id_1)
        .await
        .unwrap();
    let result = get_user_session_ids(user_id).await.unwrap();
    assert_eq!(result.len(), 2);

    // Cleanup
    remove_session_from_user_mapping(user_id, session_id_1)
        .await
        .unwrap();
    remove_session_from_user_mapping(user_id, session_id_2)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_remove_session_from_mapping() {
    test_utils::init_test_environment().await;

    let user_id = "test-user-remove-session";
    let session_id_1 = "test-session-rm-1-abcdefghij";
    let session_id_2 = "test-session-rm-2-abcdefghij";

    // Add two sessions
    add_session_to_user_mapping(user_id, session_id_1)
        .await
        .unwrap();
    add_session_to_user_mapping(user_id, session_id_2)
        .await
        .unwrap();

    // Remove first
    remove_session_from_user_mapping(user_id, session_id_1)
        .await
        .unwrap();
    let result = get_user_session_ids(user_id).await.unwrap();
    assert_eq!(result, vec![session_id_2]);

    // Remove second (should empty and remove mapping)
    remove_session_from_user_mapping(user_id, session_id_2)
        .await
        .unwrap();
    let result = get_user_session_ids(user_id).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_cleanup_stale_sessions() {
    test_utils::init_test_environment().await;

    let user_id_str = "test-user-cleanup-stale";
    let user_id = UserId::new(user_id_str.to_string()).unwrap();
    let real_session_id_str = "test-session-real-abcdefghij";
    let stale_session_id_str = "test-session-stale-bcdefghij";
    let real_session_id = SessionId::new(real_session_id_str.to_string()).unwrap();

    // Create a test user and a real session in cache
    insert_test_user(user_id.clone(), "cleanup-test", "Cleanup Test", false)
        .await
        .unwrap();
    insert_test_session(real_session_id, user_id.clone(), "csrf-token-cleanup", 600)
        .await
        .unwrap();

    // Add both real and stale session IDs to the mapping
    add_session_to_user_mapping(user_id_str, real_session_id_str)
        .await
        .unwrap();
    add_session_to_user_mapping(user_id_str, stale_session_id_str)
        .await
        .unwrap();

    // Verify both are in mapping before cleanup
    let before = get_user_session_ids(user_id_str).await.unwrap();
    assert_eq!(before.len(), 2);

    // Cleanup should remove the stale session (not in cache) but keep the real one
    let valid = cleanup_stale_sessions(user_id_str).await.unwrap();
    assert_eq!(valid, vec![real_session_id_str]);

    // Verify mapping was updated
    let after = get_user_session_ids(user_id_str).await.unwrap();
    assert_eq!(after, vec![real_session_id_str]);

    // Cleanup
    remove_session_from_user_mapping(user_id_str, real_session_id_str)
        .await
        .unwrap();
}
