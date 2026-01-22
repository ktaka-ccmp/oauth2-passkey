use super::*;
use chrono::Utc;

/// Test that has_admin_privileges() correctly identifies admin users
#[test]
fn test_has_admin_privileges_regular_admin() {
    let admin_user = User {
        id: "user1".to_string(),
        account: "admin@example.com".to_string(),
        label: "Admin User".to_string(),
        is_admin: true,
        sequence_number: Some(5),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(admin_user.has_admin_privileges());
}

/// Test that has_admin_privileges() correctly identifies first user as admin
#[test]
fn test_has_admin_privileges_first_user() {
    let first_user = User {
        id: "first_user".to_string(),
        account: "first@example.com".to_string(),
        label: "First User".to_string(),
        is_admin: false, // Even without is_admin=true, should be admin
        sequence_number: Some(1),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(first_user.has_admin_privileges());
}

/// Test that has_admin_privileges() correctly identifies regular users
#[test]
fn test_has_admin_privileges_regular_user() {
    let regular_user = User {
        id: "regular_user".to_string(),
        account: "user@example.com".to_string(),
        label: "Regular User".to_string(),
        is_admin: false,
        sequence_number: Some(2),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(!regular_user.has_admin_privileges());
}

/// Test that has_admin_privileges() handles users without sequence numbers
#[test]
fn test_has_admin_privileges_no_sequence_number() {
    let user_without_sequence = User {
        id: "temp_user".to_string(),
        account: "temp@example.com".to_string(),
        label: "Temp User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(!user_without_sequence.has_admin_privileges());
}

/// Test that first user with is_admin=true is still admin (both conditions true)
#[test]
fn test_has_admin_privileges_first_user_and_admin() {
    let first_admin_user = User {
        id: "first_admin".to_string(),
        account: "first-admin@example.com".to_string(),
        label: "First Admin User".to_string(),
        is_admin: true,
        sequence_number: Some(1),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(first_admin_user.has_admin_privileges());
}
