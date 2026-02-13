use super::*;

#[test]
fn test_mask_email() {
    assert_eq!(mask_email("user@example.com"), "u***@***");
    assert_eq!(mask_email("a@b.org"), "a***@***");
    assert_eq!(mask_email("test"), "t***");
}

#[test]
fn test_mask_name() {
    assert_eq!(mask_name("John Smith"), "J*** S***");
    assert_eq!(mask_name("Alice"), "A***");
    assert_eq!(mask_name(""), "");
}

#[test]
fn test_mask_ip() {
    assert_eq!(mask_ip("192.168.1.1"), "192.168.*.*");
    assert_eq!(mask_ip("10.0.0.1"), "10.0.*.*");
}

#[test]
fn test_mask_id() {
    assert_eq!(mask_id("abc123def456"), "abc1***");
    assert_eq!(mask_id("ab"), "a***");
}

#[test]
fn test_mask_user_agent() {
    assert_eq!(mask_user_agent("Mozilla/5.0 Chrome/120.0"), "Chrome/***");
    assert_eq!(mask_user_agent("Mozilla/5.0 Firefox/119"), "Firefox/***");
    assert_eq!(mask_user_agent("SomeBot/1.0"), "***");
}

#[test]
fn test_mask_users_preserves_self() {
    use chrono::Utc;
    let now = Utc::now();
    let users = vec![
        DbUser {
            sequence_number: Some(1),
            id: "me".to_string(),
            account: "me@example.com".to_string(),
            label: "My Name".to_string(),
            is_admin: true,
            created_at: now,
            updated_at: now,
        },
        DbUser {
            sequence_number: Some(2),
            id: "other".to_string(),
            account: "other@example.com".to_string(),
            label: "Other User".to_string(),
            is_admin: false,
            created_at: now,
            updated_at: now,
        },
    ];

    let masked = mask_users(users, "me");
    assert_eq!(masked[0].account, "me@example.com");
    assert_eq!(masked[0].label, "My Name");
    assert_eq!(masked[1].account, "o***@***");
    assert_eq!(masked[1].label, "O*** U***");
}

#[test]
fn test_mask_users_filters_demo_placeholder() {
    use chrono::Utc;
    let now = Utc::now();
    let users = vec![
        DbUser {
            sequence_number: Some(1),
            id: oauth2_passkey::DEMO_PLACEHOLDER_USER_ID.to_string(),
            account: "system@demo.local".to_string(),
            label: "[Demo Placeholder]".to_string(),
            is_admin: true,
            created_at: now,
            updated_at: now,
        },
        DbUser {
            sequence_number: Some(2),
            id: "real_user".to_string(),
            account: "real@example.com".to_string(),
            label: "Real User".to_string(),
            is_admin: true,
            created_at: now,
            updated_at: now,
        },
    ];

    let masked = mask_users(users, "real_user");
    // Placeholder should be filtered out
    assert_eq!(masked.len(), 1);
    assert_eq!(masked[0].id, "real_user");
    assert_eq!(masked[0].account, "real@example.com"); // Own data unmasked
}
