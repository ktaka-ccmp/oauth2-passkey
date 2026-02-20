use super::*;

#[test]
fn test_mask_email() {
    assert_eq!(mask_email("user@example.com"), "***");
    assert_eq!(mask_email("a@b.org"), "***");
    assert_eq!(mask_email("test"), "***");
}

#[test]
fn test_mask_name() {
    assert_eq!(mask_name("John Smith"), "***");
    assert_eq!(mask_name("Alice"), "***");
    assert_eq!(mask_name(""), "***");
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

    let masker = Masker::always_active();
    let masked = masker.mask_users(users, "me");
    assert_eq!(masked[0].account, "me@example.com");
    assert_eq!(masked[0].label, "My Name");
    assert_eq!(masked[1].account, "***");
    assert_eq!(masked[1].label, "***");
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

    let masker = Masker::always_active();
    let masked = masker.mask_users(users, "real_user");
    // Placeholder should be filtered out
    assert_eq!(masked.len(), 1);
    assert_eq!(masked[0].id, "real_user");
    assert_eq!(masked[0].account, "real@example.com"); // Own data unmasked
}

#[test]
fn test_masker_inactive_returns_unchanged() {
    let masker = Masker::inactive();
    assert_eq!(masker.email("user@example.com"), "user@example.com");
    assert_eq!(masker.name("John Smith"), "John Smith");
    assert_eq!(masker.id("abc123def456"), "abc123def456");
    assert_eq!(masker.ip("192.168.1.1"), "192.168.1.1");
    assert_eq!(
        masker.user_agent("Mozilla/5.0 Chrome/120.0"),
        "Mozilla/5.0 Chrome/120.0"
    );
    assert_eq!(masker.metadata("{\"key\":\"val\"}"), "{\"key\":\"val\"}");
}

#[test]
fn test_masker_active_masks_fields() {
    let masker = Masker::always_active();
    assert_eq!(masker.email("user@example.com"), "***");
    assert_eq!(masker.name("John Smith"), "***");
    assert_eq!(masker.id("abc123def456"), "abc1***");
    assert_eq!(masker.ip("192.168.1.1"), "192.168.*.*");
    assert_eq!(masker.user_agent("Mozilla/5.0 Chrome/120.0"), "Chrome/***");
    assert_eq!(masker.metadata("{\"key\":\"val\"}"), "***");
}

#[test]
fn test_masker_inactive_mask_users_returns_unchanged() {
    use chrono::Utc;
    let now = Utc::now();
    let users = vec![
        DbUser {
            sequence_number: Some(1),
            id: "user1".to_string(),
            account: "user1@example.com".to_string(),
            label: "User One".to_string(),
            is_admin: false,
            created_at: now,
            updated_at: now,
        },
        DbUser {
            sequence_number: Some(2),
            id: oauth2_passkey::DEMO_PLACEHOLDER_USER_ID.to_string(),
            account: "system@demo.local".to_string(),
            label: "[Demo Placeholder]".to_string(),
            is_admin: true,
            created_at: now,
            updated_at: now,
        },
    ];

    let masker = Masker::inactive();
    let result = masker.mask_users(users, "user1");
    // Inactive masker returns everything unchanged (no filtering, no masking)
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].account, "user1@example.com");
    assert_eq!(result[1].account, "system@demo.local");
}

#[test]
fn test_masker_inactive_mask_user_returns_unchanged() {
    use chrono::Utc;
    let now = Utc::now();
    let user = DbUser {
        sequence_number: Some(1),
        id: "user1".to_string(),
        account: "user1@example.com".to_string(),
        label: "User One".to_string(),
        is_admin: false,
        created_at: now,
        updated_at: now,
    };

    let masker = Masker::inactive();
    let result = masker.mask_user(user);
    assert_eq!(result.account, "user1@example.com");
    assert_eq!(result.label, "User One");
}
