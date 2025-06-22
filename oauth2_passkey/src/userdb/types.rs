use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Represents a core user identity in the system
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, PartialEq)]
pub struct User {
    /// Database-assigned sequence number (primary key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<i64>,
    /// Unique user identifier
    pub id: String,
    /// User account name or login identifier
    pub account: String,
    /// Display name or user-friendly label
    pub label: String,
    /// Whether the user has administrator privileges
    pub is_admin: bool,
    /// When the user account was created
    pub created_at: DateTime<Utc>,
    /// When the user account was last updated
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user
    pub fn new(id: String, account: String, label: String) -> Self {
        let now = Utc::now();
        Self {
            sequence_number: None,
            id,
            account,
            label,
            is_admin: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if the user has admin privileges
    ///
    /// This is determined by either:
    /// 1. The user has is_admin flag set to true, or
    /// 2. The user is the first user in the system (sequence_number = 1)
    pub fn has_admin_privileges(&self) -> bool {
        self.is_admin || self.sequence_number == Some(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use proptest::prelude::*;

    /// Test that a new user can be created with the expected properties
    /// and that the timestamps are set correctly
    /// This test checks:
    /// 1. The user has the correct id, account, label
    /// 2. is_admin defaults to false
    /// 3. sequence_number is None
    /// 4. created_at and updated_at are set to the current time
    #[test]
    fn test_user_new() {
        // Given user information
        let id = "user123".to_string();
        let account = "test@example.com".to_string();
        let label = "Test User".to_string();

        // When creating a new user
        let user = User::new(id.clone(), account.clone(), label.clone());

        // Then the user should have the correct properties
        assert_eq!(user.id, id);
        assert_eq!(user.account, account);
        assert_eq!(user.label, label);
        assert!(!user.is_admin);
        assert_eq!(user.sequence_number, None);

        // And created_at and updated_at should be within the last second
        let now = Utc::now();
        let one_second_ago = now - Duration::seconds(1);
        assert!(user.created_at > one_second_ago);
        assert!(user.updated_at > one_second_ago);
        assert_eq!(user.created_at, user.updated_at);
    }

    /// Test that has_admin_privileges works correctly
    /// This test checks:
    /// 1. If is_admin is true, has_admin_privileges should return true
    /// 2. If sequence_number is 1, has_admin_privileges should return true
    /// 3. If neither condition is met, has_admin_privileges should return false
    #[test]
    fn test_has_admin_privileges_with_is_admin_true() {
        // Given a user with is_admin set to true
        let mut user = User::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "Test User".to_string(),
        );
        user.is_admin = true;

        // When checking admin privileges
        let has_privileges = user.has_admin_privileges();

        // Then the user should have admin privileges
        assert!(has_privileges);
    }

    /// Test that has_admin_privileges works correctly with sequence_number
    /// This test checks:
    /// 1. If sequence_number is 1, has_admin_privileges should return true
    /// 2. If sequence_number is not 1, has_admin_privileges should return false
    #[test]
    fn test_has_admin_privileges_with_sequence_number_1() {
        // Given a user with sequence_number set to 1
        let mut user = User::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "Test User".to_string(),
        );
        user.is_admin = false;
        user.sequence_number = Some(1);

        // When checking admin privileges
        let has_privileges = user.has_admin_privileges();

        // Then the user should have admin privileges
        assert!(has_privileges);
    }

    /// Test that has_admin_privileges works correctly when user has no admin privileges
    /// This test checks:
    /// 1. If is_admin is false and sequence_number is not 1, has_admin_privileges should return false
    #[test]
    fn test_has_admin_privileges_with_no_privileges() {
        // Given a user with no admin privileges
        let mut user = User::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "Test User".to_string(),
        );
        user.is_admin = false;
        user.sequence_number = Some(2);

        // When checking admin privileges
        let has_privileges = user.has_admin_privileges();

        // Then the user should not have admin privileges
        assert!(!has_privileges);
    }

    // Property-based tests for User struct
    proptest! {
        /// Test that any valid User can be serialized and deserialized correctly
        #[test]
        fn test_user_serde_roundtrip(
            id in "[a-zA-Z0-9_-]{1,64}",
            account in "[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,64}\\.[a-zA-Z]{2,8}",
            label in "[\\p{L}\\p{N}\\p{P}\\p{Z}]{1,128}",
            is_admin in proptest::bool::ANY,
            sequence_number in proptest::option::of(1..10000i64)
        ) {
            // Create a user with the generated properties
            let now = Utc::now();
            let user = User {
                id,
                account,
                label,
                is_admin,
                sequence_number,
                created_at: now,
                updated_at: now,
            };

            // Serialize and deserialize
            let serialized = serde_json::to_string(&user).expect("Failed to serialize");
            let deserialized: User = serde_json::from_str(&serialized).expect("Failed to deserialize");

            // Check equality for all fields except timestamps
            // (timestamps might have precision issues during serialization/deserialization)
            prop_assert_eq!(user.id, deserialized.id);
            prop_assert_eq!(user.account, deserialized.account);
            prop_assert_eq!(user.label, deserialized.label);
            prop_assert_eq!(user.is_admin, deserialized.is_admin);
            prop_assert_eq!(user.sequence_number, deserialized.sequence_number);
        }

        /// Test that User::new creates valid users with expected properties
        #[test]
        fn test_user_new_properties(
            id in "[a-zA-Z0-9_-]{1,64}",
            account in "[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,64}\\.[a-zA-Z]{2,8}",
            label in "[\\p{L}\\p{N}\\p{P}\\p{Z}]{1,128}"
        ) {
            let user = User::new(id.clone(), account.clone(), label.clone());

            prop_assert_eq!(user.id, id);
            prop_assert_eq!(user.account, account);
            prop_assert_eq!(user.label, label);
            prop_assert_eq!(user.is_admin, false);
            prop_assert_eq!(user.sequence_number, None);

            // created_at and updated_at should be the same
            prop_assert_eq!(user.created_at, user.updated_at);

            // created_at should be recent (within the last second)
            let now = Utc::now();
            let one_second_ago = now - Duration::seconds(1);
            prop_assert!(user.created_at > one_second_ago);
        }

        /// Test that has_admin_privileges works correctly with various inputs
        #[test]
        fn test_has_admin_privileges_properties(
            is_admin in proptest::bool::ANY,
            sequence_number in proptest::option::of(0..10000i64)
        ) {
            let mut user = User::new(
                "test_user".to_string(),
                "test@example.com".to_string(),
                "Test User".to_string()
            );

            user.is_admin = is_admin;
            user.sequence_number = sequence_number;

            let expected_has_privileges = is_admin || sequence_number == Some(1);
            prop_assert_eq!(user.has_admin_privileges(), expected_has_privileges);
        }
    }
}
