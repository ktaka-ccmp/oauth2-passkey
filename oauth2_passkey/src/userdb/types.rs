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
    pub account: String,
    pub label: String,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
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
        assert_eq!(user.is_admin, false);
        assert_eq!(user.sequence_number, None);

        // And created_at and updated_at should be within the last second
        let now = Utc::now();
        let one_second_ago = now - Duration::seconds(1);
        assert!(user.created_at > one_second_ago);
        assert!(user.updated_at > one_second_ago);
        assert_eq!(user.created_at, user.updated_at);
    }

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

    #[test]
    fn test_user_serialization() {
        // Given a user
        let mut user = User::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "Test User".to_string(),
        );
        user.sequence_number = Some(42);

        // When serializing to JSON
        let json = serde_json::to_string(&user).expect("Failed to serialize user");

        // Then the JSON should include all fields
        assert!(json.contains("\"id\":\"user123\""));
        assert!(json.contains("\"account\":\"test@example.com\""));
        assert!(json.contains("\"label\":\"Test User\""));
        assert!(json.contains("\"is_admin\":false"));
        assert!(json.contains("\"sequence_number\":42"));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains("\"updated_at\":"));
    }

    #[test]
    fn test_user_deserialization() {
        // Given a JSON string representing a user
        let json = r#"{
            "id": "user123",
            "account": "test@example.com",
            "label": "Test User",
            "is_admin": true,
            "sequence_number": 42,
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-02T00:00:00Z"
        }"#;

        // When deserializing from JSON
        let user: User = serde_json::from_str(json).expect("Failed to deserialize user");

        // Then the user should have the correct properties
        assert_eq!(user.id, "user123");
        assert_eq!(user.account, "test@example.com");
        assert_eq!(user.label, "Test User");
        assert_eq!(user.is_admin, true);
        assert_eq!(user.sequence_number, Some(42));

        // And the dates should be parsed correctly
        let created_at = DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
            .expect("Failed to parse date")
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z")
            .expect("Failed to parse date")
            .with_timezone(&Utc);

        assert_eq!(user.created_at, created_at);
        assert_eq!(user.updated_at, updated_at);
    }

    #[test]
    fn test_user_sequence_number_serialization_when_none() {
        // Given a user with no sequence number
        let user = User::new(
            "user123".to_string(),
            "test@example.com".to_string(),
            "Test User".to_string(),
        );

        // When serializing to JSON
        let json = serde_json::to_string(&user).expect("Failed to serialize user");

        // Then the sequence_number field should be omitted
        assert!(!json.contains("sequence_number"));
    }
}
