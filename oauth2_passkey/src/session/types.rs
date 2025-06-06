use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::session::errors::SessionError;
use crate::storage::CacheData;
use crate::userdb::User as DbUser;

// User information from libuserdb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub account: String,
    pub label: String,
    pub is_admin: bool,
    pub sequence_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
            account: db_user.account,
            label: db_user.label,
            is_admin: db_user.is_admin,
            sequence_number: db_user.sequence_number.unwrap_or(0),
            created_at: db_user.created_at,
            updated_at: db_user.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredSession {
    pub(super) user_id: String,
    pub(super) csrf_token: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) ttl: u64,
}

impl From<StoredSession> for CacheData {
    fn from(data: StoredSession) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize StoredSession"),
        }
    }
}

impl TryFrom<CacheData> for StoredSession {
    type Error = SessionError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| SessionError::Storage(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct CsrfToken(String);

/// Indicates whether the CSRF token was verified via an HTTP header by a calling layer (e.g., middleware).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsrfHeaderVerified(pub bool);

/// Indicates the overall authentication status of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticationStatus(pub bool);

impl std::fmt::Display for AuthenticationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for CsrfHeaderVerified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CsrfToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct UserId(String);

impl UserId {
    pub fn new(id: String) -> Self {
        Self(id)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_user_from_db_user() {
        let now = Utc::now();
        let db_user = DbUser {
            id: "user123".to_string(),
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: true,
            sequence_number: Some(42),
            created_at: now,
            updated_at: now,
        };

        let session_user = User::from(db_user);

        assert_eq!(session_user.id, "user123");
        assert_eq!(session_user.account, "test@example.com");
        assert_eq!(session_user.label, "Test User");
        assert!(session_user.is_admin);
        assert_eq!(session_user.sequence_number, 42);
        assert_eq!(session_user.created_at, now);
        assert_eq!(session_user.updated_at, now);
    }

    #[test]
    fn test_user_from_db_user_with_no_sequence() {
        let now = Utc::now();
        let db_user = DbUser {
            id: "user123".to_string(),
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: None,
            created_at: now,
            updated_at: now,
        };

        let session_user = User::from(db_user);

        assert_eq!(session_user.id, "user123");
        assert_eq!(session_user.account, "test@example.com");
        assert_eq!(session_user.label, "Test User");
        assert!(!session_user.is_admin);
        assert_eq!(session_user.sequence_number, 0); // Default to 0 when None
        assert_eq!(session_user.created_at, now);
        assert_eq!(session_user.updated_at, now);
    }

    #[test]
    fn test_stored_session_to_cache_data() {
        let expires_at = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let stored_session = StoredSession {
            user_id: "user123".to_string(),
            csrf_token: "token123".to_string(),
            expires_at,
            ttl: 3600,
        };

        let cache_data = CacheData::from(stored_session.clone());

        // Verify the serialization worked correctly by deserializing and comparing
        let deserialized: StoredSession = serde_json::from_str(&cache_data.value).unwrap();
        assert_eq!(deserialized.user_id, "user123");
        assert_eq!(deserialized.csrf_token, "token123");
        assert_eq!(deserialized.expires_at, expires_at);
        assert_eq!(deserialized.ttl, 3600);
    }

    #[test]
    fn test_cache_data_to_stored_session() {
        let expires_at = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let stored_session = StoredSession {
            user_id: "user123".to_string(),
            csrf_token: "token123".to_string(),
            expires_at,
            ttl: 3600,
        };

        let json = serde_json::to_string(&stored_session).unwrap();
        let cache_data = CacheData { value: json };

        let result = StoredSession::try_from(cache_data);
        assert!(result.is_ok());

        let converted = result.unwrap();
        assert_eq!(converted.user_id, "user123");
        assert_eq!(converted.csrf_token, "token123");
        assert_eq!(converted.expires_at, expires_at);
        assert_eq!(converted.ttl, 3600);
    }

    #[test]
    fn test_cache_data_to_stored_session_invalid_json() {
        let cache_data = CacheData {
            value: "invalid json".to_string(),
        };
        let result = StoredSession::try_from(cache_data);
        assert!(result.is_err());
        match result {
            Err(SessionError::Storage(_)) => {} // Expected error type
            _ => panic!("Expected SessionError::Storage"),
        }
    }
}
