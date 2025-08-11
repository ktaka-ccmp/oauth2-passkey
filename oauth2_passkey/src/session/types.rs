use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::session::errors::SessionError;
use crate::storage::CacheData;
use crate::userdb::User as DbUser;

/// User information stored in the session.
///
/// This struct represents authenticated user data that is stored in the session
/// and retrieved during authentication checks. It contains essential user identity
/// and permission information needed for the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user
    pub id: String,
    /// User account name or login identifier
    pub account: String,
    /// Display name or label for the user
    pub label: String,
    /// Whether the user has administrative privileges
    pub is_admin: bool,
    /// Database-assigned sequence number (primary key), None for users not yet persisted
    pub sequence_number: Option<i64>,
    /// When the user account was created
    pub created_at: DateTime<Utc>,
    /// When the user account was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
            account: db_user.account,
            label: db_user.label,
            is_admin: db_user.is_admin,
            sequence_number: db_user.sequence_number,
            created_at: db_user.created_at,
            updated_at: db_user.updated_at,
        }
    }
}

impl From<User> for DbUser {
    fn from(session_user: User) -> Self {
        Self {
            id: session_user.id,
            account: session_user.account,
            label: session_user.label,
            is_admin: session_user.is_admin,
            sequence_number: session_user.sequence_number,
            created_at: session_user.created_at,
            updated_at: session_user.updated_at,
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
            expires_at: data.expires_at,
        }
    }
}

impl TryFrom<CacheData> for StoredSession {
    type Error = SessionError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| SessionError::Storage(e.to_string()))
    }
}

/// CSRF (Cross-Site Request Forgery) token for request validation.
///
/// This struct represents a security token that must be included in forms
/// and state-changing requests to prevent cross-site request forgery attacks.
/// It's a newtype wrapper around a String to provide type safety and prevent
/// confusion with other string types.
#[derive(Debug, Clone)]
pub struct CsrfToken(String);

/// Indicates whether the CSRF token was verified via an HTTP header.
///
/// This is typically set by middleware or other authentication layers that have
/// already performed CSRF validation. It's used to avoid redundant validation
/// when multiple layers of authentication checks are applied.
///
/// Contains a boolean where `true` means the CSRF token was already verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsrfHeaderVerified(pub bool);

/// Indicates the overall authentication status of a session.
///
/// This is a simple boolean wrapper that indicates whether a user is authenticated.
/// It's used as a return type from authentication check functions to explicitly
/// communicate the authentication state.
///
/// Contains a boolean where `true` means the user is authenticated.
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
    /// Creates a new CSRF token from a string.
    ///
    /// # Arguments
    /// * `token` - The token string
    ///
    /// # Returns
    /// * A new CsrfToken instance
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Returns the token as a string slice.
    ///
    /// This method is useful when you need to include the token in a
    /// response or use it for comparison.
    ///
    /// # Returns
    /// * A string slice containing the token
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
