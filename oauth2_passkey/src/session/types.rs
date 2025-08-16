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

impl User {
    /// Determines if the user has administrative privileges.
    ///
    /// A user has admin privileges if:
    /// 1. They have the `is_admin` flag set to true, OR
    /// 2. They are the first user in the system (sequence_number = 1)
    ///
    /// This method provides consistent admin privilege checking across the codebase
    /// and ensures the first user always has admin access regardless of the is_admin flag.
    ///
    /// # Returns
    /// * `true` if the user has administrative privileges
    /// * `false` otherwise
    ///
    /// # Examples
    /// ```
    /// use oauth2_passkey::SessionUser as User;
    /// use chrono::Utc;
    ///
    /// // Regular admin user
    /// let admin_user = User {
    ///     id: "user1".to_string(),
    ///     account: "admin@example.com".to_string(),
    ///     label: "Admin User".to_string(),
    ///     is_admin: true,
    ///     sequence_number: Some(5),
    ///     created_at: Utc::now(),
    ///     updated_at: Utc::now(),
    /// };
    /// assert!(admin_user.has_admin_privileges());
    ///
    /// // First user (always admin)
    /// let first_user = User {
    ///     id: "user1".to_string(),
    ///     account: "first@example.com".to_string(),
    ///     label: "First User".to_string(),
    ///     is_admin: false,
    ///     sequence_number: Some(1),
    ///     created_at: Utc::now(),
    ///     updated_at: Utc::now(),
    /// };
    /// assert!(first_user.has_admin_privileges());
    ///
    /// // Regular user
    /// let regular_user = User {
    ///     id: "user1".to_string(),
    ///     account: "user@example.com".to_string(),
    ///     label: "Regular User".to_string(),
    ///     is_admin: false,
    ///     sequence_number: Some(2),
    ///     created_at: Utc::now(),
    ///     updated_at: Utc::now(),
    /// };
    /// assert!(!regular_user.has_admin_privileges());
    /// ```
    /// IMPORTANT: This logic must stay in sync with DbUser::has_admin_privileges()
    /// and AuthUser::has_admin_privileges() implementations.
    pub fn has_admin_privileges(&self) -> bool {
        self.is_admin || self.sequence_number == Some(1)
    }
}

#[cfg(test)]
mod tests {
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

/// Type-safe wrapper for user identifiers.
///
/// This provides compile-time safety to prevent mixing up user IDs with other string types.
/// It's used in coordination layer functions to ensure type safety when passing user identifiers.
#[derive(Debug, Clone, PartialEq)]
pub struct UserId(String);

impl UserId {
    /// Creates a new UserId from a string.
    ///
    /// # Arguments
    /// * `id` - The user ID string
    ///
    /// # Returns
    /// * A new UserId instance
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the user ID as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the user ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for session identifiers.
///
/// This provides compile-time safety to prevent mixing up session IDs with other string types.
/// It's used in coordination layer functions to ensure type safety when passing session identifiers.
#[derive(Debug, Clone)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a new SessionId from a string.
    ///
    /// # Arguments
    /// * `id` - The session ID string
    ///
    /// # Returns
    /// * A new SessionId instance
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the session ID as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the session ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for session cookies.
///
/// This provides compile-time safety to prevent mixing up session cookies with other string types.
/// Session cookies are HTTP cookie values used for user session identification and must be
/// properly validated to prevent session hijacking and other security issues.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionCookie(String);

impl SessionCookie {
    /// Creates a new SessionCookie from a string with validation.
    ///
    /// This constructor validates the session cookie format to ensure it meets
    /// security requirements for session identification.
    ///
    /// # Arguments
    /// * `cookie` - The session cookie string
    ///
    /// # Returns
    /// * `Ok(SessionCookie)` - If the cookie is valid
    /// * `Err(SessionError)` - If the cookie is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain only valid characters (alphanumeric + basic symbols)
    /// * Must be reasonable length (not too short or too long)
    pub fn new(cookie: String) -> Result<Self, crate::session::SessionError> {
        use crate::session::SessionError;

        // Validate cookie is not empty
        if cookie.is_empty() {
            return Err(SessionError::Cookie(
                "Session cookie cannot be empty".to_string(),
            ));
        }

        // Validate cookie length (reasonable bounds)
        if cookie.len() < 10 {
            return Err(SessionError::Cookie("Session cookie too short".to_string()));
        }

        if cookie.len() > 1024 {
            return Err(SessionError::Cookie("Session cookie too long".to_string()));
        }

        // Validate cookie contains only safe characters
        // Allow alphanumeric, hyphens, underscores, equals signs, and basic URL-safe characters
        if !cookie
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '=' | '.' | '+' | '/'))
        {
            return Err(SessionError::Cookie(
                "Session cookie contains invalid characters".to_string(),
            ));
        }

        Ok(SessionCookie(cookie))
    }

    /// Returns the session cookie as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the session cookie
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
