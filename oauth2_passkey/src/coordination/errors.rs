//! Error types for the libauth crate

use thiserror::Error;

use crate::oauth2::OAuth2Error;
use crate::passkey::PasskeyError;
use crate::session::SessionError;
use crate::userdb::UserError;
use crate::utils::UtilError;

/// Errors that can occur during authentication coordination
#[derive(Error, Debug)]
pub enum CoordinationError {
    /// General coordination error
    #[error("Coordination error: {0}")]
    Coordination(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Session mismatch error - when user in session differs from user in context
    #[error("Session mismatch: {0}")]
    SessionMismatch(String),

    /// Missing context token error
    #[error("Context token is missing")]
    MissingContextToken,

    /// Unauthorized access error
    #[error("Unauthorized access")]
    Unauthorized,

    /// Unexpectedly authorized access error
    #[error("You are already authenticated")]
    UnexpectedlyAuthorized,

    /// No content error
    #[error("No content")]
    NoContent,

    /// Invalid mode
    #[error("Invalid mode")]
    InvalidMode,

    /// Conflict error
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Invalid state error
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Resource not found with context
    #[error("Resource not found: {resource_type} {resource_id}")]
    ResourceNotFound {
        resource_type: String,
        resource_id: String,
    },

    /// Error from the user database operations
    #[error("User error: {0}")]
    UserError(UserError),

    /// Error from OAuth2 operations
    #[error("OAuth2 error: {0}")]
    OAuth2Error(OAuth2Error),

    /// Error from Passkey operations
    #[error("Passkey error: {0}")]
    PasskeyError(PasskeyError),

    /// Error from Session operations
    #[error("Session error: {0}")]
    SessionError(SessionError),

    /// Error from utils operations
    #[error("Utils error: {0}")]
    UtilsError(UtilError),

    /// Invalid response mode
    #[error("Invalid response mode: {0}")]
    InvalidResponseMode(String),
}

impl CoordinationError {
    /// Log the error and return self
    ///
    /// This method logs the error with appropriate context and returns self,
    /// allowing for method chaining and explicit logging when needed.
    ///
    pub fn log(self) -> Self {
        match &self {
            Self::Coordination(msg) => tracing::error!("Coordination error: {}", msg),
            Self::Database(msg) => tracing::error!("Database error: {}", msg),
            Self::Authentication(msg) => tracing::error!("Authentication error: {}", msg),
            Self::SessionMismatch(msg) => tracing::error!("Session mismatch: {}", msg),
            Self::MissingContextToken => tracing::error!("Context token is missing"),
            Self::Unauthorized => tracing::error!("Unauthorized access"),
            Self::UnexpectedlyAuthorized => tracing::error!("Unexpectedly authorized access"),
            Self::NoContent => tracing::error!("No content"),
            Self::InvalidMode => tracing::error!("Invalid mode"),
            Self::Conflict(message) => tracing::error!("Conflict: {}", message),
            Self::InvalidState(message) => tracing::error!("Invalid state: {}", message),
            Self::ResourceNotFound {
                resource_type,
                resource_id,
            } => tracing::error!("Resource not found: {} {}", resource_type, resource_id),
            Self::UserError(err) => tracing::error!("User error: {}", err),
            Self::OAuth2Error(err) => tracing::error!("OAuth2 error: {}", err),
            Self::PasskeyError(err) => tracing::error!("Passkey error: {}", err),
            Self::SessionError(err) => tracing::error!("Session error: {}", err),
            Self::UtilsError(err) => tracing::error!("Utils error: {}", err),
            Self::InvalidResponseMode(message) => {
                tracing::error!("Invalid response mode: {}", message)
            }
        }
        self
    }
}

// Custom From implementations that automatically log errors

impl From<OAuth2Error> for CoordinationError {
    fn from(err: OAuth2Error) -> Self {
        let error = Self::OAuth2Error(err);
        tracing::error!("{}", error);
        error
    }
}

impl From<PasskeyError> for CoordinationError {
    fn from(err: PasskeyError) -> Self {
        let error = Self::PasskeyError(err);
        tracing::error!("{}", error);
        error
    }
}

impl From<SessionError> for CoordinationError {
    fn from(err: SessionError) -> Self {
        let error = Self::SessionError(err);
        tracing::error!("{}", error);
        error
    }
}

impl From<UserError> for CoordinationError {
    fn from(err: UserError) -> Self {
        let error = Self::UserError(err);
        tracing::error!("{}", error);
        error
    }
}

impl From<UtilError> for CoordinationError {
    fn from(err: UtilError) -> Self {
        let error = Self::UtilsError(err);
        tracing::error!("{}", error);
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_sync_and_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<CoordinationError>();
    }

    #[test]
    fn test_error_log() {
        // Test that the log method returns self and works correctly
        let err = CoordinationError::Coordination("test error".to_string());
        let logged_err = err.log();

        if let CoordinationError::Coordination(msg) = logged_err {
            assert_eq!(msg, "test error");
        } else {
            panic!("Wrong error type after logging");
        }
    }
}
