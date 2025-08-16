use thiserror::Error;

use crate::storage::{CacheErrorConversion, StorageError};
use crate::userdb::UserError;
use crate::utils::UtilError;

/// Errors that can occur during session management operations.
///
/// This enum represents all possible error conditions when handling session
/// creation, validation, and management.
#[derive(Debug, Error, Clone)]
pub enum SessionError {
    /// Generic session-related error
    #[error("Session error")]
    SessionError,

    /// Error accessing or modifying stored session data
    #[error("Storage error: {0}")]
    Storage(String),

    /// Error in cryptographic operations used for session security
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Error related to cookie handling (setting, parsing)
    #[error("Cookie error: {0}")]
    Cookie(String),

    /// Error with page session tokens used for sensitive operations
    #[error("Page session token error: {0}")]
    PageSessionToken(String),

    /// Error with CSRF token validation or generation
    #[error("CSRF token error: {0}")]
    CsrfToken(String),

    /// Error when a session has expired (timeout or explicit invalidation)
    #[error("Session expired error")]
    SessionExpiredError,

    /// Error from utility operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    /// Error processing HTTP headers related to sessions
    #[error("Header error: {0}")]
    HeaderError(String),

    /// Error from user database operations
    #[error("User error: {0}")]
    User(#[from] UserError),
}

impl CacheErrorConversion<SessionError> for SessionError {
    fn convert_storage_error(error: StorageError) -> SessionError {
        SessionError::Storage(error.to_string())
    }
}
