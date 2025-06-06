use thiserror::Error;

use crate::userdb::UserError;
use crate::utils::UtilError;

#[derive(Debug, Error, Clone)]
pub enum SessionError {
    #[error("Session error")]
    SessionError,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Page session token error: {0}")]
    PageSessionToken(String),

    #[error("CSRF token error: {0}")]
    CsrfToken(String),

    #[error("Session expired error")]
    SessionExpiredError,

    /// Error from utils operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    #[error("Header error: {0}")]
    HeaderError(String),

    /// Error from user database operations
    #[error("User error: {0}")]
    User(#[from] UserError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_util_error() {
        let util_error = UtilError::Crypto("Crypto operation failed".to_string());
        let session_error = SessionError::from(util_error);
        assert!(matches!(session_error, SessionError::Utils(_)));
    }

    #[test]
    fn test_from_user_error() {
        let user_error = UserError::NotFound;
        let session_error = SessionError::from(user_error);
        assert!(matches!(session_error, SessionError::User(_)));
    }

    #[test]
    fn test_error_is_sync_and_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<SessionError>();
    }
}
