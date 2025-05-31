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
    fn test_session_error_display() {
        let error = SessionError::SessionError;
        assert_eq!(error.to_string(), "Session error");
    }

    #[test]
    fn test_storage_error_display() {
        let error = SessionError::Storage("Failed to access cache".to_string());
        assert_eq!(error.to_string(), "Storage error: Failed to access cache");
    }

    #[test]
    fn test_crypto_error_display() {
        let error = SessionError::Crypto("Invalid key".to_string());
        assert_eq!(error.to_string(), "Crypto error: Invalid key");
    }

    #[test]
    fn test_cookie_error_display() {
        let error = SessionError::Cookie("Invalid cookie format".to_string());
        assert_eq!(error.to_string(), "Cookie error: Invalid cookie format");
    }

    #[test]
    fn test_page_session_token_error_display() {
        let error = SessionError::PageSessionToken("Token mismatch".to_string());
        assert_eq!(
            error.to_string(),
            "Page session token error: Token mismatch"
        );
    }

    #[test]
    fn test_csrf_token_error_display() {
        let error = SessionError::CsrfToken("Token missing".to_string());
        assert_eq!(error.to_string(), "CSRF token error: Token missing");
    }

    #[test]
    fn test_header_error_display() {
        let error = SessionError::HeaderError("Missing header".to_string());
        assert_eq!(error.to_string(), "Header error: Missing header");
    }

    #[test]
    fn test_from_util_error() {
        let util_error = UtilError::Crypto("Crypto operation failed".to_string());
        let session_error = SessionError::from(util_error);

        match session_error {
            SessionError::Utils(e) => {
                assert_eq!(e.to_string(), "Crypto error: Crypto operation failed");
            }
            _ => panic!("Expected Utils error variant"),
        }
    }

    #[test]
    fn test_from_user_error() {
        let user_error = UserError::NotFound;
        let session_error = SessionError::from(user_error);

        match session_error {
            SessionError::User(e) => {
                assert_eq!(e.to_string(), "User not found");
            }
            _ => panic!("Expected User error variant"),
        }
    }

    #[test]
    fn test_error_is_sync_and_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<SessionError>();
    }
}
