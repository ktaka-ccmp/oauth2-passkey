use crate::session::SessionError;
use crate::utils::UtilError;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum OAuth2Error {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Id mismatch")]
    IdMismatch,

    #[error("Serde error: {0}")]
    Serde(String),

    #[error("Security token not found: {0}")]
    SecurityTokenNotFound(String),

    #[error("Nonce expired")]
    NonceExpired,

    #[error("Nonce mismatch")]
    NonceMismatch,

    #[error("Csrf token mismatch")]
    CsrfTokenMismatch,

    #[error("Csrf token expired")]
    CsrfTokenExpired,

    #[error("User agent mismatch")]
    UserAgentMismatch,

    #[error("Id token error: {0}")]
    IdToken(String),

    #[error("Invalid origin: {0}")]
    InvalidOrigin(String),

    #[error("Decode state error: {0}")]
    DecodeState(String),

    #[error("Fetch user info error: {0}")]
    FetchUserInfo(String),

    #[error("Token exchange error: {0}")]
    TokenExchange(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),

    /// Error from utils operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    /// Error from session operations
    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    #[error("Invalid mode: {0}")]
    InvalidMode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionError;
    use crate::utils::UtilError;

    #[test]
    fn test_error_is_sync_and_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<OAuth2Error>();
    }

    #[test]
    fn test_error_is_cloneable() {
        let err = OAuth2Error::Storage("test error".to_string());
        let cloned = err.clone();

        if let OAuth2Error::Storage(msg) = cloned {
            assert_eq!(msg, "test error");
        } else {
            panic!("Wrong error type after cloning");
        }
    }

    #[test]
    fn test_error_display() {
        // Test basic error variants
        let err = OAuth2Error::Storage("storage error".to_string());
        assert_eq!(err.to_string(), "Storage error: storage error");

        let err = OAuth2Error::Crypto("crypto error".to_string());
        assert_eq!(err.to_string(), "Crypto error: crypto error");

        let err = OAuth2Error::Encoding("encoding error".to_string());
        assert_eq!(err.to_string(), "Encoding error: encoding error");

        let err = OAuth2Error::Cookie("cookie error".to_string());
        assert_eq!(err.to_string(), "Cookie error: cookie error");

        let err = OAuth2Error::IdMismatch;
        assert_eq!(err.to_string(), "Id mismatch");

        let err = OAuth2Error::Serde("serde error".to_string());
        assert_eq!(err.to_string(), "Serde error: serde error");

        let err = OAuth2Error::SecurityTokenNotFound("token".to_string());
        assert_eq!(err.to_string(), "Security token not found: token");

        let err = OAuth2Error::NonceExpired;
        assert_eq!(err.to_string(), "Nonce expired");

        let err = OAuth2Error::NonceMismatch;
        assert_eq!(err.to_string(), "Nonce mismatch");

        let err = OAuth2Error::CsrfTokenMismatch;
        assert_eq!(err.to_string(), "Csrf token mismatch");

        let err = OAuth2Error::CsrfTokenExpired;
        assert_eq!(err.to_string(), "Csrf token expired");

        let err = OAuth2Error::UserAgentMismatch;
        assert_eq!(err.to_string(), "User agent mismatch");

        let err = OAuth2Error::IdToken("id token error".to_string());
        assert_eq!(err.to_string(), "Id token error: id token error");

        let err = OAuth2Error::InvalidOrigin("origin".to_string());
        assert_eq!(err.to_string(), "Invalid origin: origin");

        let err = OAuth2Error::DecodeState("decode error".to_string());
        assert_eq!(err.to_string(), "Decode state error: decode error");

        let err = OAuth2Error::FetchUserInfo("fetch error".to_string());
        assert_eq!(err.to_string(), "Fetch user info error: fetch error");

        let err = OAuth2Error::TokenExchange("exchange error".to_string());
        assert_eq!(err.to_string(), "Token exchange error: exchange error");

        let err = OAuth2Error::Database("db error".to_string());
        assert_eq!(err.to_string(), "Database error: db error");

        let err = OAuth2Error::Internal("internal error".to_string());
        assert_eq!(err.to_string(), "Internal error: internal error");

        let err = OAuth2Error::InvalidMode("mode".to_string());
        assert_eq!(err.to_string(), "Invalid mode: mode");
    }

    #[test]
    fn test_from_util_error() {
        let util_err = UtilError::Format("format error".to_string());
        let err: OAuth2Error = util_err.into();

        if let OAuth2Error::Utils(inner) = err {
            if let UtilError::Format(msg) = inner {
                assert_eq!(msg, "format error");
            } else {
                panic!("Wrong inner error type");
            }
        } else {
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_from_session_error() {
        let session_err = SessionError::Storage("session error".to_string());
        let err: OAuth2Error = session_err.into();

        if let OAuth2Error::Session(inner) = err {
            if let SessionError::Storage(msg) = inner {
                assert_eq!(msg, "session error");
            } else {
                panic!("Wrong inner error type");
            }
        } else {
            panic!("Wrong error type");
        }
    }
}
