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
    use std::error::Error;

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

        match err {
            OAuth2Error::Utils(UtilError::Format(msg)) => {
                assert_eq!(msg, "format error");
            }
            _ => panic!(
                "Expected OAuth2Error::Utils(UtilError::Format), got: {:?}",
                err
            ),
        }
    }

    #[test]
    fn test_from_session_error() {
        let session_err = SessionError::Storage("session error".to_string());
        let err: OAuth2Error = session_err.into();

        match err {
            OAuth2Error::Session(SessionError::Storage(msg)) => {
                assert_eq!(msg, "session error");
            }
            _ => panic!(
                "Expected OAuth2Error::Session(SessionError::Storage), got: {:?}",
                err
            ),
        }
    }

    #[test]
    fn test_error_source_chaining() {
        // Test that From conversions preserve error sources
        let util_err = UtilError::Format("format error".to_string());
        let oauth2_err: OAuth2Error = util_err.into();

        // The source should be the original UtilError
        match oauth2_err.source() {
            Some(source) => {
                assert_eq!(source.to_string(), "Invalid format: format error");
            }
            None => panic!("Expected error to have a source"),
        }

        let session_err = SessionError::Storage("session error".to_string());
        let oauth2_err: OAuth2Error = session_err.into();

        // The source should be the original SessionError
        match oauth2_err.source() {
            Some(source) => {
                assert_eq!(source.to_string(), "Storage error: session error");
            }
            None => panic!("Expected error to have a source"),
        }
    }

    #[test]
    fn test_error_equality_and_cloning() {
        // Test that errors can be cloned and compared properly
        let err1 = OAuth2Error::Storage("storage error".to_string());
        let err2 = err1.clone();

        // Both should have the same display string
        assert_eq!(err1.to_string(), err2.to_string());

        // Test different error types
        let crypto_err = OAuth2Error::Crypto("crypto error".to_string());
        assert_ne!(err1.to_string(), crypto_err.to_string());

        // Test parameterless errors
        let nonce_expired1 = OAuth2Error::NonceExpired;
        let nonce_expired2 = OAuth2Error::NonceExpired;
        assert_eq!(nonce_expired1.to_string(), nonce_expired2.to_string());
    }

    #[test]
    fn test_error_conversion_edge_cases() {
        // Test all UtilError variants conversion
        let crypto_err = UtilError::Crypto("crypto error".to_string());
        let oauth2_err: OAuth2Error = crypto_err.into();
        match oauth2_err {
            OAuth2Error::Utils(UtilError::Crypto(msg)) => {
                assert_eq!(msg, "crypto error");
            }
            _ => panic!(
                "Expected OAuth2Error::Utils(UtilError::Crypto), got: {:?}",
                oauth2_err
            ),
        }

        let cookie_err = UtilError::Cookie("cookie error".to_string());
        let oauth2_err: OAuth2Error = cookie_err.into();
        match oauth2_err {
            OAuth2Error::Utils(UtilError::Cookie(msg)) => {
                assert_eq!(msg, "cookie error");
            }
            _ => panic!(
                "Expected OAuth2Error::Utils(UtilError::Cookie), got: {:?}",
                oauth2_err
            ),
        }

        // Test all SessionError variants conversion
        let crypto_session_err = SessionError::Crypto("session crypto error".to_string());
        let oauth2_err: OAuth2Error = crypto_session_err.into();
        match oauth2_err {
            OAuth2Error::Session(SessionError::Crypto(msg)) => {
                assert_eq!(msg, "session crypto error");
            }
            _ => panic!(
                "Expected OAuth2Error::Session(SessionError::Crypto), got: {:?}",
                oauth2_err
            ),
        }

        let cookie_session_err = SessionError::Cookie("session cookie error".to_string());
        let oauth2_err: OAuth2Error = cookie_session_err.into();
        match oauth2_err {
            OAuth2Error::Session(SessionError::Cookie(msg)) => {
                assert_eq!(msg, "session cookie error");
            }
            _ => panic!(
                "Expected OAuth2Error::Session(SessionError::Cookie), got: {:?}",
                oauth2_err
            ),
        }
    }

    #[test]
    fn test_error_display_edge_cases() {
        // Test errors with empty strings
        let err = OAuth2Error::Storage("".to_string());
        assert_eq!(err.to_string(), "Storage error: ");

        // Test errors with special characters
        let err = OAuth2Error::Internal("Error with \"quotes\" and 'apostrophes'".to_string());
        assert_eq!(
            err.to_string(),
            "Internal error: Error with \"quotes\" and 'apostrophes'"
        );

        // Test errors with newlines and tabs
        let err = OAuth2Error::Database("Error\nwith\nnewlines\tand\ttabs".to_string());
        assert_eq!(
            err.to_string(),
            "Database error: Error\nwith\nnewlines\tand\ttabs"
        );

        // Test wrapped errors display properly
        let util_err = UtilError::Format("nested error".to_string());
        let oauth2_err: OAuth2Error = util_err.into();
        assert_eq!(
            oauth2_err.to_string(),
            "Utils error: Invalid format: nested error"
        );

        let session_err = SessionError::Storage("nested session error".to_string());
        let oauth2_err: OAuth2Error = session_err.into();
        assert_eq!(
            oauth2_err.to_string(),
            "Session error: Storage error: nested session error"
        );
    }
}
