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
}
