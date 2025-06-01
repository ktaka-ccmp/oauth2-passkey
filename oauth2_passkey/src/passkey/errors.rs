use thiserror::Error;

use crate::utils::UtilError;

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid challenge: {0}")]
    Challenge(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Registration error: {0}")]
    Registration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Json conversion(Serde) error: {0}")]
    Serde(String),

    #[error("Invalid client data: {0}")]
    ClientData(String),

    #[error("Invalid authenticator data: {0}")]
    AuthenticatorData(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Not found error: {0}")]
    NotFound(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid format: {0}")]
    Format(String),

    #[error("Unauthorized error: {0}")]
    Unauthorized(String),

    #[error("{0}")]
    Other(String),

    /// Error from utils operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    /// Error from redis operations
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Error from serde operations
    #[error("Serde error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_error_display() {
        // Test each error variant's Display implementation
        let errors = [
            (
                PasskeyError::Config("test config error".to_string()),
                "Configuration error: test config error",
            ),
            (
                PasskeyError::Challenge("test challenge error".to_string()),
                "Invalid challenge: test challenge error",
            ),
            (
                PasskeyError::Authentication("test auth error".to_string()),
                "Authentication error: test auth error",
            ),
            (
                PasskeyError::Registration("test reg error".to_string()),
                "Registration error: test reg error",
            ),
            (
                PasskeyError::Storage("test storage error".to_string()),
                "Storage error: test storage error",
            ),
            (
                PasskeyError::Serde("test serde error".to_string()),
                "Json conversion(Serde) error: test serde error",
            ),
            (
                PasskeyError::ClientData("test client data error".to_string()),
                "Invalid client data: test client data error",
            ),
            (
                PasskeyError::AuthenticatorData("test auth data error".to_string()),
                "Invalid authenticator data: test auth data error",
            ),
            (
                PasskeyError::Verification("test verification error".to_string()),
                "Verification error: test verification error",
            ),
            (
                PasskeyError::NotFound("test not found error".to_string()),
                "Not found error: test not found error",
            ),
            (
                PasskeyError::Crypto("test crypto error".to_string()),
                "Crypto error: test crypto error",
            ),
            (
                PasskeyError::Format("test format error".to_string()),
                "Invalid format: test format error",
            ),
            (
                PasskeyError::Unauthorized("test unauthorized error".to_string()),
                "Unauthorized error: test unauthorized error",
            ),
            (
                PasskeyError::Other("test other error".to_string()),
                "test other error",
            ),
            (
                PasskeyError::Utils(UtilError::Format("test format error".to_string())),
                "Utils error: Invalid format: test format error",
            ),
            (
                PasskeyError::Redis(redis::RedisError::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test redis error",
                ))),
                "Redis error: test redis error",
            ),
            // Create a serde_json::Error by attempting to deserialize invalid JSON
            (
                PasskeyError::SerdeJson(
                    serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err(),
                ),
                "Serde error: key must be a string at line 1 column 2",
            ),
        ];

        for (error, expected_message) in errors.iter() {
            assert_eq!(error.to_string(), *expected_message);
        }
    }

    #[test]
    fn test_passkey_error_from_util_error() {
        // Test conversion from UtilError to PasskeyError
        let util_error = UtilError::Format("test format error".to_string());
        let passkey_error: PasskeyError = util_error.into();

        match passkey_error {
            PasskeyError::Utils(UtilError::Format(msg)) => {
                assert_eq!(msg, "test format error");
            }
            _ => panic!("Expected PasskeyError::Utils variant"),
        }
    }

    #[test]
    fn test_passkey_error_from_redis_error() {
        // Test conversion from redis::RedisError to PasskeyError
        let redis_error = redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test redis error",
        ));
        let passkey_error: PasskeyError = redis_error.into();

        match passkey_error {
            PasskeyError::Redis(_) => {
                // Successfully converted
            }
            _ => panic!("Expected PasskeyError::Redis variant"),
        }
    }

    #[test]
    fn test_passkey_error_from_serde_error() {
        // Test conversion from serde_json::Error to PasskeyError
        // Create a serde_json::Error by attempting to deserialize invalid JSON
        let serde_error = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let passkey_error: PasskeyError = serde_error.into();

        match passkey_error {
            PasskeyError::SerdeJson(_) => {
                // Successfully converted
            }
            _ => panic!("Expected PasskeyError::SerdeJson variant"),
        }
    }
}
