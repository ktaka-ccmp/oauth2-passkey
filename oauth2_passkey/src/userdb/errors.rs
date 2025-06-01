use thiserror::Error;

#[derive(Clone, Error, Debug)]
pub enum UserError {
    #[error("User not found")]
    NotFound,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

impl From<serde_json::Error> for UserError {
    fn from(err: serde_json::Error) -> Self {
        UserError::InvalidData(err.to_string())
    }
}

impl From<redis::RedisError> for UserError {
    fn from(err: redis::RedisError) -> Self {
        UserError::Storage(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_error_display() {
        // Test NotFound variant
        let error = UserError::NotFound;
        assert_eq!(error.to_string(), "User not found");

        // Test Storage variant
        let error = UserError::Storage("Database connection failed".to_string());
        assert_eq!(
            error.to_string(),
            "Storage error: Database connection failed"
        );

        // Test InvalidData variant
        let error = UserError::InvalidData("Invalid JSON".to_string());
        assert_eq!(error.to_string(), "Invalid data: Invalid JSON");
    }

    #[test]
    fn test_from_serde_json_error() {
        // Create a serde_json::Error
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();

        // Convert to UserError
        let user_error = UserError::from(json_error);

        // Verify it's the correct variant
        match user_error {
            UserError::InvalidData(msg) => {
                assert!(
                    msg.contains("expected value"),
                    "Error message should contain the original error"
                );
            }
            _ => panic!("Expected InvalidData variant"),
        }
    }

    #[test]
    fn test_from_redis_error() {
        // Create a redis::RedisError
        let redis_error =
            redis::RedisError::from((redis::ErrorKind::IoError, "Connection refused"));

        // Convert to UserError
        let user_error = UserError::from(redis_error);

        // Verify it's the correct variant
        match user_error {
            UserError::Storage(msg) => {
                assert!(
                    msg.contains("Connection refused"),
                    "Error message should contain the original error"
                );
            }
            _ => panic!("Expected Storage variant"),
        }
    }

    #[test]
    fn test_error_is_sync_and_send() {
        // This test verifies that UserError implements Send and Sync
        fn assert_send_sync<T: Send + Sync>() {}

        // UserError should be Send + Sync
        assert_send_sync::<UserError>();
    }

    #[test]
    fn test_error_is_cloneable() {
        // Test that UserError can be cloned
        let error = UserError::NotFound;
        let cloned = error.clone();

        // Both should have the same string representation
        assert_eq!(error.to_string(), cloned.to_string());
    }
}
