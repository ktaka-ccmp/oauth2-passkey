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
    use crate::test_utils::init_test_environment;
    use crate::userdb::UserStore;
    use serial_test::serial;

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

    // New tests that test error propagation in realistic scenarios

    /// Test error propagation in a function that returns Result<T, UserError>
    #[test]
    fn test_error_propagation() {
        // Define a function that might return UserError
        fn validate_user_data(id: &str) -> Result<(), UserError> {
            if id.is_empty() {
                return Err(UserError::InvalidData(
                    "User ID cannot be empty".to_string(),
                ));
            }
            Ok(())
        }

        // Test with valid data
        let result = validate_user_data("user123");
        assert!(result.is_ok());

        // Test with invalid data
        let result = validate_user_data("");
        match result {
            Err(UserError::InvalidData(msg)) => {
                assert!(msg.contains("cannot be empty"));
            }
            _ => panic!("Expected InvalidData error"),
        }

        // Test error propagation through the ? operator
        fn process_user(id: &str) -> Result<String, UserError> {
            validate_user_data(id)?;
            Ok(format!("Processed user {id}"))
        }

        // The error should propagate
        let result = process_user("");
        assert!(matches!(result, Err(UserError::InvalidData(_))));
    }

    /// Test NotFound error in a realistic context with database operations
    #[tokio::test]
    #[serial]
    async fn test_not_found_error_in_context() {
        init_test_environment().await;

        // Try to get a user that doesn't exist
        let result = UserStore::get_user("nonexistent_user_id").await;

        // This should succeed with None, not error
        assert!(result.is_ok());
        assert!(
            result
                .expect("Getting non-existent user should succeed")
                .is_none()
        );

        // Now let's create a function that expects the user to exist
        async fn get_existing_user(id: &str) -> Result<crate::userdb::User, UserError> {
            match UserStore::get_user(id).await? {
                Some(user) => Ok(user),
                None => Err(UserError::NotFound),
            }
        }

        // Test with a non-existent user
        let result = get_existing_user("nonexistent_user_id").await;
        assert!(matches!(result, Err(UserError::NotFound)));
    }

    /// Test error handling with database operations
    #[tokio::test]
    #[serial]
    async fn test_database_error_handling() {
        init_test_environment().await;

        // Create a function that simulates a database error
        async fn simulate_db_error() -> Result<(), UserError> {
            Err(UserError::Storage("Simulated database error".to_string()))
        }

        // Test error propagation through multiple functions
        async fn user_operation() -> Result<(), UserError> {
            // First operation fails
            simulate_db_error().await?;
            // This should never execute due to the ? operator
            Ok(())
        }

        let result = user_operation().await;
        match result {
            Err(UserError::Storage(msg)) => {
                assert!(msg.contains("Simulated database error"));
            }
            _ => panic!("Expected Storage error"),
        }
    }
}
