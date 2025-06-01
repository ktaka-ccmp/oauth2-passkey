use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub(crate) enum StorageError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Json conversion(Serde) error: {0}")]
    Serde(String),
}

impl From<redis::RedisError> for StorageError {
    fn from(err: redis::RedisError) -> Self {
        Self::Storage(err.to_string()) // Adjust this based on how you want to represent the error
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_display() {
        // Given a StorageError with a Storage variant
        let error = StorageError::Storage("Connection failed".to_string());

        // When converting to a string
        let error_string = error.to_string();

        // Then it should format correctly
        assert_eq!(error_string, "Storage error: Connection failed");
    }

    #[test]
    fn test_serde_error_display() {
        // Given a StorageError with a Serde variant
        let error = StorageError::Serde("Invalid JSON".to_string());

        // When converting to a string
        let error_string = error.to_string();

        // Then it should format correctly
        assert_eq!(error_string, "Json conversion(Serde) error: Invalid JSON");
    }

    #[test]
    fn test_from_redis_error() {
        // Given a RedisError
        let redis_error =
            redis::RedisError::from((redis::ErrorKind::IoError, "Connection refused"));

        // When converting to StorageError
        let storage_error = StorageError::from(redis_error);

        // Then it should be a Storage variant
        match storage_error {
            StorageError::Storage(msg) => {
                assert!(msg.contains("Connection refused"));
            }
            _ => panic!("Expected Storage variant"),
        }
    }

    #[test]
    fn test_from_serde_error() {
        // Given a serde_json::Error
        let json = "invalid json";
        let serde_error = serde_json::from_str::<serde_json::Value>(json).unwrap_err();

        // When converting to StorageError
        let storage_error = StorageError::from(serde_error);

        // Then it should be a Serde variant
        match storage_error {
            StorageError::Serde(msg) => {
                assert!(msg.contains("expected value") || msg.contains("invalid"));
            }
            _ => panic!("Expected Serde variant"),
        }
    }

    #[test]
    fn test_error_is_sync_and_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<StorageError>();
    }
}
