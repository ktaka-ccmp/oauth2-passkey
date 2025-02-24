use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("SQLite error: {0}")]
    SqliteError(#[from] sqlx::Error),

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Lock error")]
    LockError,

    #[error("Store not initialized")]
    NotInitialized,

    #[error("Invalid storage type: {0}")]
    InvalidStorageType(String),

    #[error("Storage error: {0}")]
    Other(String),
}

impl From<std::env::VarError> for StorageError {
    fn from(err: std::env::VarError) -> Self {
        StorageError::ConfigError(err.to_string())
    }
}

impl From<String> for StorageError {
    fn from(err: String) -> Self {
        StorageError::Other(err)
    }
}
