#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Invalid configuration: {0}")]
    Config(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid query combination")]
    InvalidQuery,
    
    #[error("Not found")]
    NotFound,
    
    #[error("Store not initialized")]
    NotInitialized,
}
