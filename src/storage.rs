use crate::oauth2::AppError;
use crate::oauth2::{StoredSession, StoredToken};
use async_trait::async_trait;
use std::env;

mod memory;
mod redis;

#[derive(Clone, Debug)]
pub enum TokenStoreType {
    Memory,
    // Sqlite { url: String },
    // Postgres { url: String },
    Redis { url: String },
}

#[derive(Clone, Debug)]
pub enum SessionStoreType {
    Memory,
    // Sqlite { url: String },
    // Postgres { url: String },
    Redis { url: String },
}

impl TokenStoreType {
    pub fn from_env() -> Result<Self, AppError> {
        dotenv::dotenv().ok();

        let store_type = env::var("OAUTH2_TOKEN_STORE")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase();

        match store_type.as_str() {
            "memory" => Ok(TokenStoreType::Memory),
            // "sqlite" => {
            //     let url = env::var("OAUTH2_TOKEN_SQLITE_URL").map_err(|_| {
            //         AppError::Storage("OAUTH2_TOKEN_SQLITE_URL not set".to_string())
            //     })?;
            //     Ok(TokenStoreType::Sqlite { url })
            // }
            // "postgres" => {
            //     let url = env::var("OAUTH2_TOKEN_POSTGRES_URL").map_err(|_| {
            //         AppError::Storage("OAUTH2_TOKEN_POSTGRES_URL not set".to_string())
            //     })?;
            //     Ok(TokenStoreType::Postgres { url })
            // }
            "redis" => {
                let url = env::var("OAUTH2_TOKEN_REDIS_URL")?;
                Ok(TokenStoreType::Redis { url })
            }
            _ => Err(AppError::from(anyhow::anyhow!(
                "Unknown token store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn CacheStoreToken>, AppError> {
        match self {
            TokenStoreType::Memory => Ok(Box::new(memory::InMemoryTokenStore::new())),
            // TokenStoreType::Sqlite { url } => {
            //     Ok(Box::new(sqlite::SqliteTokenStore::connect(url).await?))
            // }
            // TokenStoreType::Postgres { url } => Ok(Box::new(
            //     postgres::PostgresTokenStore::connect(url).await?,
            // )),
            TokenStoreType::Redis { url } => {
                Ok(Box::new(redis::RedisTokenStore::connect(url).await?))
            }
        }
    }
}

impl SessionStoreType {
    pub fn from_env() -> Result<Self, AppError> {
        dotenv::dotenv().ok();

        let store_type = env::var("PASSKEY_SESSION_STORE")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase();

        match store_type.as_str() {
            "memory" => Ok(SessionStoreType::Memory),
            // "sqlite" => {
            //     let url = env::var("OAUTH2_SESSION_SQLITE_URL").map_err(|_| {
            //         AppError::Storage("OAUTH2_SESSION_SQLITE_URL not set".to_string())
            //     })?;
            //     Ok(SessionStoreType::Sqlite { url })
            // }
            // "postgres" => {
            //     let url = env::var("OAUTH2_SESSION_POSTGRES_URL").map_err(|_| {
            //         AppError::Storage("OAUTH2_SESSION_POSTGRES_URL not set".to_string())
            //     })?;
            //     Ok(SessionStoreType::Postgres { url })
            // }
            "redis" => {
                let url = env::var("OAUTH2_SESSION_REDIS_URL")?;
                Ok(SessionStoreType::Redis { url })
            }
            _ => Err(AppError::from(anyhow::anyhow!(
                "Unknown session store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn CacheStoreSession>, AppError> {
        match self {
            SessionStoreType::Memory => Ok(Box::new(memory::InMemorySessionStore::new())),
            // SessionStoreType::Sqlite { url } => {
            //     Ok(Box::new(sqlite::SqliteSessionStore::connect(url).await?))
            // }
            // SessionStoreType::Postgres { url } => Ok(Box::new(
            //     postgres::PostgresSessionStore::connect(url).await?,
            // )),
            SessionStoreType::Redis { url } => {
                Ok(Box::new(redis::RedisSessionStore::connect(url).await?))
            }
        }
    }
}

// pub(crate) trait CacheStore<T>: Send + Sync + 'static {
//     /// Initialize the store. This is called when the store is created.
//     async fn init(&self) -> Result<(), AppError>;

//     async fn put(
//         &mut self,
//         key: &str,
//         value: T,
//     ) -> Result<(), AppError>;

//     async fn get(
//         &self,
//         key: &str,
//     ) -> Result<Option<T>, AppError>;

//     async fn remove(&mut self, key: &str) -> Result<(), AppError>;
// }

#[async_trait]
pub trait CacheStoreToken: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), AppError>;

    /// Put a token into the store.
    async fn put(&mut self, key: &str, value: StoredToken) -> Result<(), AppError>;

    /// Get a token from the store.
    async fn get(&self, key: &str) -> Result<Option<StoredToken>, AppError>;

    /// Remove a token from the store.
    async fn remove(&mut self, key: &str) -> Result<(), AppError>;
}

#[async_trait]
pub(crate) trait CacheStoreSession: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), AppError>;

    async fn put(&mut self, key: &str, value: StoredSession) -> Result<(), AppError>;

    async fn get(&self, key: &str) -> Result<Option<StoredSession>, AppError>;

    async fn remove(&mut self, key: &str) -> Result<(), AppError>;
}
