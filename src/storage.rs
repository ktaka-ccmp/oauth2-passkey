use std::env;
use crate::oauth2::AppError;

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
                let url = env::var("OAUTH2_TOKEN_REDIS_URL").map_err(|_| {
                    AppError::Storage("OAUTH2_TOKEN_REDIS_URL not set".to_string())
                })?;
                Ok(TokenStoreType::Redis { url })
            }
            _ => Err(AppError::Storage(format!(
                "Unknown token store type: {}",
                store_type
            ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn ChallengeStore>, PasskeyError> {
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

        let store_type = env::var("PASSKEY_CREDENTIAL_STORE")
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
                    let url = env::var("OAUTH2_SESSION_REDIS_URL").map_err(|_| {
                        AppError::Storage("OAUTH2_SESSION_REDIS_URL not set".to_string())
                    })?;
                    Ok(SessionStoreType::Redis { url })
                }
                _ => Err(AppError::Storage(format!(
                    "Unknown session store type: {}",
                    store_type
                ))),
        }
    }

    pub(crate) async fn create_store(&self) -> Result<Box<dyn SessionStore>, PasskeyError> {
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

pub(crate) trait TokenStore: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), AppError>;

    async fn store_token(
        &mut self,
        token_id: String,
        token: StoredToken,
    ) -> Result<(), AppError>;

    async fn get_token(
        &self,
        token_id: &str,
    ) -> Result<Option<StoredToken>, AppError>;

    async fn remove_token(&mut self, token_id: &str) -> Result<(), AppError>;
}

pub(crate) trait SessionStore: Send + Sync + 'static {
    /// Initialize the store. This is called when the store is created.
    async fn init(&self) -> Result<(), AppError>;

    async fn store_credential(
        &mut self,
        credential_id: String,
        credential: StoredSession,
    ) -> Result<(), AppError>;

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredSession>, AppError>;

    async fn remove_session(&mut self, session_id: &str) -> Result<(), AppError>;
}
