use sqlx::{
    encode::{Encode, IsNull},
    postgres::{PgArgumentBuffer, PgTypeInfo, Postgres},
    sqlite::{Sqlite, SqliteArgumentValue, SqliteTypeInfo},
    Type,
};
use std::{error::Error as StdError, fmt, str::FromStr};
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum StorageType {
    Memory,
    Redis(String),
    Postgres(String),
    Sqlite(String),
}

impl FromStr for StorageType {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("://").collect();
        if parts.len() != 2 {
            return Err(StorageError::ConfigError(format!(
                "Invalid storage URL format: {}",
                s
            )));
        }

        let url = parts[1].to_string();
        match parts[0] {
            "memory" => Ok(StorageType::Memory),
            "redis" => Ok(StorageType::Redis(url)),
            "postgres" => Ok(StorageType::Postgres(url)),
            "sqlite" => Ok(StorageType::Sqlite(url)),
            _ => Err(StorageError::ConfigError(format!(
                "Unknown storage type: {}",
                s
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Type)]
#[sqlx(type_name = "cache_data_kind", rename_all = "snake_case")]
pub enum CacheDataKind {
    Session,
    State,
    Challenge,
}

impl fmt::Display for CacheDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheDataKind::Session => write!(f, "aa_session"),
            CacheDataKind::State => write!(f, "ab_state"),
            CacheDataKind::Challenge => write!(f, "ac_challenge"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Type)]
#[sqlx(type_name = "permanent_data_kind", rename_all = "snake_case")]
pub enum PermanentDataKind {
    User,
    Credential,
}

impl fmt::Display for PermanentDataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermanentDataKind::User => write!(f, "user"),
            PermanentDataKind::Credential => write!(f, "credential"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum QueryField {
    Email(String),
    UserHandle(String),
}

impl QueryField {
    fn get_value(&self) -> String {
        match self {
            QueryField::Email(email) => email.clone(),
            QueryField::UserHandle(handle) => handle.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Invalid storage type: {0}")]
    InvalidStorageType(String),
}

impl Type<Postgres> for QueryField {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

impl Type<Sqlite> for QueryField {
    fn type_info() -> SqliteTypeInfo {
        <String as Type<Sqlite>>::type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <String as Type<Sqlite>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Postgres> for QueryField {
    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer,
    ) -> Result<IsNull, Box<dyn StdError + Send + Sync>> {
        let value = self.get_value();
        <String as Encode<Postgres>>::encode_by_ref(&value, buf)
    }
}

impl<'q> Encode<'q, Sqlite> for QueryField {
    fn encode_by_ref(
        &self,
        buf: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, Box<dyn StdError + Send + Sync>> {
        let value = self.get_value();
        <String as Encode<Sqlite>>::encode_by_ref(&value, buf)
    }
}
