use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
// Minimal session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub user_id: String,
    // pub provider: String,
    pub expires_at: DateTime<Utc>,
}

// User information from libuserdb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub(crate) id: String,
    pub(crate) email: String,
    pub name: String,
    pub picture: String,
    pub(crate) provider: String,
    pub(crate) provider_user_id: String,
    pub(crate) metadata: Value,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

use libuserdb::User as DbUser;

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
            name: db_user.name,
            email: db_user.email,
            picture: db_user.picture.unwrap_or_default(),
            provider: db_user.provider,
            provider_user_id: db_user.provider_user_id,
            metadata: db_user.metadata,
            created_at: db_user.created_at,
            updated_at: db_user.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredSession {
    pub(crate) info: SessionInfo,
    pub(crate) ttl: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum SessionStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}
