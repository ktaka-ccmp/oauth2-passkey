use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::session::errors::SessionError;
use crate::storage::CacheData;
use crate::userdb::User as DbUser;

// User information from libuserdb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub account: String,
    pub label: String,
    pub is_admin: bool,
    pub sequence_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<DbUser> for User {
    fn from(db_user: DbUser) -> Self {
        Self {
            id: db_user.id,
            account: db_user.account,
            label: db_user.label,
            is_admin: db_user.is_admin,
            sequence_number: db_user.sequence_number.unwrap_or(0),
            created_at: db_user.created_at,
            updated_at: db_user.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredSession {
    pub(super) user_id: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) ttl: u64,
}

impl From<StoredSession> for CacheData {
    fn from(data: StoredSession) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize StoredSession"),
        }
    }
}

impl TryFrom<CacheData> for StoredSession {
    type Error = SessionError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| SessionError::Storage(e.to_string()))
    }
}
