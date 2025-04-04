use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Represents a core user identity in the system
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    /// Database-assigned sequence number (primary key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<i64>,
    /// Unique user identifier
    pub id: String,
    pub account: String,
    pub label: String,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user
    pub fn new(id: String, account: String, label: String) -> Self {
        let now = Utc::now();
        Self {
            sequence_number: None,
            id,
            account,
            label,
            is_admin: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if the user has admin privileges
    ///
    /// This is determined by either:
    /// 1. The user has is_admin flag set to true, or
    /// 2. The user is the first user in the system (sequence_number = 1)
    pub fn has_admin_privileges(&self) -> bool {
        self.is_admin || self.sequence_number == Some(1)
    }
}
