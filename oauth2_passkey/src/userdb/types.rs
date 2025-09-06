use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;

/// Represents a core user identity in the system
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, PartialEq)]
pub struct User {
    /// Database-assigned sequence number (primary key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<i64>,
    /// Unique user identifier
    pub id: String,
    /// User account name or login identifier
    pub account: String,
    /// Display name or user-friendly label
    pub label: String,
    /// Whether the user has administrator privileges
    pub is_admin: bool,
    /// When the user account was created
    pub created_at: DateTime<Utc>,
    /// When the user account was last updated
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum UserSearchField {
    Id(String),
    SequenceNumber(i64),
}

impl fmt::Display for UserSearchField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserSearchField::Id(id) => write!(f, "Id({id})"),
            UserSearchField::SequenceNumber(seq) => write!(f, "SequenceNumber({seq})"),
        }
    }
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
    ///
    /// IMPORTANT: This logic must stay in sync with SessionUser::has_admin_privileges()
    /// and AuthUser::has_admin_privileges() implementations.
    pub fn has_admin_privileges(&self) -> bool {
        self.is_admin || self.sequence_number == Some(1)
    }
}

#[cfg(test)]
mod tests;
