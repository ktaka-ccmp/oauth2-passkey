use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, Clone)]
pub enum StorageType {
    Memory,
    Redis { url: String },
    Postgres { url: String },
    Sqlite { path: String },
}

#[derive(Debug, Clone, Copy)]
pub enum StorageKind {
    Cache,    // For temporary data (sessions, challenges)
    Permanent // For persistent data (credentials)
}

#[derive(Debug, Clone, Copy)]
pub enum CacheDataKind {
    Session,
    Challenge,
    EmailUserId,
    CredentialMapping,
}

impl CacheDataKind {
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Session => "session:",
            Self::Challenge => "challenge:",
            Self::EmailUserId => "email2uid:",
            Self::CredentialMapping => "cred:",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PermanentDataKind {
    Credential,
    User,
}

#[derive(Debug, Clone)]
pub enum QueryField {
    UserHandle(String),
    Email(String),
    CredentialId(String),
    UserId(String),
    UserName(String),
}

#[derive(Debug, Clone)]
pub enum QueryRelation {
    CredentialsByUser,
    UserByEmail,
    CredentialsByEmail,
}

impl QueryRelation {
    pub fn to_sql(&self) -> &'static str {
        match self {
            Self::CredentialsByUser => r#"
                SELECT c.* FROM credentials c
                JOIN users u ON c.user_handle = u.user_id
                WHERE u.user_id = $1
            "#,
            Self::UserByEmail => 
                "SELECT * FROM users WHERE email = $1",
            Self::CredentialsByEmail => r#"
                SELECT c.* FROM credentials c
                JOIN users u ON c.user_handle = u.user_id
                WHERE u.email = $1
            "#,
        }
    }

    pub fn redis_key_pattern(&self, field: &QueryField) -> String {
        match (self, field) {
            (Self::CredentialsByUser, QueryField::UserId(id)) => 
                format!("user:{}:credentials", id),
            (Self::UserByEmail, QueryField::Email(email)) => 
                format!("email:{}:user", email),
            (Self::CredentialsByEmail, QueryField::Email(email)) => 
                format!("email:{}:credentials", email),
            _ => panic!("Invalid query combination"),
        }
    }
}
