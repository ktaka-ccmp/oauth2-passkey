use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct SessionParams {
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub session_cookie_max_age: u64,
    pub csrf_cookie_max_age: u64,
}

#[derive(Clone)]
pub struct SessionState {
    pub(crate) session_store: Arc<Mutex<Box<dyn crate::storage::CacheStoreSession>>>,
    pub session_params: SessionParams,
}

// The user data we'll get back from Google
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub family_name: String,
    pub name: String,
    pub picture: String,
    pub email: String,
    pub given_name: String,
    pub id: String,
    pub hd: Option<String>,
    pub verified_email: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredSession {
    pub(crate) user: User,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) ttl: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum SessionStoreType {
    Memory,
    // Sqlite { url: String },
    // Postgres { url: String },
    Redis { url: String },
}
