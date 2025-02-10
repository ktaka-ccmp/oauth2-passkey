use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct OAuth2State;

// The user data we'll get back from Google
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub(crate) family_name: String,
    pub name: String,
    pub picture: String,
    pub(crate) email: String,
    pub(crate) given_name: String,
    pub(crate) id: String,
    pub(crate) hd: Option<String>,
    pub(crate) verified_email: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct StateParams {
    pub(crate) csrf_token: String,
    pub(crate) nonce_id: String,
    pub(crate) pkce_id: String,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub(crate) struct StoredToken {
    pub(crate) token: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) user_agent: Option<String>,
    pub(crate) ttl: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub(crate) code: String,
    pub state: String,
    _id_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OidcTokenResponse {
    pub(crate) access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
    pub(crate) id_token: Option<String>,
}

#[derive(Clone, Debug)]
pub enum TokenStoreType {
    Memory,
    Sqlite { url: String },
    Postgres { url: String },
    Redis { url: String },
}
