use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Data stored in the cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub value: String,
    #[serde(default = "default_expires_at")]
    pub expires_at: DateTime<Utc>,
}

/// Default expiration time for cache entries (far future)
fn default_expires_at() -> DateTime<Utc> {
    DateTime::from_timestamp(4102444800, 0).unwrap_or_else(Utc::now) // Year 2100
}
