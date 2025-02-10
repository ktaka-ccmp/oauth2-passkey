use std::sync::LazyLock;
use tokio::sync::Mutex;

use crate::types::SessionStoreType;

pub static SESSION_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-SessionId".to_string())
});
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600) // Default to 10 minutes if not set or invalid
});

pub(crate) static SESSION_STORE: LazyLock<Mutex<Box<dyn crate::storage::CacheStoreSession>>> =
    LazyLock::new(|| Mutex::new(Box::new(crate::storage::memory::InMemorySessionStore::new())));
