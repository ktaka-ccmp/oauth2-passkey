use std::sync::LazyLock;
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::storage::{memory::InMemorySessionStore, redis::RedisSessionStore};
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

pub async fn init_session_store() -> Result<(), AppError> {
    let store_type = SessionStoreType::from_env().unwrap_or_else(|e| {
        eprintln!("Failed to initialize session store from environment: {}", e);
        eprintln!("Falling back to in-memory store");
        SessionStoreType::Memory
    });

    tracing::info!("Initializing session store with type: {:?}", store_type);
    let store = store_type.create_store().await?;
    *SESSION_STORE.lock().await = store;
    tracing::info!("Session store initialized successfully");
    Ok(())
}
