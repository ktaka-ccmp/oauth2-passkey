use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::types::{SessionState, SessionStoreType};

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

pub async fn session_state_init() -> Result<SessionState, AppError> {
    let session_store = SessionStoreType::from_env()?.create_store().await?;
    session_store.init().await?;

    Ok(SessionState {
        session_store: Arc::new(Mutex::new(session_store)),
    })
}
