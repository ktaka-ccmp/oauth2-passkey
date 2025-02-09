use std::sync::Arc;
use tokio::sync::Mutex;

use crate::errors::AppError;
use crate::types::{SessionParams, SessionState, SessionStoreType};

pub(crate) static SESSION_COOKIE_NAME: &str = "__Host-SessionId";
pub(crate) static SESSION_COOKIE_MAX_AGE: u64 = 600; // 10 minutes
pub(crate) static CSRF_COOKIE_NAME: &str = "__Host-CsrfId";
pub(crate) static CSRF_COOKIE_MAX_AGE: u64 = 60; // 60 seconds

pub async fn session_state_init() -> Result<SessionState, AppError> {
    let session_params = SessionParams {
        session_cookie_name: SESSION_COOKIE_NAME.to_string(),
        csrf_cookie_name: CSRF_COOKIE_NAME.to_string(),
        session_cookie_max_age: SESSION_COOKIE_MAX_AGE,
        csrf_cookie_max_age: CSRF_COOKIE_MAX_AGE,
    };

    let session_store = SessionStoreType::from_env()?.create_store().await?;
    session_store.init().await?;

    Ok(SessionState {
        session_store: Arc::new(Mutex::new(session_store)),
        session_params,
    })
}
