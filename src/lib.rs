mod axum;
mod common;
mod config;
mod errors;
mod session;
mod storage;
mod types;

pub use config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
pub use errors::AppError;
pub use session::{create_new_session, delete_session_from_store, prepare_logout_response};
pub use types::User;

/// Initialize the session library, including session store.
/// This must be called before using the library.
pub async fn init() -> Result<(), AppError> {
    config::init_session_store().await
}
