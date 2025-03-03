mod common;
mod config;
mod errors;
mod session;
mod types;

pub use config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME}; // Required for cookie configuration
pub use errors::SessionError;
pub use session::{
    create_session_with_uid,
    // create_new_session,
    create_session_with_user,
    delete_session_from_store,
    get_user_from_session,
    prepare_logout_response,
};
pub use types::{SessionInfo, User}; // Required for session data

pub async fn init() -> Result<(), errors::SessionError> {
    libuserdb::init()
        .await
        .map_err(|e| errors::SessionError::Storage(e.to_string()))?;
    Ok(())
}
