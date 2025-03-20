mod common;
mod config;
mod errors;
mod main;
mod types;

pub use config::SESSION_COOKIE_NAME; // Required for cookie configuration
pub use errors::SessionError;
pub use main::{
    create_session_with_uid, delete_session_from_store_by_session_id, get_user_from_session,
    prepare_logout_response,
};
pub use types::User; // Required for session data
